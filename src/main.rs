extern crate base64;
extern crate crypto;
extern crate rocket;
extern crate tokio_postgres;

use core::panic;
use std::env;

use ::serde::{Deserialize, Serialize};
use crypto::digest::Digest;
use crypto::sha2::Sha384;
use once_cell::sync::OnceCell;
use regex::Regex;
use rocket::*;
use rocket::{serde::json::Json, tokio};
use tokio_postgres::{Client, NoTls, SimpleQueryMessage};

pub static PQ: OnceCell<DB> = OnceCell::new();

pub async fn init_db() -> Result<DB, ()> {
    let dbuser = env::var("POSTGRES_USER").unwrap();
    let dbpass = env::var("POSTGRES_PASSWORD").unwrap();
    let dbname = env::var("POSTGRES_DB").unwrap();
    let host = env::var("DB_HOSTNAME").unwrap();

    // we're not going to recreate the DB connection for every query, and rocket::build
    // will not let us do dependency injection
    Ok(DB::new(&dbuser, &dbpass, &host, &dbname).await.unwrap())
}

pub struct DB {
    db: Client,
}

impl DB {
    // connect to the db when a new db is created
    pub async fn new(
        username: &str,
        password: &str,
        host: &str,
        dbname: &str,
    ) -> Result<DB, Error> {
        let connstr = format!(
            "host={} user={} password={} dbname={}",
            host, username, password, dbname
        );
        let (client, connection) = tokio_postgres::connect(&connstr[..], NoTls).await.unwrap();
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                panic!("postgres connection error: {}", e);
            }
        });
        Ok(DB { db: client })
    }
}
#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct InsertPayload<'r> {
    node_type: &'r str,
    metadata: &'r str,
    parent_hash: &'r str,
    content_hash: &'r str,
    content_length: u32,
}

#[post("/insert", data = "<payload>")]
async fn upload(payload: Json<InsertPayload<'_>>) -> &'static str {
    let pq = &PQ.get().unwrap().db;

    let x = base64::decode(payload.metadata).unwrap();

    let mut h = Sha384::new();
    h.input(x.as_slice());
    let meta_hash = h.result_str();

    let mut h = Sha384::new();
    h.input_str(&meta_hash);
    h.input_str(payload.content_hash);
    let node_hash = h.result_str();

    let context = get_tree_context(payload.parent_hash.to_string())
        .await
        .unwrap();

    let mut new_context = context.clone();
    let parent_hash = payload.parent_hash.to_string();
    let new_node = Node {
        hash: node_hash,
        metadata: x,
        parent_hash: parent_hash.clone(),
        metadata_hash: meta_hash,
    };
    new_context.push(new_node);
    let new_context = update_tree(parent_hash, context);

    "Hello, world!"
}

fn update_tree(tbu: String, mut context: Vec<Node>) -> Vec<Node> {
    // will this be very slow? yes, i don't care
    // can't be bothered to build trees

    // the nodes have to be sorted in order for the hashes to be reproducible
    context.sort_by(|a, b| a.hash.cmp(&b.hash));

    let mut tbun_idx = context.binary_search_by(|n| n.hash.cmp(&tbu)).unwrap();
    let mut tbun: Option<&Node> = Some(&context[tbun_idx]);

    while tbun.is_some() {
        let mut new_hash = Sha384::new();

        new_hash.input_str(tbun.unwrap().metadata_hash.as_str());

        let mut next_tbun = None;

        let mut i = 0;
        while i < context.len() {
            let node = &context[i];
        
            if node.parent_hash == tbun.unwrap().hash {
                new_hash.input_str(node.hash.as_str());
            }

            if node.hash == tbun.unwrap().parent_hash {
                next_tbun = Some(node);
                tbun_idx = i;
            }
        }

        context[tbun_idx].hash = new_hash.result_str();
        tbun = next_tbun;
        i += 1;

    context
}

#[post("/delete")]
fn delete() -> &'static str {
    "Hello, world!"
}

#[derive(Serialize, Clone)]
#[serde(crate = "rocket::serde")]
struct Node {
    hash: String,
    metadata: Vec<u8>,
    metadata_hash: String,
    parent_hash: String,
}

#[get("/node/<hash>/children")]
async fn children(hash: &str) -> Json<Vec<Node>> {
    let re = Regex::new("^[0-9a-f]{84}$").unwrap();

    if !re.is_match(hash) {
        panic!("yoo");
    }

    let pq = &PQ.get().unwrap().db;
    let query = format!(
        "SELECT hash, metadata, parent_hash, metadata_hash FROM nodes WHERE hash = '\\x{}';",
        hash
    );

    let children = pq.simple_query(query.as_str()).await.unwrap();

    Json(convert_nodes(children))
}

async fn get_tree_context(hash: String) -> Result<Vec<Node>, ()> {
    let re = Regex::new("^[0-9a-f]{84}$").unwrap();

    if !re.is_match(&hash) {
        return Err(());
    }

    let pq = &PQ.get().unwrap().db;
    let query = format!(
        "WITH RECURSIVE higher_nodes(n) AS (
        SELECT hash, metadata, parent_hash, metadata_hash FROM nodes WHERE hash = '\\x{}'
        UNION ALL
        SELECT n.hash, n.metadata, n.parent_hash, metadata_hash
        FROM higher_nodes hn, nodes n
        WHERE n.hash = hn.parent_hash OR n.parent_hash = hn.parent_hash
    ) SELECT * FROM higher_nodes;",
        hash
    );

    let children = pq.simple_query(query.as_str()).await.unwrap();

    Ok(convert_nodes(children))
}

fn convert_nodes(nodes: Vec<SimpleQueryMessage>) -> Vec<Node> {
    let mut result: Vec<Node> = Vec::with_capacity(nodes.len());

    for node in nodes {
        match node {
            SimpleQueryMessage::Row(x) => {
                result.push(Node {
                    hash: x.get(0).unwrap().to_owned(),
                    metadata: x.get(1).unwrap().as_bytes().to_vec(),
                    parent_hash: x.get(2).unwrap().to_owned(),
                    metadata_hash: x.get(3).unwrap().to_owned(),
                });
            }
            _ => panic!("not expected"),
        }
    }
    result
}

#[rocket::launch]
async fn rocket() -> _ {
    dotenvy::dotenv().unwrap();

    let conn = init_db().await.unwrap();
    if PQ.set(conn).is_err() {
        panic!("sadge");
    }

    rocket::build().mount("/api", routes![upload, children, delete])
}
