extern crate base64;
extern crate crypto;
extern crate hex;
extern crate rocket;
extern crate tokio_postgres;

use core::panic;
use std::env;

use ::serde::{Deserialize, Serialize};
use crypto::digest::Digest;
use crypto::sha2::Sha384;
use once_cell::sync::OnceCell;
use rocket::*;
use rocket::{serde::json::Json, tokio};
use tokio_postgres::{Client, NoTls, Row};

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
struct InitPayload<'r> {
    metadata: &'r str,
    username: &'r str,
}

#[post("/root", data = "<payload>")]
async fn new_root(payload: Json<InitPayload<'_>>) -> &'static str {
    let pq = &PQ.get().unwrap().db;

    let raw_meta = base64::decode(payload.metadata).unwrap();

    let mut meta_hash: [u8; 84] = [0; 84];
    {
        let mut h = Sha384::new();
        h.input(raw_meta.as_slice());
        h.result(&mut meta_hash);
    }

    let mut node_hash: [u8; 84] = [0; 84];
    {
        let mut h = Sha384::new();
        h.input(&meta_hash);
        h.result(&mut node_hash);
    }

    pq.execute(
        "INSERT INTO users (username, top_hash) VALUES ($1,$2);",
        &[&payload.username, &meta_hash.to_vec()],
    )
    .await
    .unwrap();

    pq.execute(
        "INSERT INTO nodes (hash,  metadata, metadata_hash) VALUES ($1,$2,$3);",
        &[&node_hash.to_vec(), &raw_meta, &meta_hash.to_vec()],
    )
    .await
    .unwrap();

    ""
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct InsertPayload<'r> {
    is_dir: bool,
    metadata: &'r str,
    parent_hash: &'r str,
    content_hash: &'r str,
    content_length: u32,
}

#[post("/node", data = "<payload>")]
async fn upload(payload: Json<InsertPayload<'_>>) -> &'static str {
    if payload.is_dir && payload.content_length != 0 {
        return "dir can't contain data";
    }

    let raw_meta = base64::decode(payload.metadata).unwrap();

    let mut meta_hash: [u8; 84] = [0; 84];
    {
        let mut h = Sha384::new();
        h.input(raw_meta.as_slice());
        h.result(&mut meta_hash);
    }

    let mut node_hash: [u8; 84] = [0; 84];
    {
        let mut h = Sha384::new();
        h.input(&meta_hash);
        if payload.content_length != 0 {
            h.input(payload.content_hash.as_bytes());
        }
        h.result(&mut node_hash);
    }

    let context = get_tree_context(payload.parent_hash.as_bytes().to_vec())
        .await
        .unwrap();

    let mut new_context = context.clone();

    let parent_hash = payload.parent_hash.as_bytes();

    let new_node = Node {
        hash: node_hash.to_vec(),
        metadata: raw_meta,
        parent_hash: parent_hash.to_vec(),
        metadata_hash: meta_hash.to_vec(),
    };
    new_context.push(new_node);
    let new_context = update_tree(parent_hash.to_vec(), context);

    let pq = &PQ.get().unwrap().db;
    // i tried to do a transaction, but the borrows were too wierd

    for node in new_context {
        pq.execute(
            "INSERT INTO nodes (hash, parent_hash, metadata, metadata_hash) VALUES ($1,$2,$3,$4);",
            &[
                &node.hash,
                &node.parent_hash,
                &node.metadata,
                &node.metadata_hash,
            ],
        )
        .await
        .unwrap();

        if node.parent_hash.is_empty() {
            pq.execute("UPDATE users SET top_hash = $1;", &[&node.hash])
                .await
                .unwrap();
        }
    }

    "Hello, world!"
}

fn update_tree(tbu: Vec<u8>, mut context: Vec<Node>) -> Vec<Node> {
    // will this be very slow? yes, i don't care
    // can't be bothered to build trees

    // the nodes have to be sorted in order for the hashes to be reproducible
    context.sort_by(|a, b| a.hash.cmp(&b.hash));

    let mut tbun_idx = context.binary_search_by(|n| n.hash.cmp(&tbu)).unwrap();

    while tbun_idx != 694206969 {
        let mut new_hash = Sha384::new();

        new_hash.input(&context[tbun_idx].metadata_hash);

        let mut next_ti = 694206969;

        let mut back_prop = vec![];

        let mut i = 0;
        while i < context.len() {
            let node = &context[i];

            if node.parent_hash == context[tbun_idx].hash {
                new_hash.input(&node.hash);
                back_prop.push(i);
            }

            if node.hash == context[tbun_idx].parent_hash {
                next_ti = i;
            }
            i += 1;
        }

        new_hash.result(&mut context[tbun_idx].hash);

        for bb in back_prop {
            context[bb].parent_hash = context[tbun_idx].hash.clone();
        }

        tbun_idx = next_ti;
    }
    context
}

#[delete("/node/<hash>")]
fn delete(hash: String) -> &'static str {
    _ = hash;
    "Hello, world!"
}

#[derive(Serialize, Clone)]
#[serde(crate = "rocket::serde")]
struct Node {
    hash: Vec<u8>,
    metadata: Vec<u8>,
    metadata_hash: Vec<u8>,
    parent_hash: Vec<u8>,
}

#[get("/node/<hash>/children")]
async fn children(hash: &str) -> Json<Vec<Node>> {
    let pq = &PQ.get().unwrap().db;

    let children = pq
        .query(
            "SELECT hash, metadata, parent_hash, metadata_hash FROM nodes WHERE hash = $1;",
            &[&hash],
        )
        .await
        .unwrap();

    Json(convert_nodes(children))
}

async fn get_tree_context(hash: Vec<u8>) -> Result<Vec<Node>, ()> {
    let pq = &PQ.get().unwrap().db;
    let query = "WITH RECURSIVE higher_nodes(n) AS (
        SELECT hash, metadata, parent_hash, metadata_hash FROM nodes WHERE hash = $1
        UNION ALL
        SELECT n.hash, n.metadata, n.parent_hash, metadata_hash
        FROM higher_nodes hn, nodes n
        WHERE n.hash = hn.parent_hash OR n.parent_hash = hn.parent_hash
    ) SELECT * FROM higher_nodes;";

    let children = pq.query(query, &[&hash]).await.unwrap();

    Ok(convert_nodes(children))
}

fn convert_nodes(rows: Vec<Row>) -> Vec<Node> {
    rows.iter()
        .map(|row| Node {
            hash: row.get::<usize, Vec<u8>>(0),
            metadata: row.get::<usize, Vec<u8>>(1),
            parent_hash: row.get::<usize, Vec<u8>>(2),
            metadata_hash: row.get::<usize, Vec<u8>>(3),
        })
        .collect()
}

#[rocket::launch]
async fn rocket() -> _ {
    dotenvy::dotenv().unwrap();

    let conn = init_db().await.unwrap();
    if PQ.set(conn).is_err() {
        panic!("sadge");
    }

    rocket::build().mount("/api", routes![upload, children, delete, new_root])
}
