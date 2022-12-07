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

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
struct InitResponse {
    top_hash: String,
}

#[post("/root", data = "<payload>")]
async fn new_root(payload: Json<InitPayload<'_>>) -> Json<InitResponse> {
    let pq = &PQ.get().unwrap().db;

    let raw_meta = base64::decode(payload.metadata).unwrap();

    let mut meta_hash: [u8; 48] = [0; 48];
    {
        let mut h = Sha384::new();
        h.input(raw_meta.as_slice());
        h.result(&mut meta_hash);
    }

    let mut node_hash: [u8; 48] = [0; 48];
    {
        let mut h = Sha384::new();
        h.input(&meta_hash);
        h.result(&mut node_hash);
    }

    pq.execute(
        "INSERT INTO nodes (hash,  metadata, metadata_hash, is_dir) VALUES ($1,$2,$3, true);",
        &[&node_hash.to_vec(), &raw_meta, &meta_hash.to_vec()],
    )
    .await
    .unwrap();

    pq.execute(
        "INSERT INTO users (username, top_hash) VALUES ($1,$2);",
        &[&payload.username, &node_hash.to_vec()],
    )
    .await
    .unwrap();

    Json(InitResponse {
        top_hash: hex::encode(node_hash),
    })
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct InsertPayload<'r> {
    is_dir: bool,
    metadata: &'r str,
    parent_hash: &'r str,
    content_hash: Option<&'r str>,
    content_length: Option<u32>,
}
#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
struct InsertResponse {
    old_tree: Vec<Node>,
    new_tree: Vec<Node>,
    new_top_hash: String,
}

#[post("/node", data = "<payload>")]
async fn upload(payload: Json<InsertPayload<'_>>) -> Result<Json<InsertResponse>, &str> {
    if payload.is_dir && payload.content_length.is_some() {
        return Err("dir can't contain data");
    }

    let raw_meta = base64::decode(payload.metadata).unwrap();

    let mut meta_hash: [u8; 48] = [0; 48];
    {
        let mut h = Sha384::new();
        h.input(raw_meta.as_slice());
        h.result(&mut meta_hash);
    }

    let mut node_hash: [u8; 48] = [0; 48];
    {
        let mut h = Sha384::new();
        h.input(&meta_hash);
        if payload.content_length.is_some() {
            h.input(
                hex::decode(payload.content_hash.unwrap())
                    .unwrap()
                    .as_slice(),
            );
        }
        h.result(&mut node_hash);
    }

    let context = get_tree_context(hex::decode(payload.parent_hash).unwrap())
        .await
        .unwrap();
    let context = iconvert_nodes(context);

    let parent_hash = hex::decode(payload.parent_hash).unwrap();

    let new_node = InternalNode {
        hash: node_hash.to_vec(),
        metadata: raw_meta,
        parent_hash: parent_hash.clone(),
        metadata_hash: meta_hash.to_vec(),
        is_dir: payload.is_dir,
    };

    let mut new_context = context.clone();
    new_context.push(new_node);
    let new_context = update_tree(parent_hash, new_context);

    let pq = &PQ.get().unwrap().db;

    let mut q =
        "INSERT INTO nodes (hash, parent_hash, metadata, metadata_hash, data_hash, is_dir) VALUES "
            .to_owned();

    let mut args: Vec<&(dyn tokio_postgres::types::ToSql + std::marker::Sync)> =
        Vec::with_capacity(5 * new_context.len());

    let mut top_hash = vec![];

    let mut x = 0;
    for (i, node) in new_context.iter().enumerate() {
        if !node.parent_hash.is_empty() {
            q.push_str(
                format!(
                    "(${},${},${},${},${},${})",
                    x + 1,
                    x + 2,
                    x + 3,
                    x + 4,
                    x + 5,
                    x + 6
                )
                .as_str(),
            );
            x += 6;
        } else {
            q.push_str(
                format!(
                    "(${},NULL,${},${},${},${})",
                    x + 1,
                    x + 2,
                    x + 3,
                    x + 4,
                    x + 5
                )
                .as_str(),
            );
            x += 5;
        }

        if i != new_context.len() - 1 {
            q.push(',');
        }

        args.push(&node.hash);
        if !node.parent_hash.is_empty() {
            args.push(&node.parent_hash);
        }
        args.push(&node.metadata);
        args.push(&node.metadata_hash);
        args.push(&node.data_hash);

        args.push(&node.is_dir);

        if node.parent_hash.is_empty() {
            top_hash = node.hash.clone();
        }
    }

    pq.execute(&q, &args).await.unwrap();

    pq.execute("UPDATE users SET top_hash = $1;", &[&top_hash])
        .await
        .unwrap();

    Ok(Json(InsertResponse {
        old_tree: externalize_node(context),
        new_tree: externalize_node(new_context),
        new_top_hash: hex::encode(top_hash),
    }))
}

fn update_tree(tbu: Vec<u8>, mut context: Vec<InternalNode>) -> Vec<InternalNode> {
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
fn delete(hash: String) -> Json<Node> {
    panic!("")
}

#[get("/node/<hash>")]
async fn get_node(hash: String) -> Json<Node> {
    let pq = &PQ.get().unwrap().db;

    let row = pq
        .query_one(
            "SELECT hash, metadata, parent_hash, metadata_hash, is_dir FROM nodes WHERE hash = $1;",
            &[&hex::decode(hash).unwrap()],
        )
        .await
        .unwrap();

    Json(convert_node(&row))
}

#[derive(Serialize, Clone, Debug)]
#[serde(crate = "rocket::serde")]
struct Node {
    hash: String,
    metadata: String,
    metadata_hash: String,
    data_hash: String,
    parent_hash: String,
    is_dir: bool,
}

#[derive(Clone)]
struct InternalNode {
    hash: Vec<u8>,
    metadata: Vec<u8>,
    metadata_hash: Vec<u8>,
    data_hash: Vec<u8>,
    parent_hash: Vec<u8>,
    is_dir: bool,
}

#[get("/node/<hash>/children")]
async fn children(hash: &str) -> Json<Vec<Node>> {
    let pq = &PQ.get().unwrap().db;

    let children = pq
        .query(
            "SELECT hash, metadata, parent_hash, metadata_hash, data_hash, is_dir FROM nodes WHERE parent_hash = $1;",
            &[&hex::decode(hash).unwrap()],
        )
        .await
        .unwrap();

    Json(convert_nodes(children))
}

async fn get_tree_context(hash: Vec<u8>) -> Result<Vec<Row>, ()> {
    let pq = &PQ.get().unwrap().db;
    let query = "WITH RECURSIVE higher_nodes(n) AS (
        SELECT hash, metadata, parent_hash, metadata_hash, data_hash, is_dir FROM nodes WHERE hash = $1
        UNION ALL
        SELECT n.hash, n.metadata, n.parent_hash, n.metadata_hash, n.data_hash, n.is_dir
        FROM higher_nodes hn, nodes n
        WHERE n.hash = hn.parent_hash OR n.parent_hash = hn.parent_hash
    ) SELECT * FROM higher_nodes;";

    let children = pq.query(query, &[&hash]).await.unwrap();

    Ok(children)
}

fn externalize_node(nodes: Vec<InternalNode>) -> Vec<Node> {
    nodes
        .iter()
        .map(|n| Node {
            hash: hex::encode(&n.hash),
            metadata: base64::encode(&n.metadata),
            parent_hash: hex::encode(&n.parent_hash),
            metadata_hash: hex::encode(&n.metadata_hash),
            data_hash: hex::encode(&n.data_hash),
            is_dir: n.is_dir,
        })
        .collect()
}

fn convert_nodes(rows: Vec<Row>) -> Vec<Node> {
    rows.iter().map(convert_node).collect()
}
fn convert_node(row: &Row) -> Node {
    Node {
        hash: hex::encode(row.get::<usize, Vec<u8>>(0)),
        metadata: base64::encode(row.get::<usize, Vec<u8>>(1)),
        parent_hash: hex::encode(row.get::<usize, Option<Vec<u8>>>(2).unwrap_or_default()),
        metadata_hash: hex::encode(row.get::<usize, Vec<u8>>(3)),
        data_hash: hex::encode(row.get::<usize, Vec<u8>>(4)),
        is_dir: row.get::<usize, bool>(5),
    }
}

fn iconvert_nodes(rows: Vec<Row>) -> Vec<InternalNode> {
    rows.iter().map(iconvert_node).collect()
}
fn iconvert_node(row: &Row) -> InternalNode {
    InternalNode {
        hash: (row.get::<usize, Vec<u8>>(0)),
        metadata: (row.get::<usize, Vec<u8>>(1)),
        parent_hash: (row.get::<usize, Option<Vec<u8>>>(2).unwrap_or_default()),
        metadata_hash: (row.get::<usize, Vec<u8>>(3)),
        data_hash: row.get::<usize, Vec<u8>>(4),
        is_dir: row.get::<usize, bool>(5),
    }
}

#[rocket::launch]
async fn rocket() -> _ {
    dotenvy::dotenv().unwrap();

    let conn = init_db().await.unwrap();
    if PQ.set(conn).is_err() {
        panic!("sadge");
    }

    rocket::build().mount(
        "/api",
        routes![upload, children, delete, new_root, get_node],
    )
}
