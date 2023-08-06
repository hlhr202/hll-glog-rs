use std::io::BufReader;

use axum::{extract::Multipart, routing::post, Router};
use glog_rust::io::log_reader;

async fn upload(mut multipart: Multipart) {
    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        let pri_key = std::env::var("PRI_KEY").unwrap();
        if name == "file" {
            let data = field.bytes().await.unwrap();
            tokio::task::spawn_blocking(move || {
                let reader = BufReader::new(data.as_ref());
                log_reader::read(reader, &pri_key, |content| println!("{}", content)).unwrap();
            })
            .await
            .unwrap();
        }
    }
}

#[tokio::main]
async fn main() {
    dotenvy::from_path(".env.local").unwrap();
    let app = Router::new().route("/", post(upload));

    println!("listening on 8080");
    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
