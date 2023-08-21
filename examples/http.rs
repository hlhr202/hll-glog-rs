use axum::{extract::Multipart, routing::post, Router};
use glog_rust::{cipher::aes_cfb_ecdh::Cipher, io::log_reader::LogBufReaderV4};
use std::io::BufReader;

#[macro_use]
extern crate lazy_static;

lazy_static! {
    // CIPHER is absolutely thread safe
    static ref CIPHER: Cipher = {
        dotenvy::from_path(".env.local").unwrap();
        let pri_key = std::env::var("PRI_KEY").unwrap();
        Cipher::new(&pri_key).unwrap()
    };
}

async fn upload(mut multipart: Multipart) {
    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        if name == "file" {
            let data = field.bytes().await.unwrap();

            tokio::task::spawn_blocking(move || {
                let reader = BufReader::new(data.as_ref());
                let mut reader = LogBufReaderV4::new(reader, &CIPHER);
                reader.read(|content| println!("{}", content)).unwrap();
            })
            .await
            .unwrap();
        }
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", post(upload));

    println!("listening on 8080");
    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
