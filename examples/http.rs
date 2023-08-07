use axum::{
    extract::{Multipart, State},
    routing::post,
    Router,
};
use glog_rust::{cipher::aes_cfb_ecdh::Cipher, io::log_reader::LogBufReaderV4};
use std::io::BufReader;

async fn upload(State(cipher_context): State<Cipher>, mut multipart: Multipart) {
    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        if name == "file" {
            let data = field.bytes().await.unwrap();
            let cipher_context = cipher_context.clone();
            tokio::task::spawn_blocking(move || {
                let reader = BufReader::new(data.as_ref());
                let mut reader = LogBufReaderV4::new(reader, cipher_context);
                reader.read(|content| println!("{}", content)).unwrap();
            })
            .await
            .unwrap();
        }
    }
}

#[tokio::main]
async fn main() {
    dotenvy::from_path(".env.local").unwrap();
    let cipher_context = Cipher::new(&std::env::var("PRI_KEY").unwrap()).unwrap();
    let app = Router::new()
        .route("/", post(upload))
        .with_state(cipher_context);

    println!("listening on 8080");
    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
