use anyhow::Result;
use glog_rust::{
    io::{
        log_writer::LogBufWriterV4,
        primitive::{CompressMode, EncryptMode},
    },
    cipher::{key_pair::KeyPair, aes_cfb_ecdh::Cipher},
};

fn create_logs() -> Vec<String> {
    let mut logs = vec![];
    for i in 0..100 {
        let log = format!(
            r#"{{"msg":"save:{}","level":"3","timestamp":"2023-08-03 08:38:48 +0000","userId":"uid12345","namespace":"namespace"}}"#,
            i
        );
        logs.push(log);
    }
    logs
}

fn main() -> Result<()> {
    dotenvy::from_path(".env.local")?;
    let pub_key = std::env::var("PUB_KEY")?;
    let file = std::fs::File::create("test.glog")?;
    let writer = std::io::BufWriter::new(file);

    let logs = create_logs();

    let client_secret = KeyPair::random()?;
    let cipher = Cipher::new(&client_secret.private_key)?;
    let mut log_buf_writer = LogBufWriterV4::new(writer, &cipher);
    log_buf_writer.write_head()?;

    for log in logs {
        log_buf_writer.write_single_log(&(CompressMode::Zlib, EncryptMode::Aes), &pub_key, &log)?;
    }

    Ok(())
}
