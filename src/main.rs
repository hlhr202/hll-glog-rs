use anyhow::Result;
use glog_rust::{cipher::aes_cfb_ecdh::Cipher, io::log_reader::LogBufReaderV4};
use std::{fs::File, io::BufReader};

fn main() -> Result<()> {
    dotenvy::from_path(".env.local")?;
    let pri_key = std::env::var("PRI_KEY")?;
    let file = File::open("ATRealTimeLog-20230803163848626.glog")?;
    let reader = BufReader::new(file);
    let cipher = Cipher::new(&pri_key)?;
    let mut log_buf_reader = LogBufReaderV4::new(reader, &cipher);

    log_buf_reader.read(|content| println!("{}", content))?;
    Ok(())
}
