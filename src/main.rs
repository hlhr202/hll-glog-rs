use anyhow::Result;
use std::{fs::File, io::BufReader};

mod log_writer;
mod compression;
mod cipher;
mod log_reader;

fn main() -> Result<()> {
    dotenvy::from_path(".env.local")?;
    let pri_key = std::env::var("PRI_KEY")?;
    let file = File::open("ATRealTimeLog-20230803163848626.glog")?;
    let reader = BufReader::new(file);
    log_reader::read(reader, &pri_key, |content| println!("{}", content))?;
    Ok(())
}
