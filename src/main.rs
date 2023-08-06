use anyhow::Result;
use glog_rust::io::log_reader;
use std::{fs::File, io::BufReader};

fn main() -> Result<()> {
    dotenvy::from_path(".env")?;
    let pri_key = std::env::var("PRI_KEY")?;
    let file = File::open("ATRealTimeLog-20230803163848626.glog")?;
    let reader = BufReader::new(file);
    log_reader::read(reader, &pri_key, |content| println!("{}", content))?;
    Ok(())
}
