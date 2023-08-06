use anyhow::Result;
use glog_rust::io::log_reader;
use std::{fs::File, io::BufReader};

fn main() -> Result<()> {
    dotenvy::from_path(".env.local")?;
    let pri_key = std::env::var("PRI_KEY")?;
    let file = File::open("test.glog")?;
    let reader = BufReader::new(file);
    log_reader::read(reader, &pri_key, |content| println!("{}", content))?;
    Ok(())
}
