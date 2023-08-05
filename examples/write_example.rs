use anyhow::Result;
use glog_rust::log_writer::{self, CompressMode, EncryptMode};

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
    let mut writer = std::io::BufWriter::new(file);

    let logs = create_logs();

    log_writer::write_head(&mut writer)?;

    for log in logs {
        log_writer::write_single_log(
            &mut writer,
            &(CompressMode::Zlib, EncryptMode::Aes),
            &pub_key,
            &log,
        )?;
    }

    Ok(())
}
