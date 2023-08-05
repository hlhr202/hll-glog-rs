use glog_rust::log_writer;

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

fn main() {
    let file = std::fs::File::create("test.glog").unwrap();
    let mut writer = std::io::BufWriter::new(file);

    let logs = create_logs();

    log_writer::write_head(&mut writer).unwrap();

    for log in logs {
        log_writer::write_single_log(&mut writer, &log).unwrap();
    }
}
