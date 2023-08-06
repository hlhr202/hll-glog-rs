# hll-glog-rs (wip)

Rust implementation of log reader for [hll-glog](https://github.com/HuolalaTech/hll-wp-glog/)

## Progress

-   [x] File V4 Reader
    -   [x] File Header
    -   [x] AES
    -   [x] Zlib
-   [x] File V4 Writer (just for testing)
    -   [x] File Header
    -   [x] AES
    -   [x] Zlib
-   [ ] FileV3
-   [x] API

## Example

-   generate key pairs, server key will be written to .env.local

```bash
cargo run --example gen_key
```

-   write test.glog

```bash
# run under project root foler
cargo run --example write_example
```

-   read test.glog

```bash
# run under project root foler
cargo run --example read_example
```

-   http read buffer from multipart

```bash
# run both under project root foler
cargo run --example http
curl --form file='@test.glog' http://localhost:8080
```

## Acknowledgements

Based on Java implementation [hll-wp-glog/Misc/Reader](https://github.com/HuolalaTech/hll-wp-glog/tree/master/Misc/Reader)
