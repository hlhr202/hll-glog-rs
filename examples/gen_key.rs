use anyhow::Result;
use glog_rust::cipher::key_pair::KeyPair;

fn main() -> Result<()> {
    let client_key = KeyPair::random()?;
    let server_key = KeyPair::random()?;

    println!("client_key: {:?}", client_key);
    println!("server_key: {:?}", server_key);

    let shared1 = server_key.diffie_hellman(&client_key.to_public_key_untagged_bytes()?)?;
    let shared1 = shared1.raw_secret_bytes();

    let shared2 = client_key.diffie_hellman(&server_key.to_public_key_untagged_bytes()?)?;
    let shared2 = shared2.raw_secret_bytes();

    println!("shared1 == shared2: {}", shared1 == shared2);

    assert_eq!(shared1, shared2);

    Ok(())
}
