use anyhow::Result;
use glog_rust::cipher::{aes_cfb_ecdh::Cipher, key_pair::KeyPair};

fn main() -> Result<()> {
    let plain_text = b"hello world";
    let client_key_pair = KeyPair::random()?;
    let server_key_pair = KeyPair::random()?;

    let client_cipher = Cipher::new(&client_key_pair.private_key)?;
    let random_iv = Cipher::random_iv();
    let mut buffer = plain_text.to_vec();

    client_cipher.encrypt_inplace(
        &server_key_pair.to_public_key_untagged_bytes()?,
        &random_iv,
        &mut buffer,
    )?;

    println!("encrypted: {:?}", String::from_utf8_lossy(&buffer));

    let server_cipher = Cipher::new(&server_key_pair.private_key)?;
    server_cipher.decrypt_inplace(
        &client_key_pair.to_public_key_untagged_bytes()?,
        &random_iv,
        &mut buffer,
    )?;

    println!("decrypted: {:?}", String::from_utf8_lossy(&buffer));
    println!("decrypted == original: {}", buffer == plain_text);

    assert!(buffer == plain_text);

    Ok(())
}
