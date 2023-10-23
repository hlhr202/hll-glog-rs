use super::key_pair::KeyPair;
use aes::{
    cipher::{AsyncStreamCipher, KeyIvInit},
    Aes128,
};
use anyhow::Result;
use cfb_mode::{Decryptor, Encryptor};
use elliptic_curve::ecdh::SharedSecret;
use k256::Secp256k1;
use rand::{thread_rng, Rng};

type Aes128CfbDec = Decryptor<Aes128>;
type Aes128CfbEnc = Encryptor<Aes128>;

#[derive(Clone)]
pub struct Cipher {
    key_pair: KeyPair,
}

unsafe impl Send for Cipher {}
unsafe impl Sync for Cipher {}

impl Cipher {
    pub fn new(pri_key_str: &str) -> Result<Self> {
        let key_pair = KeyPair::from_private_key_str(pri_key_str)?;
        Ok(Self { key_pair })
    }

    pub fn get_key_pair(&self) -> &KeyPair {
        &self.key_pair
    }

    pub fn get_shared_key(&self, swaped_pub_key: &[u8]) -> Result<SharedSecret<Secp256k1>> {
        self.key_pair.diffie_hellman(swaped_pub_key)
    }

    pub fn random_iv() -> [u8; 16] {
        let mut iv = [0u8; 16];
        thread_rng().fill(&mut iv[..]);
        iv
    }

    pub fn decrypt_inplace(
        &self,
        swaped_pub_key: &[u8],
        iv: &[u8],
        buffer: &mut [u8],
    ) -> Result<()> {
        let shared = self.get_shared_key(swaped_pub_key)?;
        let aes_key = &shared.raw_secret_bytes()[0..16];
        let cipher = Aes128CfbDec::new(aes_key.into(), iv.into());

        cipher.decrypt(buffer);
        Ok(())
    }

    pub fn encrypt_inplace(
        &self,
        swaped_pub_key: &[u8],
        iv: &[u8],
        buffer: &mut [u8],
    ) -> Result<()> {
        let shared = self.get_shared_key(swaped_pub_key)?;
        let aes_key = &shared.raw_secret_bytes()[0..16];
        let cipher = Aes128CfbEnc::new(aes_key.into(), iv.into());

        cipher.encrypt(buffer);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Cipher;
    use super::KeyPair;
    use anyhow::Result;

    #[test]
    fn test_encryption() -> Result<()> {
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
}
