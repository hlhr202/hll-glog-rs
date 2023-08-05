use aes::{
    cipher::{AsyncStreamCipher, KeyIvInit},
    Aes128,
};
use anyhow::Result;
use cfb_mode::{Decryptor, Encryptor};
use elliptic_curve::ecdh::SharedSecret;
use k256::Secp256k1;

use super::key_pair::KeyPair;

type Aes128CfbDec = Decryptor<Aes128>;
type Aes128CfbEnc = Encryptor<Aes128>;

pub struct Cipher {
    key_pair: KeyPair,
}

impl Cipher {
    pub fn new(pri_key_str: &str) -> Result<Self> {
        let key_pair = KeyPair::from_private_key_str(pri_key_str)?;
        Ok(Self { key_pair })
    }

    pub fn get_shared_key(&self, client_pub_key: &[u8]) -> Result<SharedSecret<Secp256k1>> {
        self.key_pair.diffie_hellman(client_pub_key)
    }

    pub fn decrypt_inplace<'a>(
        &'a mut self,
        client_pub_key: &[u8],
        iv: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<()> {
        let shared = self.get_shared_key(client_pub_key)?;
        let aes_key = &shared.raw_secret_bytes()[0..16];
        let cipher = Aes128CfbDec::new(aes_key.into(), iv.into());

        cipher.decrypt(buffer);
        Ok(())
    }

    pub fn encrypt_inplace<'a>(
        &'a mut self,
        client_pub_key: &[u8],
        iv: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<()> {
        let shared = self.get_shared_key(client_pub_key)?;
        let aes_key = &shared.raw_secret_bytes()[0..16];
        let cipher = Aes128CfbEnc::new(aes_key.into(), iv.into());

        cipher.encrypt(buffer);

        Ok(())
    }
}
