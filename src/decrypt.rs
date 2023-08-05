use aes::{
    cipher::{AsyncStreamCipher, KeyIvInit},
    Aes128,
};
use anyhow::Result;
use cfb_mode::Decryptor;
use elliptic_curve::{
    ecdh::SharedSecret,
    sec1::{EncodedPoint, FromEncodedPoint},
    PublicKey, SecretKey,
};
use k256::{ecdh::diffie_hellman, Secp256k1};

type Aes128CfbDec = Decryptor<Aes128>;

pub struct AESDecryptor {
    secret: SecretKey<Secp256k1>,
}

impl AESDecryptor {
    pub fn new(pri_key_str: &str) -> Result<Self> {
        let pri_key_hex = hex::decode(pri_key_str)?;
        let secret = SecretKey::<Secp256k1>::from_slice(&pri_key_hex)?;
        Ok(Self { secret })
    }

    pub fn get_shared_key(&self, client_pub_key: &[u8]) -> Result<SharedSecret<Secp256k1>> {
        let pub_key = PublicKey::<Secp256k1>::from_encoded_point(
            &EncodedPoint::<Secp256k1>::from_untagged_bytes(client_pub_key.into()),
        );

        if pub_key.is_none().into() {
            return Err(anyhow::anyhow!("invalid public key"));
        }

        Ok(diffie_hellman(
            self.secret.to_nonzero_scalar(),
            pub_key.unwrap().as_affine(),
        ))
    }

    pub fn decrypt_inplace<'a>(
        &'a mut self,
        client_pub_key: &[u8],
        iv: &[u8],
        encrypt: &'a mut [u8],
    ) -> Result<()> {
        let shared = self.get_shared_key(client_pub_key)?;
        let aes_key = &shared.raw_secret_bytes()[0..16];
        let cipher = Aes128CfbDec::new(aes_key.into(), iv.into());

        cipher.decrypt(encrypt);
        Ok(())
    }
}
