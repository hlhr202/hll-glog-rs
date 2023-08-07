use anyhow::{Error, Result};
use elliptic_curve::{
    sec1::{FromEncodedPoint, ToEncodedPoint},
    ScalarPrimitive,
};
use k256::{
    ecdh::{diffie_hellman, SharedSecret},
    EncodedPoint, PublicKey, SecretKey,
};

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public_key: String,
    pub private_key: String,
}

impl From<&KeyPair> for Result<SecretKey> {
    fn from(val: &KeyPair) -> std::result::Result<SecretKey, Error> {
        Ok(SecretKey::from_slice(&hex::decode(&val.private_key)?)?)
    }
}

impl From<&KeyPair> for Result<PublicKey> {
    fn from(value: &KeyPair) -> std::result::Result<PublicKey, Error> {
        let secret: Result<SecretKey> = value.into();
        let secret = secret?;

        let pub_key_bytes = EncodedPoint::from(secret.public_key());
        let pub_key = PublicKey::from_sec1_bytes(pub_key_bytes.as_ref())?;
        Ok(pub_key)
    }
}

impl KeyPair {
    pub fn from_secret_key(secret_key: &SecretKey) -> Result<Self> {
        let pub_key_bytes = EncodedPoint::from(secret_key.public_key());
        let pub_key = PublicKey::from_sec1_bytes(pub_key_bytes.as_ref())?;

        let encoded_point = pub_key.to_encoded_point(false);
        let x = encoded_point
            .x()
            .ok_or(anyhow::anyhow!("invalid public key"))?;
        let y = encoded_point
            .y()
            .ok_or(anyhow::anyhow!("invalid public key"))?;

        let mut untagged_public_key = Vec::new();
        untagged_public_key.extend_from_slice(x);
        untagged_public_key.extend_from_slice(y);

        let pub_key_hex = hex::encode_upper(untagged_public_key);

        let pri_key = secret_key.as_scalar_primitive();
        let pri_key_bytes = pri_key.to_bytes();

        let pri_key_hex = hex::encode_upper(pri_key_bytes);

        Ok(KeyPair {
            public_key: pub_key_hex,
            private_key: pri_key_hex,
        })
    }

    pub fn from_private_key_str(private_key: &str) -> Result<Self> {
        Self::from_secret_key(&SecretKey::from_slice(&hex::decode(private_key)?)?)
    }

    pub fn to_public_key_untagged_bytes(&self) -> Result<Vec<u8>> {
        let pub_key: Result<PublicKey> = self.into();
        let pub_key = pub_key?;

        let result = pub_key.to_encoded_point(false);
        let x = result.x().ok_or(anyhow::anyhow!("invalid public key"))?;
        let y = result.y().ok_or(anyhow::anyhow!("invalid public key"))?;

        let mut result = Vec::new();
        result.extend_from_slice(x);
        result.extend_from_slice(y);
        Ok(result)
    }

    pub fn random() -> Result<Self> {
        let secret = SecretKey::new(ScalarPrimitive::random(&mut rand_core::OsRng));
        Self::from_secret_key(&secret)
    }

    pub fn diffie_hellman(&self, pub_key_slice: &[u8]) -> Result<SharedSecret> {
        let secret: Result<SecretKey> = self.into();
        let secret = secret?;

        let pub_key =
            PublicKey::from_encoded_point(&EncodedPoint::from_untagged_bytes(pub_key_slice.into()));

        if pub_key.is_none().into() {
            return Err(anyhow::anyhow!("invalid public key"));
        }

        Ok(diffie_hellman(
            secret.to_nonzero_scalar(),
            pub_key.unwrap().as_affine(),
        ))
    }
}
