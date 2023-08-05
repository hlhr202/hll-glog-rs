use std::io::{BufWriter, Write};

use anyhow::Result;
use byteorder::WriteBytesExt;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::ToPrimitive;

use crate::{
    cipher::{aes_cfb_ecdh::Cipher, key_pair::KeyPair},
    compression::compress_zlib,
};

const MAGIC_NUMBER: [u8; 4] = [0x1B, 0xAD, 0xC0, 0xDE];
const SYNC_MARKER: [u8; 8] = [0xB7, 0xDB, 0xE7, 0xDB, 0x80, 0xAD, 0xD9, 0x57];
const FILE_VERSION: u8 = 4; // V4

#[derive(Debug, FromPrimitive)]
pub enum CompressMode {
    None = 1,
    Zlib = 2,
}

#[derive(Debug, FromPrimitive)]
pub enum EncryptMode {
    None = 1,
    Aes = 2,
}

#[derive(Debug, FromPrimitive, ToPrimitive)]
pub enum Mode {
    M11 = 0x11,
    M12 = 0x12,
    M21 = 0x21,
    M22 = 0x22,
}

impl From<&(CompressMode, EncryptMode)> for Mode {
    fn from(mode: &(CompressMode, EncryptMode)) -> Mode {
        match mode {
            (CompressMode::None, EncryptMode::None) => Mode::M11,
            (CompressMode::None, EncryptMode::Aes) => Mode::M12,
            (CompressMode::Zlib, EncryptMode::None) => Mode::M21,
            (CompressMode::Zlib, EncryptMode::Aes) => Mode::M22,
        }
    }
}

pub fn write_head<W: Write>(writer: &mut BufWriter<W>) -> Result<()> {
    writer.write_all(&MAGIC_NUMBER)?;
    writer.write_u8(FILE_VERSION)?;

    let proto_name = b"ATRealTimeLog";
    let proto_name_length = proto_name.len() as u16;
    writer.write_u16::<byteorder::LittleEndian>(proto_name_length)?;
    writer.write_all(proto_name)?;
    writer.write_all(&SYNC_MARKER)?;
    writer.flush()?;
    Ok(())
}

pub fn write_single_log<W: Write>(
    writer: &mut BufWriter<W>,
    mode_tuple: &(CompressMode, EncryptMode),
    pub_key: &str,
    body: &str,
) -> Result<()> {
    let mode: Mode = mode_tuple.into();
    let mode_primitive = ToPrimitive::to_u8(&mode).ok_or(anyhow::anyhow!("invalid mode"))?;
    println!(
        "compress: {:?}, encrypt: {:?}, log: {}",
        mode_tuple.0, mode_tuple.1, body
    );
    writer.write_u8(mode_primitive)?;

    let mut log_body = body.as_bytes().to_vec();

    match mode_tuple.0 {
        CompressMode::None => {}
        CompressMode::Zlib => {
            log_body = compress_zlib(&log_body)?;
        }
    }

    match mode_tuple.1 {
        EncryptMode::None => {}
        EncryptMode::Aes => {
            let client_secret = KeyPair::random()?;
            let client_cipher = Cipher::new(&client_secret.private_key)?;
            let server_pub_key = hex::decode(pub_key)?;
            let client_pub_key = client_secret.to_public_key_untagged_bytes()?;
            let iv = Cipher::random_iv();
            writer.write_all(&iv)?;
            writer.write_all(&client_pub_key)?;

            client_cipher.encrypt_inplace(&server_pub_key, &iv, &mut log_body)?;
        }
    }

    let log_length = log_body.len() as u16;

    writer.write_u16::<byteorder::LittleEndian>(log_length)?;
    writer.write_all(&log_body)?;
    writer.write_all(&SYNC_MARKER)?;
    writer.flush()?;
    Ok(())
}
