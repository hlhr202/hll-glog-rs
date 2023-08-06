use crate::cipher::aes_cfb_ecdh::Cipher;
use crate::compression::decompress_zlib;
use anyhow::Result;
use byteorder::{LittleEndian, ReadBytesExt};
use num_traits::FromPrimitive;
use std::io::{BufReader, Read};
use thiserror::Error;

use super::primitive::{
    CompressMode, EncryptMode, FileVersion, MAGIC_NUMBER, SINGLE_LOG_CONTENT_MAX_LENGTH,
    SYNC_MARKER,
};

#[derive(Debug, Error)]
pub enum LogBufReadError {
    #[error("io error")]
    IoError(#[from] std::io::Error),

    #[error("invalid secret error")]
    InvalidSecret,

    #[error("invalid magic number")]
    InValidMagicNumber,

    #[error("invalid version")]
    InvalidVersion,

    #[error("invalid sync marker")]
    InvalidSyncMarker,

    #[error("invalid log length")]
    InvalidLogLength,

    #[error("decryption error")]
    DecryptionError,

    #[error("decompress error")]
    DecompressError,
}

struct LogBufReaderV4<T: Read> {
    reader: BufReader<T>,
    position: i64,
    cipher: Cipher,
}

impl<T: Read> LogBufReaderV4<T> {
    pub fn read_header(&mut self) -> Result<(), LogBufReadError> {
        let magic: &mut [u8; 4] = &mut self.reader.read_u32::<LittleEndian>()?.to_le_bytes();

        if magic != &MAGIC_NUMBER {
            return Err(LogBufReadError::InValidMagicNumber);
        }

        let version = self.reader.read_u8()?;

        match FromPrimitive::from_u8(version) {
            Some(FileVersion::V3) => {
                // println!("version: 3");
            }
            Some(FileVersion::V4) => {
                // println!("version: 4");
            }
            _ => {
                return Err(LogBufReadError::InvalidVersion);
            }
        }

        self.read_remain_header()?;

        Ok(())
    }

    pub fn read_sync_marker(&mut self) -> Result<(), LogBufReadError> {
        let sync_marker = &self.reader.read_u64::<LittleEndian>()?.to_le_bytes();
        if sync_marker != &SYNC_MARKER {
            return Err(LogBufReadError::InvalidSyncMarker);
        }
        self.position += 8;
        Ok(())
    }

    pub fn read_log_length(&mut self) -> Result<i64, LogBufReadError> {
        let log_len = self.reader.read_u16::<LittleEndian>()?.into();
        if log_len <= 0 || log_len > SINGLE_LOG_CONTENT_MAX_LENGTH as i64 {
            return Err(LogBufReadError::InvalidLogLength);
        }
        self.position += 2;
        Ok(log_len)
    }

    pub fn read_remain_header(&mut self) -> Result<(), LogBufReadError> {
        let proto_name_len: usize = self.reader.read_u16::<LittleEndian>()?.into();
        let mut name: Vec<u8> = vec![0; proto_name_len];
        self.reader.read_exact(&mut name)?;
        // let proto_name = String::from_utf8(name)?;
        // println!("proto_name: {}", proto_name);
        self.read_sync_marker()?;
        self.position += 4 + 1 + 2 + proto_name_len as i64;

        Ok(())
    }

    pub fn read(&mut self, out_buffer: &mut [u8]) -> Result<i64, LogBufReadError> {
        if self.reader.buffer().len() < 2 + 1 + 8 {
            return Ok(-1);
        }

        let ms: i32 = self.reader.read_u8()?.into();

        let compress_mode = match ms >> 4 {
            1 => CompressMode::None,
            2 => CompressMode::Zlib,
            _ => {
                println!("illegal compress mode: {}", ms >> 4);
                return Ok(-2);
            }
        };

        let encrypt_mode = match ms & 0x0F {
            1 => EncryptMode::None,
            2 => EncryptMode::Aes,
            _ => {
                println!("illegal encrypt mode: {}", ms & 0x0F);
                return Ok(-3);
            }
        };

        // println!("compress_mode: {:?}", compress_mode);
        // println!("encrypt_mode: {:?}", encrypt_mode);

        self.position += 1;

        #[allow(unused_assignments)]
        let mut log_len: i64 = 0;

        let buf = match encrypt_mode {
            EncryptMode::Aes => {
                let iv = &self.reader.read_u128::<LittleEndian>()?.to_le_bytes();
                let client_pubkey: &mut [u8; 64] = &mut [0; 64];
                self.reader.read_exact(client_pubkey)?;
                self.position += 16 + 64;

                log_len = self.read_log_length()?;

                let mut buf = vec![0; log_len as usize];
                self.reader.read_exact(&mut buf)?;
                self.cipher
                    .decrypt_inplace(client_pubkey, iv, &mut buf)
                    .map_err(|_| LogBufReadError::DecryptionError)?;

                if buf.is_empty() {
                    return Ok(-5);
                }

                buf
            }
            EncryptMode::None => {
                log_len = self.read_log_length()?;
                let mut buf = vec![0; log_len as usize];
                self.reader.read_exact(&mut buf)?;
                buf
            }
        };

        match compress_mode {
            CompressMode::None => {
                out_buffer[..buf.len()].copy_from_slice(&buf);
                log_len = buf.len() as i64;
            }
            CompressMode::Zlib => {
                let plain = decompress_zlib(&buf).map_err(|_| LogBufReadError::DecompressError)?;
                out_buffer[..plain.len()].copy_from_slice(&plain);
                log_len = plain.len() as i64;
            }
        }

        self.read_sync_marker()?;

        Ok(log_len)
    }
}

pub fn read<T: Read>(
    reader: BufReader<T>,
    pri_key: &str,
    mut callback: impl FnMut(&str),
) -> Result<(), LogBufReadError> {
    let cipher = Cipher::new(pri_key).map_err(|_| LogBufReadError::InvalidSecret)?;

    let mut file_reader = LogBufReaderV4 {
        reader,
        position: 0,
        cipher,
    };

    let mut buffer = [0; SINGLE_LOG_CONTENT_MAX_LENGTH];

    file_reader.read_header()?;

    loop {
        let size = file_reader.read(&mut buffer)?;

        // println!("size: {}", size);
        if size <= 0 {
            break;
        }
        let content = buffer[0..size as usize].to_vec();
        let content = String::from_utf8_lossy(&content);
        callback(&content);
    }

    Ok(())
}