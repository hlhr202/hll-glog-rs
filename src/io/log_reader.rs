use super::primitive::{
    CompressMode, EncryptMode, FileVersion, MAGIC_NUMBER, SINGLE_LOG_CONTENT_MAX_LENGTH,
    SYNC_MARKER,
};
use crate::cipher::aes_cfb_ecdh::Cipher;
use anyhow::Result;
use byteorder::{LittleEndian, ReadBytesExt};
use flate2::{Decompress, FlushDecompress};
use num_traits::FromPrimitive;
use std::io::{BufReader, Read};
use thiserror::Error;

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

pub struct LogBufReaderV4<'a, T: Read> {
    reader: BufReader<T>,
    position: i64,
    cipher: &'a Cipher,
    decompressor: Decompress, // use flate2::Decompress as mutable decompressor
}

impl<'a, T: Read> LogBufReaderV4<'a, T> {
    pub fn new(reader: T, cipher: &'a Cipher) -> LogBufReaderV4<'a, T> {
        Self {
            reader: BufReader::new(reader),
            position: 0,
            cipher,
            decompressor: Decompress::new_with_window_bits(false, 15),
        }
    }

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

    fn read_sync_marker(&mut self) -> Result<(), LogBufReadError> {
        let sync_marker = &self.reader.read_u64::<LittleEndian>()?.to_le_bytes();
        if sync_marker != &SYNC_MARKER {
            return Err(LogBufReadError::InvalidSyncMarker);
        }
        self.position += 8;
        Ok(())
    }

    fn read_log_length(&mut self) -> Result<i64, LogBufReadError> {
        let log_len = self.reader.read_u16::<LittleEndian>()?.into();
        if log_len <= 0 || log_len > SINGLE_LOG_CONTENT_MAX_LENGTH as i64 {
            return Err(LogBufReadError::InvalidLogLength);
        }
        self.position += 2;
        Ok(log_len)
    }

    fn read_remain_header(&mut self) -> Result<(), LogBufReadError> {
        let proto_name_len: usize = self.reader.read_u16::<LittleEndian>()?.into();
        let mut name: Vec<u8> = vec![0; proto_name_len];
        self.reader.read_exact(&mut name)?;
        // let proto_name = String::from_utf8(name)?;
        // println!("proto_name: {}", proto_name);
        self.read_sync_marker()?;
        self.position += 4 + 1 + 2 + proto_name_len as i64;

        Ok(())
    }

    pub fn read_body(&mut self, out_buffer: &mut Vec<u8>) -> Result<i64, LogBufReadError> {
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
                log_len =
                    self.decompress_zlib(&buf, out_buffer)
                        .map_err(|_| LogBufReadError::DecompressError)? as i64;
            }
        }

        self.read_sync_marker()?;

        Ok(log_len)
    }

    pub fn read(&mut self, mut callback: impl FnMut(&str)) -> Result<(), LogBufReadError> {
        let mut buffer = Vec::with_capacity(SINGLE_LOG_CONTENT_MAX_LENGTH);

        self.read_header()?;

        loop {
            let size = self.read_body(&mut buffer)?;

            if size <= 0 {
                break;
            }
            let content = buffer[0..size as usize].to_vec();

            buffer.clear(); // for resetting inflater output buffer

            let content = String::from_utf8_lossy(&content);
            callback(&content);
        }

        Ok(())
    }

    pub fn decompress_zlib(&mut self, input: &[u8], output: &mut Vec<u8>) -> Result<usize> {
        self.decompressor
            .decompress_vec(input, output, FlushDecompress::Sync)?;
        Ok(output.len())
    }
}
