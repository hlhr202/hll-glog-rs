use crate::decrypt::AESDecryptor;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::io::{self, BufReader, Read};

const SINGLE_LOG_CONTENT_MAX_LENGTH: usize = 16 * 1024;
const MAGIC_NUMBER: [u8; 4] = [0x1B, 0xAD, 0xC0, 0xDE];
const SYNC_MARKER: [u8; 8] = [0xB7, 0xDB, 0xE7, 0xDB, 0x80, 0xAD, 0xD9, 0x57];

#[derive(FromPrimitive)]
enum FileVersion {
    V3 = 3,
    V4 = 4,
}

#[derive(Debug)]
enum CompressMode {
    None = 1,
    Zlib = 2,
}

#[derive(Debug)]
enum EncryptMode {
    None = 1,
    Aes = 2,
}

struct LogBufReaderV4<T: Read> {
    reader: BufReader<T>,
    position: i64,
    decryptor: AESDecryptor,
}

impl<T: Read> LogBufReaderV4<T> {
    pub fn read_header(&mut self) -> Result<(), io::Error> {
        let magic: &mut [u8; 4] = &mut [0; 4];
        self.reader.read_exact(magic)?;

        if magic != &MAGIC_NUMBER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "magic number not match",
            ));
        }

        let next = &mut [0; 1];

        self.reader.read_exact(next)?;

        match FromPrimitive::from_u8(next[0]) {
            Some(FileVersion::V3) => {
                // println!("version: 3");
            }
            Some(FileVersion::V4) => {
                // println!("version: 4");
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "version not match",
                ));
            }
        }

        self.read_remain_header()?;

        Ok(())
    }

    pub fn read_u16le(&mut self) -> Result<u16, io::Error> {
        let mut buffer = [0; 2];
        self.reader.read_exact(&mut buffer)?;
        Ok(u16::from_le_bytes(buffer))
    }

    pub fn read_remain_header(&mut self) -> Result<(), io::Error> {
        let proto_name_len = self.read_u16le()? as usize;
        let mut name: Vec<u8> = vec![0; proto_name_len];
        self.reader.read_exact(&mut name)?;
        // let proto_name = String::from_utf8(name).unwrap();
        // println!("proto_name: {}", proto_name);

        let sync_marker: &mut [u8; 8] = &mut [0; 8];
        self.reader.read_exact(sync_marker)?;

        if sync_marker != &SYNC_MARKER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sync marker not match",
            ));
        }

        self.position += 4 + 1 + 2 + proto_name_len as i64 + 8;

        Ok(())
    }

    pub fn read(&mut self, out_buffer: &mut [u8]) -> anyhow::Result<i64, io::Error> {
        if self.reader.buffer().len() < 2 + 1 + 8 {
            return Ok(-1);
        }

        let byte: &mut [u8; 1] = &mut [0; 1];
        self.reader.read_exact(byte)?;
        let ms = byte[0] as i32;

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

        match encrypt_mode {
            EncryptMode::Aes => {
                let iv: &mut [u8; 16] = &mut [0; 16];
                self.reader.read_exact(iv)?;

                let client_pubkey: &mut [u8; 64] = &mut [0; 64];
                self.reader.read_exact(client_pubkey)?;

                self.position += 16 + 64;

                log_len = self.read_u16le()? as i64;

                // println!("log_len: {}", log_len);

                if log_len <= 0 || log_len > SINGLE_LOG_CONTENT_MAX_LENGTH as i64 {
                    return Ok(-4);
                }

                self.position += 2 + log_len;

                let mut buf = vec![0; log_len as usize];
                self.reader.read_exact(&mut buf)?;

                let plain = self
                    .decryptor
                    .decrypt(client_pubkey, iv, &mut buf)
                    .map_err(|e| {
                        io::Error::new(io::ErrorKind::InvalidData, format!("decrypt failed: {}", e))
                    })?;

                if plain.is_empty() {
                    return Ok(-5);
                }

                match compress_mode {
                    CompressMode::None => {
                        out_buffer[..plain.len()].copy_from_slice(plain);
                    }
                    CompressMode::Zlib => todo!("compress_mode: Zlib"),
                }
            }
            EncryptMode::None => todo!("encrypt_mode: None"),
        }

        let sync_marker: &mut [u8; 8] = &mut [0; 8];
        self.reader.read_exact(sync_marker)?;

        if sync_marker != &SYNC_MARKER {
            return Ok(-7);
        }

        self.position += 8;

        Ok(log_len)
    }
}

pub fn read<T: Read>(reader: BufReader<T>, pri_key: &str) -> anyhow::Result<()> {
    let decryptor = AESDecryptor::new(pri_key)?;

    let mut file_reader = LogBufReaderV4 {
        reader,
        position: 0,
        decryptor,
    };

    let mut buffer = [0; SINGLE_LOG_CONTENT_MAX_LENGTH];

    file_reader.read_header()?;

    loop {
        let result = file_reader.read(&mut buffer);

        match result {
            Ok(size) => {
                // println!("size: {}", size);
                if size <= 0 {
                    break;
                }
                let content = buffer[0..size as usize].to_vec();
                println!("content: {:?}", String::from_utf8_lossy(&content));
            }
            Err(e) => {
                println!("error: {}", e);
                break;
            }
        }
    }

    Ok(())
}
