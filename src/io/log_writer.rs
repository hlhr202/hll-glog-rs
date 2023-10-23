use crate::{cipher::aes_cfb_ecdh::Cipher, io::primitive::Mode};
use anyhow::Result;
use byteorder::WriteBytesExt;
use flate2::{Compress, Compression, FlushCompress};
use num_traits::ToPrimitive;
use std::io::{BufWriter, Write};

use super::primitive::{
    CompressMode, EncryptMode, FileVersion, MAGIC_NUMBER, SYNC_MARKER,
    SINGLE_LOG_CONTENT_MAX_LENGTH,
};

pub struct LogBufWriterV4<'a, W: Write> {
    writer: BufWriter<W>,
    cipher: &'a Cipher,
    compressor: Compress,
}

impl<'a, W: Write> LogBufWriterV4<'a, W> {
    pub fn new(writer: W, cipher: &'a Cipher) -> Self {
        Self {
            writer: BufWriter::new(writer),
            cipher,
            compressor: Compress::new_with_window_bits(Compression::default(), false, 15),
        }
    }

    pub fn into_inner(&mut self) -> &mut BufWriter<W> {
        &mut self.writer
    }

    pub fn write_head(&mut self) -> Result<()> {
        let writer = &mut self.writer;
        writer.write_all(&MAGIC_NUMBER)?;
        writer.write_u8(
            ToPrimitive::to_u8(&FileVersion::default())
                .ok_or(anyhow::anyhow!("invalid file version"))?,
        )?;

        let proto_name = b"ATRealTimeLog";
        let proto_name_length = proto_name.len() as u16;
        writer.write_u16::<byteorder::LittleEndian>(proto_name_length)?;
        writer.write_all(proto_name)?;
        writer.write_all(&SYNC_MARKER)?;
        writer.flush()?;
        Ok(())
    }

    pub fn write_single_log(
        &mut self,
        mode_tuple: &(CompressMode, EncryptMode),
        pub_key: &str,
        body: &str,
    ) -> Result<()> {
        let mode: Mode = mode_tuple.into();
        let mode_primitive = ToPrimitive::to_u8(&mode).ok_or(anyhow::anyhow!("invalid mode"))?;
        // println!(
        //     "compress: {:?}, encrypt: {:?}, log: {}",
        //     mode_tuple.0, mode_tuple.1, body
        // );
        self.writer.write_u8(mode_primitive)?;

        let mut log_body = body.as_bytes().to_vec();

        match mode_tuple.0 {
            CompressMode::None => {}
            CompressMode::Zlib => {
                log_body = self.compress_zlib(&log_body)?;
            }
        }

        match mode_tuple.1 {
            EncryptMode::None => {}
            EncryptMode::Aes => {
                let client_secret = self.cipher.get_key_pair();
                let server_pub_key = hex::decode(pub_key)?;
                let client_pub_key = client_secret.to_public_key_untagged_bytes()?;
                let iv = Cipher::random_iv();
                self.writer.write_all(&iv)?;
                self.writer.write_all(&client_pub_key)?;

                self.cipher
                    .encrypt_inplace(&server_pub_key, &iv, &mut log_body)?;
            }
        }

        let log_length = log_body.len() as u16;

        self.writer
            .write_u16::<byteorder::LittleEndian>(log_length)?;
        self.writer.write_all(&log_body)?;
        self.writer.write_all(&SYNC_MARKER)?;
        self.writer.flush()?;
        Ok(())
    }

    pub fn compress_zlib(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        let mut output: Vec<u8> = Vec::with_capacity(SINGLE_LOG_CONTENT_MAX_LENGTH);
        self.compressor
            .compress_vec(bytes, &mut output, FlushCompress::Sync)?;
        Ok(output)
    }
}
