/* const MAGIC_NUMBER: [u8; 4] = [0x1B, 0xAD, 0xC0, 0xDE];
const SYNC_MARKER: [u8; 8] = [0xB7, 0xDB, 0xE7, 0xDB, 0x80, 0xAD, 0xD9, 0x57];

struct EntityV4 {
    magic: [u8; 4],
    version: u8,
    proto_name_length: u16,
    proto_name: Vec<u8>,
    sync_marker: [u8; 8],
    mode_set: u8
}
 */
use std::io::{BufWriter, Write};

use anyhow::Result;
use byteorder::WriteBytesExt;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::ToPrimitive;

const MAGIC_NUMBER: [u8; 4] = [0x1B, 0xAD, 0xC0, 0xDE];
const SYNC_MARKER: [u8; 8] = [0xB7, 0xDB, 0xE7, 0xDB, 0x80, 0xAD, 0xD9, 0x57];
const FILE_VERSION: u8 = 4; // V4

#[derive(Debug, FromPrimitive)]
enum CompressMode {
    None = 1,
    Zlib = 2,
}

#[derive(Debug, FromPrimitive)]
enum EncryptMode {
    None = 1,
    Aes = 2,
}

#[derive(Debug, FromPrimitive, ToPrimitive)]
enum Mode {
    M11 = 0x11,
    M12 = 0x12,
    M21 = 0x21,
    M22 = 0x22,
}

impl From<(CompressMode, EncryptMode)> for Mode {
    fn from(mode: (CompressMode, EncryptMode)) -> Mode {
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

pub fn write_single_log<W: Write>(writer: &mut BufWriter<W>, body: &str) -> Result<()> {
    let mode: Mode = (CompressMode::None, EncryptMode::None).into();
    let mode_primitive = ToPrimitive::to_u8(&mode).unwrap();
    println!(
        "compress: {:?}, encrypt: {:?}, log: {}",
        CompressMode::None,
        EncryptMode::None,
        body
    );
    writer.write_u8(mode_primitive)?;

    let log_body = body.as_bytes();
    let log_length = log_body.len() as u16;
    writer.write_u16::<byteorder::LittleEndian>(log_length)?;
    writer.write_all(log_body)?;
    writer.write_all(&SYNC_MARKER)?;
    writer.flush()?;
    Ok(())
}
