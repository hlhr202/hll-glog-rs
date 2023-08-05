use anyhow::Result;
use flate2::bufread::ZlibDecoder;
use std::io::{Read, Write};

pub fn decompress_zlib(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut z = ZlibDecoder::new(bytes);
    z.read_to_end(&mut buf)?;
    Ok(buf)
}

pub fn compress_zlib(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut z = flate2::write::ZlibEncoder::new(&mut buf, flate2::Compression::default());
    z.write_all(bytes)?;
    z.finish()?;
    Ok(buf)
}
