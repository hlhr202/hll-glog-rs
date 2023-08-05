use anyhow::Result;
use flate2::bufread::ZlibDecoder;
use std::io::Read;

pub fn decompress_zlib(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut z = ZlibDecoder::new(bytes);
    z.read_to_end(&mut buf)?;
    Ok(buf)
}
