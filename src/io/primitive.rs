use num_derive::{FromPrimitive, ToPrimitive};

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
