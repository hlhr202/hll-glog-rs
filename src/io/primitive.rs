use num_derive::{FromPrimitive, ToPrimitive};

#[derive(FromPrimitive, ToPrimitive, Default)]
pub enum FileVersion {
    V3 = 3,

    #[default]
    V4 = 4,
}

#[derive(Debug, FromPrimitive, Default)]
pub enum CompressMode {
    #[default]
    None = 1,
    Zlib = 2,
}

#[derive(Debug, FromPrimitive, Default)]
pub enum EncryptMode {
    #[default]
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

pub const SINGLE_LOG_CONTENT_MAX_LENGTH: usize = 16 * 1024;
pub const MAGIC_NUMBER: [u8; 4] = [0x1B, 0xAD, 0xC0, 0xDE];
pub const SYNC_MARKER: [u8; 8] = [0xB7, 0xDB, 0xE7, 0xDB, 0x80, 0xAD, 0xD9, 0x57];
