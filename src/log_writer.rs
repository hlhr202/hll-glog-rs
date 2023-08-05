const MAGIC_NUMBER: [u8; 4] = [0x1B, 0xAD, 0xC0, 0xDE];
const SYNC_MARKER: [u8; 8] = [0xB7, 0xDB, 0xE7, 0xDB, 0x80, 0xAD, 0xD9, 0x57];

struct EntityV4 {
    magic: [u8; 4],
    version: u8,
    proto_name_length: u16,
    proto_name: Vec<u8>,
    sync_marker: [u8; 8],
    mode_set: u8
}
