// The rust detector matches the cipher identifier, not the key length, so this
// arrives as AES with no size even though the source says 128 on this line.
use aes_gcm::{Aes128Gcm, KeyInit};

pub fn cipher(key: &[u8; 16]) -> Aes128Gcm {
    Aes128Gcm::new(key.into())
}
