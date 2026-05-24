//! ChaCha20 compatibility helper.
//!
//! The C++ source implements the stream cipher directly.  The Rust port keeps
//! the old `keylock::crypto::chacha20` boundary and uses RustCrypto's
//! `chacha20` crate for DJB, IETF, HChaCha20, and XChaCha20.

use ::chacha20::{
    ChaCha20, ChaCha20Legacy, XChaCha20,
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek, consts::U10},
    hchacha,
};

pub const KEYBYTES: usize = 32;
pub const NONCEBYTES_DJB: usize = 8;
pub const NONCEBYTES_IETF: usize = 12;
pub const NONCEBYTES_XCHACHA20: usize = 24;
pub const BLOCKBYTES: usize = 64;

pub fn hchacha20(key: &[u8], nonce16: &[u8]) -> Vec<u8> {
    if key.len() != KEYBYTES || nonce16.len() != 16 {
        return Vec::new();
    }
    hchacha::<U10>(key.into(), nonce16.into()).to_vec()
}

pub fn chacha20_djb(
    input: Option<&[u8]>,
    len: usize,
    key: &[u8],
    nonce: &[u8],
    counter: u64,
) -> Vec<u8> {
    if key.len() != KEYBYTES || nonce.len() != NONCEBYTES_DJB {
        return Vec::new();
    }
    let mut out = match input {
        Some(bytes) if bytes.len() == len => bytes.to_vec(),
        Some(_) => return Vec::new(),
        None => vec![0u8; len],
    };
    let mut cipher = ChaCha20Legacy::new(key.into(), nonce.into());
    cipher.seek(counter.saturating_mul(BLOCKBYTES as u64));
    cipher.apply_keystream(&mut out);
    out
}

pub fn chacha20_ietf(
    input: Option<&[u8]>,
    len: usize,
    key: &[u8],
    nonce: &[u8],
    counter: u32,
) -> Vec<u8> {
    if key.len() != KEYBYTES || nonce.len() != NONCEBYTES_IETF {
        return Vec::new();
    }
    let mut out = match input {
        Some(bytes) if bytes.len() == len => bytes.to_vec(),
        Some(_) => return Vec::new(),
        None => vec![0u8; len],
    };
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    cipher.seek(u64::from(counter) * BLOCKBYTES as u64);
    cipher.apply_keystream(&mut out);
    out
}

pub fn xchacha20(
    input: Option<&[u8]>,
    len: usize,
    key: &[u8],
    nonce: &[u8],
    counter: u64,
) -> Vec<u8> {
    if key.len() != KEYBYTES || nonce.len() != NONCEBYTES_XCHACHA20 {
        return Vec::new();
    }
    let mut out = match input {
        Some(bytes) if bytes.len() == len => bytes.to_vec(),
        Some(_) => return Vec::new(),
        None => vec![0u8; len],
    };
    let mut cipher = XChaCha20::new(key.into(), nonce.into());
    cipher.seek(counter.saturating_mul(BLOCKBYTES as u64));
    cipher.apply_keystream(&mut out);
    out
}
