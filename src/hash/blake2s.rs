//! BLAKE2s compatibility helper.
//!
//! Mirrors `keylock/hash/blake2s/blake2s.hpp` while delegating BLAKE2s and
//! keyed MAC behavior to the RustCrypto `blake2` crate.

use blake2::{
    Blake2sMac, Blake2sMac256, Blake2sVar,
    digest::{
        Mac, Update, VariableOutput,
        consts::{U16, U24},
    },
};

pub const BYTES: usize = 32;
pub const BYTES_MIN: usize = 1;
pub const BYTES_MAX: usize = 32;
pub const KEYBYTES: usize = 32;
pub const KEYBYTES_MAX: usize = 32;
pub const BLOCKBYTES: usize = 64;
pub const SALTBYTES: usize = 8;
pub const PERSONALBYTES: usize = 8;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Context {
    hash_size: usize,
    key: Vec<u8>,
    data: Vec<u8>,
}

pub fn init() -> Context {
    init_with_size(BYTES)
}

pub fn init_with_size(hash_size: usize) -> Context {
    Context {
        hash_size,
        key: Vec::new(),
        data: Vec::new(),
    }
}

pub fn keyed_init(hash_size: usize, key: &[u8]) -> Context {
    Context {
        hash_size,
        key: key.to_vec(),
        data: Vec::new(),
    }
}

pub fn update(ctx: &mut Context, message: &[u8]) {
    ctx.data.extend_from_slice(message);
}

pub fn final_bytes(ctx: &Context) -> Vec<u8> {
    if ctx.key.is_empty() {
        hash_with_size(ctx.hash_size, &ctx.data)
    } else {
        keyed_with_size(ctx.hash_size, &ctx.key, &ctx.data)
    }
}

pub fn hash(message: &[u8]) -> Vec<u8> {
    hash_with_size(BYTES, message)
}

pub fn hash_with_size(hash_size: usize, message: &[u8]) -> Vec<u8> {
    if !(BYTES_MIN..=BYTES_MAX).contains(&hash_size) {
        return Vec::new();
    }
    let Ok(mut hasher) = Blake2sVar::new(hash_size) else {
        return Vec::new();
    };
    hasher.update(message);
    let mut out = vec![0u8; hash_size];
    if hasher.finalize_variable(&mut out).is_err() {
        return Vec::new();
    }
    out
}

pub fn keyed(key: &[u8], message: &[u8]) -> Vec<u8> {
    keyed_with_size(BYTES, key, message)
}

pub fn keyed_with_size(hash_size: usize, key: &[u8], message: &[u8]) -> Vec<u8> {
    if key.is_empty() || key.len() > KEYBYTES_MAX || !(BYTES_MIN..=BYTES_MAX).contains(&hash_size) {
        return Vec::new();
    }
    match hash_size {
        16 => keyed_16(key, message),
        24 => keyed_24(key, message),
        32 => keyed_32(key, message),
        _ => {
            let full = keyed_32(key, message);
            full[..hash_size].to_vec()
        }
    }
}

fn keyed_16(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac =
        <Blake2sMac<U16> as Mac>::new_from_slice(key).expect("validated BLAKE2s-128 key length");
    Mac::update(&mut mac, message);
    mac.finalize().into_bytes().to_vec()
}

fn keyed_24(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac =
        <Blake2sMac<U24> as Mac>::new_from_slice(key).expect("validated BLAKE2s-192 key length");
    Mac::update(&mut mac, message);
    mac.finalize().into_bytes().to_vec()
}

pub fn keyed_32(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac =
        <Blake2sMac256 as Mac>::new_from_slice(key).expect("validated BLAKE2s-256 key length");
    Mac::update(&mut mac, message);
    mac.finalize().into_bytes().to_vec()
}
