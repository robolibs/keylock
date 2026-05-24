//! BLAKE2b-backed generic hash helpers.

use blake2::{
    Blake2bMac, Blake2bMac512,
    digest::{
        FixedOutput, KeyInit, Update,
        consts::{U16, U32, U48},
    },
};

use crate::hash::blake2b;

pub const BYTES: usize = 32;
pub const BYTES_MIN: usize = 16;
pub const BYTES_MAX: usize = 64;
pub const KEYBYTES: usize = 32;
pub const KEYBYTES_MIN: usize = 16;
pub const KEYBYTES_MAX: usize = 64;

#[derive(Clone)]
enum Inner {
    Unkeyed(blake2b::Context),
    Keyed16(Blake2bMac<U16>),
    Keyed32(Blake2bMac<U32>),
    Keyed48(Blake2bMac<U48>),
    Keyed64(Blake2bMac512),
}

#[derive(Clone)]
pub struct Context {
    inner: Inner,
}

pub fn init(hash_size: usize) -> Option<Context> {
    Some(Context {
        inner: Inner::Unkeyed(blake2b::init(hash_size)?),
    })
}

pub fn init_with_key(hash_size: usize, key: &[u8]) -> Option<Context> {
    if key.is_empty() || key.len() > KEYBYTES_MAX {
        return None;
    }

    let inner = match hash_size {
        16 => Inner::Keyed16(Blake2bMac::<U16>::new_from_slice(key).ok()?),
        32 => Inner::Keyed32(Blake2bMac::<U32>::new_from_slice(key).ok()?),
        48 => Inner::Keyed48(Blake2bMac::<U48>::new_from_slice(key).ok()?),
        64 => Inner::Keyed64(Blake2bMac512::new_from_slice(key).ok()?),
        _ => return None,
    };
    Some(Context { inner })
}

pub fn keyed_init(hash_size: usize, key: &[u8]) -> Option<Context> {
    init_with_key(hash_size, key)
}

pub fn update(ctx: &mut Context, message: &[u8]) {
    match &mut ctx.inner {
        Inner::Unkeyed(ctx) => blake2b::update(ctx, message),
        Inner::Keyed16(mac) => mac.update(message),
        Inner::Keyed32(mac) => mac.update(message),
        Inner::Keyed48(mac) => mac.update(message),
        Inner::Keyed64(mac) => mac.update(message),
    }
}

pub fn final_bytes(ctx: Context) -> Vec<u8> {
    match ctx.inner {
        Inner::Unkeyed(ctx) => blake2b::final_bytes(ctx),
        Inner::Keyed16(mac) => mac.finalize_fixed().to_vec(),
        Inner::Keyed32(mac) => mac.finalize_fixed().to_vec(),
        Inner::Keyed48(mac) => mac.finalize_fixed().to_vec(),
        Inner::Keyed64(mac) => mac.finalize_fixed().to_vec(),
    }
}

pub fn hash(message: &[u8], hash_size: usize) -> Option<Vec<u8>> {
    if !(BYTES_MIN..=BYTES_MAX).contains(&hash_size) {
        return None;
    }
    blake2b::hash(message, hash_size)
}

pub fn hash_keyed(message: &[u8], key: &[u8], hash_size: usize) -> Option<Vec<u8>> {
    if !(BYTES_MIN..=BYTES_MAX).contains(&hash_size) {
        return None;
    }
    blake2b::keyed(message, key, hash_size)
}

pub fn generichash(message: &[u8]) -> Vec<u8> {
    hash(message, BYTES).expect("default BLAKE2b generic hash size is valid")
}

pub fn generichash_keyed(message: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    hash_keyed(message, key, BYTES)
}
