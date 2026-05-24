//! BLAKE2b compatibility helper.
//!
//! The C++ surface allows variable-size BLAKE2b output and a 32-byte
//! `generichash` helper.  This module keeps that shape, but delegates to the
//! RustCrypto `blake2` crate instead of carrying the C implementation.

use blake2::{
    Blake2bMac, Blake2bMac512, Blake2bVar,
    digest::{
        FixedOutput, KeyInit, Update, VariableOutput,
        consts::{U16, U32, U48},
    },
};

use super::hmac_blake2b;

pub const BYTES: usize = 64;
pub const BYTES_MIN: usize = 1;
pub const BYTES_MAX: usize = 64;
pub const KEYBYTES: usize = 64;
pub const KEYBYTES_MIN: usize = 0;
pub const KEYBYTES_MAX: usize = 64;

#[derive(Clone)]
pub struct Context {
    hasher: Blake2bVar,
    hash_size: usize,
}

pub fn init(hash_size: usize) -> Option<Context> {
    if !(BYTES_MIN..=BYTES_MAX).contains(&hash_size) {
        return None;
    }
    let hasher = Blake2bVar::new(hash_size).ok()?;
    Some(Context { hasher, hash_size })
}

pub fn update(ctx: &mut Context, message: &[u8]) {
    ctx.hasher.update(message);
}

pub fn final_bytes(ctx: Context) -> Vec<u8> {
    let mut out = vec![0u8; ctx.hash_size];
    ctx.hasher
        .finalize_variable(&mut out)
        .expect("validated BLAKE2b output size");
    out
}

pub fn hash(message: &[u8], hash_size: usize) -> Option<Vec<u8>> {
    let mut ctx = init(hash_size)?;
    update(&mut ctx, message);
    Some(final_bytes(ctx))
}

pub fn generichash(message: &[u8]) -> Vec<u8> {
    hash(message, 32).expect("32-byte BLAKE2b output size is valid")
}

pub fn keyed(message: &[u8], key: &[u8], hash_size: usize) -> Option<Vec<u8>> {
    if key.is_empty() || key.len() > KEYBYTES || !(BYTES_MIN..=BYTES_MAX).contains(&hash_size) {
        return None;
    }

    match hash_size {
        16 => {
            let mut mac = Blake2bMac::<U16>::new_from_slice(key).ok()?;
            mac.update(message);
            Some(mac.finalize_fixed().to_vec())
        }
        32 => {
            let mut mac = Blake2bMac::<U32>::new_from_slice(key).ok()?;
            mac.update(message);
            Some(mac.finalize_fixed().to_vec())
        }
        48 => {
            let mut mac = Blake2bMac::<U48>::new_from_slice(key).ok()?;
            mac.update(message);
            Some(mac.finalize_fixed().to_vec())
        }
        64 => {
            let mut mac = Blake2bMac512::new_from_slice(key).ok()?;
            mac.update(message);
            Some(mac.finalize_fixed().to_vec())
        }
        _ => {
            // The RustCrypto BLAKE2b MAC type is compile-time sized.  Keep the
            // safe Rust surface crate-backed and support the common/keylock
            // sizes directly; callers needing arbitrary keyed sizes can add the
            // exact type-size branch without pulling in hand crypto.
            None
        }
    }
}

pub fn keyed_64(key: &[u8], message: &[u8]) -> Vec<u8> {
    keyed(message, key, 64).expect("64-byte keyed BLAKE2b output size is valid")
}

pub fn generichash_keyed(key: &[u8], message: &[u8]) -> Vec<u8> {
    hmac_blake2b::keyed_32(key, message)
}
