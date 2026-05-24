//! SHA-3 hash-family compatibility helpers.
//!
//! Mirrors `keylock/hash/sha3/sha3.hpp` while delegating hashing to the
//! RustCrypto `sha3` crate instead of carrying the C++ sponge implementation.

use sha3::{Digest as _, Sha3_224, Sha3_256, Sha3_384, Sha3_512};

pub const BYTES_224: usize = 28;
pub const BYTES_256: usize = 32;
pub const BYTES_384: usize = 48;
pub const BYTES_512: usize = 64;

#[derive(Clone)]
pub enum Context {
    Sha3_224(Sha3_224),
    Sha3_256(Sha3_256),
    Sha3_384(Sha3_384),
    Sha3_512(Sha3_512),
}

pub fn init_224() -> Context {
    Context::Sha3_224(Sha3_224::new())
}

pub fn init_256() -> Context {
    Context::Sha3_256(Sha3_256::new())
}

pub fn init_384() -> Context {
    Context::Sha3_384(Sha3_384::new())
}

pub fn init_512() -> Context {
    Context::Sha3_512(Sha3_512::new())
}

pub fn init(hash_bits: usize) -> Context {
    match hash_bits {
        224 => init_224(),
        256 => init_256(),
        384 => init_384(),
        512 => init_512(),
        _ => init_512(),
    }
}

pub fn update(ctx: &mut Context, message: &[u8]) {
    match ctx {
        Context::Sha3_224(hasher) => hasher.update(message),
        Context::Sha3_256(hasher) => hasher.update(message),
        Context::Sha3_384(hasher) => hasher.update(message),
        Context::Sha3_512(hasher) => hasher.update(message),
    }
}

pub fn final_bytes(ctx: &Context) -> Vec<u8> {
    match ctx {
        Context::Sha3_224(hasher) => hasher.clone().finalize().to_vec(),
        Context::Sha3_256(hasher) => hasher.clone().finalize().to_vec(),
        Context::Sha3_384(hasher) => hasher.clone().finalize().to_vec(),
        Context::Sha3_512(hasher) => hasher.clone().finalize().to_vec(),
    }
}

pub fn hash_224(message: &[u8]) -> Vec<u8> {
    let mut ctx = init_224();
    update(&mut ctx, message);
    final_bytes(&ctx)
}

pub fn hash_256(message: &[u8]) -> Vec<u8> {
    let mut ctx = init_256();
    update(&mut ctx, message);
    final_bytes(&ctx)
}

pub fn hash_384(message: &[u8]) -> Vec<u8> {
    let mut ctx = init_384();
    update(&mut ctx, message);
    final_bytes(&ctx)
}

pub fn hash_512(message: &[u8]) -> Vec<u8> {
    let mut ctx = init_512();
    update(&mut ctx, message);
    final_bytes(&ctx)
}
