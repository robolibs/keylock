//! SHA-512 compatibility helper.
//!
//! Keep the C++ `keylock/hash/sha512` module shape while using RustCrypto
//! `sha2` for the implementation.

use sha2::{Digest as _, Sha512};

pub const BYTES: usize = 64;

#[derive(Clone)]
pub struct Context {
    hasher: Sha512,
}

pub fn init() -> Context {
    Context {
        hasher: Sha512::new(),
    }
}

pub fn update(ctx: &mut Context, message: &[u8]) {
    ctx.hasher.update(message);
}

pub fn final_bytes(ctx: Context) -> Vec<u8> {
    ctx.hasher.finalize().to_vec()
}

pub fn hash(message: &[u8]) -> Vec<u8> {
    let mut ctx = init();
    update(&mut ctx, message);
    final_bytes(ctx)
}
