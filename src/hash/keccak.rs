//! Keccak compatibility helper.
//!
//! The C++ dependency exposes `keylock::hash::keccak::hash_256`; the Rust port
//! keeps that hierarchy and delegates to the RustCrypto `sha3` crate.

use sha3::{Digest as _, Keccak256};

pub const BYTES_256: usize = 32;

#[derive(Clone)]
pub struct Context {
    hasher: Keccak256,
}

pub fn init_256() -> Context {
    Context {
        hasher: Keccak256::new(),
    }
}

pub fn update(ctx: &mut Context, message: &[u8]) {
    ctx.hasher.update(message);
}

pub fn final_256_bytes(ctx: Context) -> Vec<u8> {
    ctx.hasher.finalize().to_vec()
}

pub fn hash_256(message: &[u8]) -> Vec<u8> {
    let mut ctx = init_256();
    update(&mut ctx, message);
    final_256_bytes(ctx)
}
