//! SHA-256 compatibility helper.
//!
//! This mirrors the small `keylock/hash/sha256` C++ namespace, but delegates
//! the actual compression/state machine to the RustCrypto `sha2` crate.

use sha2::{Digest as _, Sha256};

pub const BYTES: usize = 32;

#[derive(Clone)]
pub struct Context {
    hasher: Sha256,
}

pub fn init() -> Context {
    Context {
        hasher: Sha256::new(),
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
