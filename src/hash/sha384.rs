//! SHA-384 helper mirroring the `sha256` / `sha512` module shape.

use sha2::{Digest as _, Sha384};

#[derive(Clone, Default)]
pub struct Context {
    hasher: Sha384,
}

pub fn init() -> Context {
    Context {
        hasher: Sha384::new(),
    }
}

pub fn update(ctx: &mut Context, message: &[u8]) {
    ctx.hasher.update(message);
}

pub fn final_bytes(ctx: Context) -> Vec<u8> {
    ctx.hasher.finalize().to_vec()
}

pub fn hash(message: &[u8]) -> Vec<u8> {
    Sha384::digest(message).to_vec()
}
