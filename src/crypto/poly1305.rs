//! Poly1305 compatibility helper.
//!
//! The C++ tree keeps this at `keylock/crypto/poly1305/poly1305.hpp` and
//! contains a local Monocypher-derived implementation.  The Rust port keeps the
//! same module boundary but delegates the authenticator to the audited
//! RustCrypto `poly1305` crate.

use ::poly1305::{Key, Poly1305, universal_hash::KeyInit};

pub const BYTES: usize = 16;
pub const KEYBYTES: usize = 32;
pub const BLOCKBYTES: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Context {
    key: [u8; KEYBYTES],
    data: Vec<u8>,
    valid: bool,
}

impl Default for Context {
    fn default() -> Self {
        Self {
            key: [0u8; KEYBYTES],
            data: Vec::new(),
            valid: false,
        }
    }
}

pub fn init(key: &[u8]) -> Context {
    let mut ctx = Context::default();
    init_context(&mut ctx, key);
    ctx
}

pub fn init_context(ctx: &mut Context, key: &[u8]) -> bool {
    ctx.data.clear();
    ctx.valid = key.len() == KEYBYTES;
    ctx.key = [0u8; KEYBYTES];
    if ctx.valid {
        ctx.key.copy_from_slice(key);
    }
    ctx.valid
}

pub fn update(ctx: &mut Context, message: &[u8]) {
    if ctx.valid {
        ctx.data.extend_from_slice(message);
    }
}

pub fn final_bytes(ctx: &Context) -> Vec<u8> {
    if !ctx.valid {
        return Vec::new();
    }
    poly1305(&ctx.data, &ctx.key)
}

pub fn authenticate(message: &[u8], key: &[u8]) -> Vec<u8> {
    poly1305(message, key)
}

pub fn mac(message: &[u8], key: &[u8]) -> Vec<u8> {
    poly1305(message, key)
}

pub fn poly1305(message: &[u8], key: &[u8]) -> Vec<u8> {
    if key.len() != KEYBYTES {
        return Vec::new();
    }
    Poly1305::new(Key::from_slice(key))
        .compute_unpadded(message)
        .to_vec()
}
