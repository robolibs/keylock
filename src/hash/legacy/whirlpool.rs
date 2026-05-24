//! Whirlpool hash compatibility helper.
//!
//! Mirrors `keylock/hash/legacy/whirlpool.hpp`. Primitive delegated to the
//! RustCrypto `whirlpool` crate.

use whirlpool::{Digest, Whirlpool};

pub const BYTES: usize = 64;

pub fn hash(message: &[u8]) -> Vec<u8> {
    let mut hasher = Whirlpool::new();
    hasher.update(message);
    hasher.finalize().to_vec()
}
