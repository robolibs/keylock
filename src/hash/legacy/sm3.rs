//! SM3 (GM/T 0004-2012) hash compatibility helper.
//!
//! Mirrors `keylock/hash/legacy/sm3.hpp`. Primitive delegated to the
//! RustCrypto `sm3` crate.

use sm3::{Digest, Sm3};

pub const BYTES: usize = 32;

pub fn hash(message: &[u8]) -> Vec<u8> {
    let mut hasher = Sm3::new();
    hasher.update(message);
    hasher.finalize().to_vec()
}
