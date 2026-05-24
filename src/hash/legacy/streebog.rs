//! Streebog (GOST R 34.11-2012) hash compatibility helper.
//!
//! Mirrors `keylock/hash/legacy/streebog.hpp`. Primitive delegated to the
//! RustCrypto `streebog` crate.

use streebog::{Digest, Streebog256, Streebog512};

pub const BYTES_256: usize = 32;
pub const BYTES_512: usize = 64;

pub fn hash_256(message: &[u8]) -> Vec<u8> {
    let mut hasher = Streebog256::new();
    hasher.update(message);
    hasher.finalize().to_vec()
}

pub fn hash_512(message: &[u8]) -> Vec<u8> {
    let mut hasher = Streebog512::new();
    hasher.update(message);
    hasher.finalize().to_vec()
}
