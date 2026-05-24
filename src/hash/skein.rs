//! Skein-512 hash compatibility helper.
//!
//! Mirrors `keylock/hash/skein/skein.hpp`. The primitive is delegated to the
//! RustCrypto `skein` crate.

use skein::{
    Skein512,
    consts::{U32, U64},
    digest::Digest,
};

pub const BYTES_256: usize = 32;
pub const BYTES_512: usize = 64;

pub fn hash_256(message: &[u8]) -> Vec<u8> {
    let mut hasher = Skein512::<U32>::new();
    Digest::update(&mut hasher, message);
    hasher.finalize().to_vec()
}

pub fn hash_512(message: &[u8]) -> Vec<u8> {
    let mut hasher = Skein512::<U64>::new();
    Digest::update(&mut hasher, message);
    hasher.finalize().to_vec()
}
