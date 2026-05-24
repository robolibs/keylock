//! Shared helpers for the keylock crypto compatibility namespace.
//!
//! Keep the C++ helper placement visible, but route hashing/randomness through
//! the existing Rust crate ecosystem paths.

use crate::hash::{self, HashAlgorithm};

pub fn normalize_key(key: &[u8], required: usize) -> Vec<u8> {
    if key.len() == required {
        return key.to_vec();
    }

    let mut normalized = hash::digest(HashAlgorithm::Blake2b, key).data;
    normalized.resize(required, 0);
    normalized.truncate(required);
    normalized
}

pub fn random_nonce<const N: usize>() -> Result<[u8; N], String> {
    let mut nonce = [0u8; N];
    getrandom::getrandom(&mut nonce).map_err(|err| err.to_string())?;
    Ok(nonce)
}
