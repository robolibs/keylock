//! Compatibility namespace mirroring `keylock/hash`.
//!
//! The C++ dependency exposes hash/HMAC helpers under `keylock::hash`.  The Rust
//! port keeps that public hierarchy, but delegates HMAC internals to RustCrypto.

use sha2::{Digest as _, Sha384};

pub mod blake2b;
pub mod blake2s;
pub mod blake2x;
pub mod generichash;
pub mod hkdf;
pub mod hmac;
pub mod keccak;
pub mod kmac;
pub mod legacy;
pub mod sha256;
pub mod sha3;
pub mod sha512;
pub mod shake;
pub mod skein;

pub use hkdf::{hkdf, hkdf_expand, hkdf_extract, hkdf_sha256, hkdf_sha384, hkdf_sha512};
pub use hmac::{hmac_blake2b, hmac_sha256, hmac_sha384, hmac_sha512};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum HashAlgorithm {
    #[default]
    Sha256,
    Sha384,
    Sha512,
    Blake2b,
    Keccak256,
}

#[allow(non_upper_case_globals)]
impl HashAlgorithm {
    pub const SHA256: Self = Self::Sha256;
    pub const SHA384: Self = Self::Sha384;
    pub const SHA512: Self = Self::Sha512;
    pub const BLAKE2b: Self = Self::Blake2b;
    pub const KECCAK256: Self = Self::Keccak256;
}

pub type Algorithm = HashAlgorithm;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Result {
    pub success: bool,
    pub data: Vec<u8>,
    pub error_message: String,
}

impl Result {
    pub fn ok(data: Vec<u8>) -> Self {
        Self {
            success: true,
            data,
            error_message: String::new(),
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            data: Vec::new(),
            error_message: error.into(),
        }
    }
}

pub fn digest(algorithm: HashAlgorithm, data: &[u8]) -> Result {
    match algorithm {
        HashAlgorithm::Sha256 => Result::ok(sha256::hash(data)),
        HashAlgorithm::Sha384 => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            Result::ok(hasher.finalize().to_vec())
        }
        HashAlgorithm::Sha512 => Result::ok(sha512::hash(data)),
        HashAlgorithm::Blake2b => Result::ok(blake2b::generichash(data)),
        HashAlgorithm::Keccak256 => Result::ok(keccak::hash_256(data)),
    }
}

pub fn keccak256(data: &[u8]) -> Result {
    Result::ok(keccak::hash_256(data))
}

pub fn hmac(algorithm: HashAlgorithm, data: &[u8], key: &[u8]) -> Result {
    match algorithm {
        HashAlgorithm::Sha256 => Result::ok(hmac_sha256::hmac(key, data)),
        HashAlgorithm::Sha384 => Result::ok(hmac_sha384::hmac(key, data)),
        HashAlgorithm::Sha512 => Result::ok(hmac_sha512::hmac(key, data)),
        HashAlgorithm::Blake2b => {
            if key.is_empty() {
                Result::failure("BLAKE2b keyed hash requires non-empty key")
            } else {
                Result::ok(hmac_blake2b::keyed_32(key, data))
            }
        }
        HashAlgorithm::Keccak256 => Result::failure("HMAC not supported for KECCAK256"),
    }
}

pub mod detail {
    use crate::hash::HashAlgorithm;

    pub fn hash_output_size(algorithm: HashAlgorithm) -> usize {
        match algorithm {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
            HashAlgorithm::Blake2b | HashAlgorithm::Keccak256 => 32,
        }
    }
}
