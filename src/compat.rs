//! libsodium-compatible constants and function wrappers.
//!
//! Mirrors `keylock/compat_constants.hpp`. The constants are reproduced here
//! verbatim (as Rust `const`s) so downstream code originally written against
//! libsodium can compile against keylock with minimal churn.

use crate::crypto::{box_seal_x25519, ed25519, rng};

// Generic hash (BLAKE2b)
pub const CRYPTO_GENERICHASH_BYTES: usize = 32;
pub const CRYPTO_GENERICHASH_BYTES_MIN: usize = 16;
pub const CRYPTO_GENERICHASH_BYTES_MAX: usize = 64;
pub const CRYPTO_GENERICHASH_KEYBYTES: usize = 32;
pub const CRYPTO_GENERICHASH_KEYBYTES_MIN: usize = 16;
pub const CRYPTO_GENERICHASH_KEYBYTES_MAX: usize = 64;

// SHA-256 / SHA-512
pub const CRYPTO_HASH_SHA256_BYTES: usize = 32;
pub const CRYPTO_HASH_SHA512_BYTES: usize = 64;

// Ed25519 signatures
pub const CRYPTO_SIGN_BYTES: usize = ed25519::BYTES;
pub const CRYPTO_SIGN_PUBLICKEYBYTES: usize = ed25519::PUBLICKEYBYTES;
pub const CRYPTO_SIGN_SECRETKEYBYTES: usize = ed25519::SECRETKEYBYTES;
pub const CRYPTO_SIGN_ED25519_BYTES: usize = ed25519::BYTES;
pub const CRYPTO_SIGN_ED25519_PUBLICKEYBYTES: usize = ed25519::PUBLICKEYBYTES;
pub const CRYPTO_SIGN_ED25519_SECRETKEYBYTES: usize = ed25519::SECRETKEYBYTES;

// X25519 sealed box
pub const CRYPTO_BOX_PUBLICKEYBYTES: usize = box_seal_x25519::PUBLICKEYBYTES;
pub const CRYPTO_BOX_SECRETKEYBYTES: usize = box_seal_x25519::SECRETKEYBYTES;
pub const CRYPTO_BOX_SEALBYTES: usize = box_seal_x25519::SEALBYTES;

// Function wrappers

pub fn randombytes_buf(buf: &mut [u8]) -> Result<(), String> {
    rng::randombytes_buf(buf)
}

pub fn crypto_sign_keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    ed25519::keypair()
}

pub fn crypto_sign_ed25519_keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    ed25519::keypair()
}

pub fn crypto_sign_detached(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, String> {
    ed25519::sign_detached(message, secret_key)
}

pub fn crypto_sign_verify_detached(signature: &[u8], message: &[u8], public_key: &[u8]) -> bool {
    ed25519::verify_detached(signature, message, public_key)
}
