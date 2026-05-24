//! Ed25519 compatibility surface.
//!
//! Mirrors `keylock/crypto/ed25519/ed25519.hpp`. The C++ secret key layout is
//! `seed || public_key` (64 bytes total, matching libsodium); we keep the same
//! convention so callers can shuttle keys between the two implementations
//! verbatim.
//!
//! The primitive is delegated to the `ed25519-dalek` crate.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub const PUBLICKEYBYTES: usize = 32;
pub const SECRETKEYBYTES: usize = 64;
pub const SEEDBYTES: usize = 32;
pub const BYTES: usize = 64;

pub fn keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut seed = [0u8; SEEDBYTES];
    getrandom::getrandom(&mut seed).map_err(|e| e.to_string())?;
    keypair_from_seed(&seed)
}

pub fn keypair_from_seed(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if seed.len() != SEEDBYTES {
        return Err(format!(
            "Ed25519 seed must be {SEEDBYTES} bytes (got {})",
            seed.len()
        ));
    }
    let mut seed_arr = [0u8; SEEDBYTES];
    seed_arr.copy_from_slice(seed);
    let signing_key = SigningKey::from_bytes(&seed_arr);
    let public_key = signing_key.verifying_key().to_bytes().to_vec();
    let mut secret = Vec::with_capacity(SECRETKEYBYTES);
    secret.extend_from_slice(&seed_arr);
    secret.extend_from_slice(&public_key);
    Ok((public_key, secret))
}

pub fn sign_detached(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, String> {
    if secret_key.len() != SECRETKEYBYTES && secret_key.len() != SEEDBYTES {
        return Err(format!(
            "Ed25519 secret key must be {SECRETKEYBYTES} or {SEEDBYTES} bytes (got {})",
            secret_key.len()
        ));
    }
    let mut seed = [0u8; SEEDBYTES];
    seed.copy_from_slice(&secret_key[..SEEDBYTES]);
    let signing_key = SigningKey::from_bytes(&seed);
    let signature: Signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

pub fn verify_detached(signature: &[u8], message: &[u8], public_key: &[u8]) -> bool {
    if signature.len() != BYTES || public_key.len() != PUBLICKEYBYTES {
        return false;
    }
    let mut pk_arr = [0u8; PUBLICKEYBYTES];
    pk_arr.copy_from_slice(public_key);
    let verifying_key = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let mut sig_arr = [0u8; BYTES];
    sig_arr.copy_from_slice(signature);
    let sig = Signature::from_bytes(&sig_arr);
    verifying_key.verify(message, &sig).is_ok()
}

pub fn public_from_secret(secret_key: &[u8]) -> Result<Vec<u8>, String> {
    if secret_key.len() < SEEDBYTES {
        return Err("Ed25519 secret key too short".to_string());
    }
    let mut seed = [0u8; SEEDBYTES];
    seed.copy_from_slice(&secret_key[..SEEDBYTES]);
    let signing_key = SigningKey::from_bytes(&seed);
    Ok(signing_key.verifying_key().to_bytes().to_vec())
}
