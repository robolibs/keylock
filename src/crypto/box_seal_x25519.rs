//! Anonymous sealed-box (X25519 + XChaCha20-Poly1305) compatibility surface.
//!
//! Mirrors `keylock/crypto/box_seal_x25519/seal.hpp`. The wire format is
//! `ephemeral_pk (32) || ciphertext || tag (16)`, with the encryption key
//! derived as `BLAKE2b-256(shared_secret || ephemeral_pk || recipient_pk)`
//! and the nonce as `BLAKE2b-192(ephemeral_pk || recipient_pk)`. The cipher
//! is XChaCha20-Poly1305 (the C++ port chose this over the libsodium default
//! of XSalsa20-Poly1305; we keep the same choice for byte-for-byte parity).
//!
//! X25519 scalar multiplication is delegated to `x25519-dalek`.

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::Zeroize;

use crate::hash::blake2b;

pub const PUBLICKEYBYTES: usize = 32;
pub const SECRETKEYBYTES: usize = 32;
pub const SEALBYTES: usize = 48; // 32-byte ephemeral pk + 16-byte tag

pub fn keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut secret = [0u8; SECRETKEYBYTES];
    getrandom::getrandom(&mut secret).map_err(|e| e.to_string())?;
    let static_secret = StaticSecret::from(secret);
    let public = XPublic::from(&static_secret).to_bytes().to_vec();
    let secret_bytes = static_secret.to_bytes().to_vec();
    Ok((public, secret_bytes))
}

pub fn seal(message: &[u8], recipient_pk: &[u8]) -> Result<Vec<u8>, String> {
    if recipient_pk.len() != PUBLICKEYBYTES {
        return Err(format!(
            "Recipient public key must be {PUBLICKEYBYTES} bytes (got {})",
            recipient_pk.len()
        ));
    }
    let mut recipient_arr = [0u8; PUBLICKEYBYTES];
    recipient_arr.copy_from_slice(recipient_pk);

    let mut ephemeral_sk_bytes = [0u8; SECRETKEYBYTES];
    getrandom::getrandom(&mut ephemeral_sk_bytes).map_err(|e| e.to_string())?;
    let ephemeral_sk = StaticSecret::from(ephemeral_sk_bytes);
    let ephemeral_pk = XPublic::from(&ephemeral_sk).to_bytes();

    let mut shared = ephemeral_sk
        .diffie_hellman(&XPublic::from(recipient_arr))
        .to_bytes();
    let key = derive_key(&shared, &ephemeral_pk, &recipient_arr);
    let nonce = derive_nonce(&ephemeral_pk, &recipient_arr);

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| "Failed to construct XChaCha20-Poly1305 cipher".to_string())?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: message,
                aad: &[],
            },
        )
        .map_err(|_| "Sealed-box encryption failed".to_string())?;

    let mut out = Vec::with_capacity(SEALBYTES + message.len());
    out.extend_from_slice(&ephemeral_pk);
    out.extend_from_slice(&ciphertext);

    shared.zeroize();
    ephemeral_sk_bytes.zeroize();
    Ok(out)
}

pub fn seal_open(ciphertext: &[u8], recipient_pk: &[u8], recipient_sk: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.len() < SEALBYTES {
        return Err("Sealed-box ciphertext too short".to_string());
    }
    if recipient_pk.len() != PUBLICKEYBYTES {
        return Err(format!(
            "Recipient public key must be {PUBLICKEYBYTES} bytes (got {})",
            recipient_pk.len()
        ));
    }
    if recipient_sk.len() != SECRETKEYBYTES {
        return Err(format!(
            "Recipient secret key must be {SECRETKEYBYTES} bytes (got {})",
            recipient_sk.len()
        ));
    }

    let mut ephemeral_pk = [0u8; PUBLICKEYBYTES];
    ephemeral_pk.copy_from_slice(&ciphertext[..PUBLICKEYBYTES]);
    let mut recipient_pk_arr = [0u8; PUBLICKEYBYTES];
    recipient_pk_arr.copy_from_slice(recipient_pk);
    let mut recipient_sk_arr = [0u8; SECRETKEYBYTES];
    recipient_sk_arr.copy_from_slice(recipient_sk);

    let recipient_secret = StaticSecret::from(recipient_sk_arr);
    let mut shared = recipient_secret
        .diffie_hellman(&XPublic::from(ephemeral_pk))
        .to_bytes();
    let key = derive_key(&shared, &ephemeral_pk, &recipient_pk_arr);
    let nonce = derive_nonce(&ephemeral_pk, &recipient_pk_arr);

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| "Failed to construct XChaCha20-Poly1305 cipher".to_string())?;
    let result = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext[PUBLICKEYBYTES..],
                aad: &[],
            },
        )
        .map_err(|_| "Sealed-box decryption failed".to_string());

    shared.zeroize();
    recipient_sk_arr.zeroize();
    result
}

fn derive_key(shared: &[u8; 32], ephemeral_pk: &[u8; 32], recipient_pk: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 96];
    input[..32].copy_from_slice(shared);
    input[32..64].copy_from_slice(ephemeral_pk);
    input[64..].copy_from_slice(recipient_pk);
    let mut out = [0u8; 32];
    let hashed = blake2b::hash(&input, 32).expect("BLAKE2b-256 output size is valid");
    out.copy_from_slice(&hashed);
    input.zeroize();
    out
}

fn derive_nonce(ephemeral_pk: &[u8; 32], recipient_pk: &[u8; 32]) -> [u8; 24] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(ephemeral_pk);
    input[32..].copy_from_slice(recipient_pk);
    let mut out = [0u8; 24];
    let hashed = blake2b::hash(&input, 24).expect("BLAKE2b-192 output size is valid");
    out.copy_from_slice(&hashed);
    out
}
