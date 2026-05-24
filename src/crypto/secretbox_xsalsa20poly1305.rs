//! SecretBox XSalsa20-Poly1305 compatibility surface.
//!
//! This keeps the keylock namespace split, but uses the Rust crate instead of
//! copying the C++ crypto implementation into the Rust port.

use crypto_secretbox::{
    Nonce as XSalsa20Nonce, XSalsa20Poly1305,
    aead::{Aead, KeyInit},
};

use super::{common, context::CryptoResult};

pub const KEYBYTES: usize = 32;
pub const NONCEBYTES: usize = 24;
pub const MACBYTES: usize = 16;

pub fn encrypt(plaintext: &[u8], key: &[u8]) -> CryptoResult {
    let key = common::normalize_key(key, KEYBYTES);
    let nonce = match common::random_nonce::<NONCEBYTES>() {
        Ok(nonce) => nonce,
        Err(err) => return CryptoResult::failure(err),
    };

    let cipher = XSalsa20Poly1305::new_from_slice(&key).expect("fixed-size secretbox key");
    let encrypted = match cipher.encrypt(XSalsa20Nonce::from_slice(&nonce), plaintext) {
        Ok(encrypted) => encrypted,
        Err(_) => return CryptoResult::failure("SecretBox encryption failed"),
    };
    let (ciphertext, tag) = encrypted.split_at(encrypted.len() - MACBYTES);
    let mut out = Vec::with_capacity(NONCEBYTES + encrypted.len());
    out.extend(nonce);
    out.extend(tag);
    out.extend(ciphertext);
    CryptoResult::ok(out)
}

pub fn decrypt(ciphertext_with_nonce: &[u8], key: &[u8]) -> CryptoResult {
    if ciphertext_with_nonce.len() < NONCEBYTES + MACBYTES {
        return CryptoResult::failure("Ciphertext too short");
    }

    let key = common::normalize_key(key, KEYBYTES);
    let nonce = &ciphertext_with_nonce[..NONCEBYTES];
    let boxed = &ciphertext_with_nonce[NONCEBYTES..];
    let mut encrypted = Vec::with_capacity(boxed.len());
    encrypted.extend(&boxed[MACBYTES..]);
    encrypted.extend(&boxed[..MACBYTES]);

    let cipher = XSalsa20Poly1305::new_from_slice(&key).expect("fixed-size secretbox key");
    match cipher.decrypt(XSalsa20Nonce::from_slice(nonce), encrypted.as_ref()) {
        Ok(plaintext) => CryptoResult::ok(plaintext),
        Err(_) => CryptoResult::failure("SecretBox decryption failed"),
    }
}
