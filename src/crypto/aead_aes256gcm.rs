//! AES-256-GCM compatibility surface.
//!
//! The C++ keylock tree keeps AES-GCM under its own crypto namespace; this Rust
//! module keeps that shape and lets the `aes-gcm` crate own the primitive.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadInPlace, KeyInit, Payload},
};

use super::{common, context::CryptoResult};

pub const KEYBYTES: usize = 32;
pub const NPUBBYTES: usize = 12;
pub const ABYTES: usize = 16;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DetachedResult {
    pub success: bool,
    pub ciphertext: Vec<u8>,
    pub mac: Vec<u8>,
    pub error: String,
}

impl DetachedResult {
    pub fn ok(ciphertext: Vec<u8>, mac: Vec<u8>) -> Self {
        Self {
            success: true,
            ciphertext,
            mac,
            error: String::new(),
        }
    }

    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            success: false,
            ciphertext: Vec::new(),
            mac: Vec::new(),
            error: message.into(),
        }
    }
}

pub fn is_available() -> bool {
    true
}

pub fn encrypt(plaintext: &[u8], key: &[u8], associated_data: &[u8]) -> CryptoResult {
    let key = common::normalize_key(key, KEYBYTES);
    let nonce = match common::random_nonce::<NPUBBYTES>() {
        Ok(nonce) => nonce,
        Err(err) => return CryptoResult::failure(err),
    };
    let cipher = Aes256Gcm::new_from_slice(&key).expect("fixed-size AES-256 key");
    let encrypted = match cipher.encrypt(
        Nonce::from_slice(&nonce),
        Payload {
            msg: plaintext,
            aad: associated_data,
        },
    ) {
        Ok(encrypted) => encrypted,
        Err(_) => return CryptoResult::failure("AEAD encryption failed"),
    };

    let mut out = Vec::with_capacity(NPUBBYTES + encrypted.len());
    out.extend(nonce);
    out.extend(encrypted);
    CryptoResult::ok(out)
}

pub fn decrypt(ciphertext_with_nonce: &[u8], key: &[u8], associated_data: &[u8]) -> CryptoResult {
    if ciphertext_with_nonce.len() < NPUBBYTES + ABYTES {
        return CryptoResult::failure("Ciphertext too short");
    }

    let key = common::normalize_key(key, KEYBYTES);
    let (nonce, ciphertext) = ciphertext_with_nonce.split_at(NPUBBYTES);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("fixed-size AES-256 key");
    match cipher.decrypt(
        Nonce::from_slice(nonce),
        Payload {
            msg: ciphertext,
            aad: associated_data,
        },
    ) {
        Ok(plaintext) => CryptoResult::ok(plaintext),
        Err(_) => CryptoResult::failure("Authentication failed"),
    }
}

pub fn encrypt_with_nonce(
    plaintext: &[u8],
    key: &[u8],
    associated_data: &[u8],
    nonce: &[u8],
) -> CryptoResult {
    if nonce.len() != NPUBBYTES {
        return CryptoResult::failure("Invalid nonce length");
    }
    let key = common::normalize_key(key, KEYBYTES);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("fixed-size AES-256 key");
    match cipher.encrypt(
        Nonce::from_slice(nonce),
        Payload {
            msg: plaintext,
            aad: associated_data,
        },
    ) {
        Ok(encrypted) => CryptoResult::ok(encrypted),
        Err(_) => CryptoResult::failure("AEAD encryption failed"),
    }
}

pub fn decrypt_with_nonce(
    ciphertext_with_tag: &[u8],
    key: &[u8],
    associated_data: &[u8],
    nonce: &[u8],
) -> CryptoResult {
    if nonce.len() != NPUBBYTES {
        return CryptoResult::failure("Invalid nonce length");
    }
    if ciphertext_with_tag.len() < ABYTES {
        return CryptoResult::failure("Ciphertext too short");
    }
    let key = common::normalize_key(key, KEYBYTES);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("fixed-size AES-256 key");
    match cipher.decrypt(
        Nonce::from_slice(nonce),
        Payload {
            msg: ciphertext_with_tag,
            aad: associated_data,
        },
    ) {
        Ok(plaintext) => CryptoResult::ok(plaintext),
        Err(_) => CryptoResult::failure("Authentication failed"),
    }
}

pub fn encrypt_detached(
    plaintext: &[u8],
    key: &[u8],
    associated_data: &[u8],
    nonce: &[u8],
) -> DetachedResult {
    if nonce.len() != NPUBBYTES {
        return DetachedResult::failure("Invalid nonce length");
    }
    let key = common::normalize_key(key, KEYBYTES);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("fixed-size AES-256 key");
    let mut ciphertext = plaintext.to_vec();
    match cipher.encrypt_in_place_detached(
        Nonce::from_slice(nonce),
        associated_data,
        &mut ciphertext,
    ) {
        Ok(mac) => DetachedResult::ok(ciphertext, mac.to_vec()),
        Err(_) => DetachedResult::failure("AEAD encryption failed"),
    }
}

pub fn decrypt_detached(
    ciphertext: &[u8],
    mac: &[u8],
    key: &[u8],
    associated_data: &[u8],
    nonce: &[u8],
) -> CryptoResult {
    if nonce.len() != NPUBBYTES {
        return CryptoResult::failure("Invalid nonce length");
    }
    if mac.len() != ABYTES {
        return CryptoResult::failure("Invalid MAC length");
    }
    let key = common::normalize_key(key, KEYBYTES);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("fixed-size AES-256 key");
    let mut plaintext = ciphertext.to_vec();
    match cipher.decrypt_in_place_detached(
        Nonce::from_slice(nonce),
        associated_data,
        &mut plaintext,
        aes_gcm::Tag::from_slice(mac),
    ) {
        Ok(()) => CryptoResult::ok(plaintext),
        Err(_) => CryptoResult::failure("Authentication failed"),
    }
}
