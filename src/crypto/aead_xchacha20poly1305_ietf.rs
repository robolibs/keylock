//! XChaCha20-Poly1305-IETF compatibility surface.
//!
//! The C++ keylock header has this as a dedicated crypto namespace; the Rust
//! port keeps that module boundary and delegates the primitive to RustCrypto.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadInPlace, KeyInit, Payload},
};

use super::{common, context::CryptoResult};

pub const KEYBYTES: usize = 32;
pub const NPUBBYTES: usize = 24;
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

pub fn encrypt(plaintext: &[u8], key: &[u8], associated_data: &[u8]) -> CryptoResult {
    let key = common::normalize_key(key, KEYBYTES);
    let nonce = match common::random_nonce::<NPUBBYTES>() {
        Ok(nonce) => nonce,
        Err(err) => return CryptoResult::failure(err),
    };
    let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("fixed-size XChaCha20 key");
    let encrypted = match cipher.encrypt(
        XNonce::from_slice(&nonce),
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
    let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("fixed-size XChaCha20 key");
    match cipher.decrypt(
        XNonce::from_slice(nonce),
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
    let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("fixed-size XChaCha20 key");
    match cipher.encrypt(
        XNonce::from_slice(nonce),
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
    let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("fixed-size XChaCha20 key");
    match cipher.decrypt(
        XNonce::from_slice(nonce),
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
    let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("fixed-size XChaCha20 key");
    let mut ciphertext = plaintext.to_vec();
    match cipher.encrypt_in_place_detached(
        XNonce::from_slice(nonce),
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
    let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("fixed-size XChaCha20 key");
    let mut plaintext = ciphertext.to_vec();
    match cipher.decrypt_in_place_detached(
        XNonce::from_slice(nonce),
        associated_data,
        &mut plaintext,
        chacha20poly1305::Tag::from_slice(mac),
    ) {
        Ok(()) => CryptoResult::ok(plaintext),
        Err(_) => CryptoResult::failure("Authentication failed"),
    }
}
