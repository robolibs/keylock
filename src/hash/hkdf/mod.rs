//! HKDF compatibility helpers mirroring `keylock/hash/hkdf`.
//!
//! Keep the C++ namespace split, but delegate standard SHA-2 HKDF to the
//! RustCrypto `hkdf` crate instead of carrying the extract/expand loop here.

use crate::hash::HashAlgorithm;
use sha2::{Sha256, Sha384, Sha512};

use super::{Result, hmac};

pub mod hkdf_sha256;
pub mod hkdf_sha384;
pub mod hkdf_sha512;

pub fn hkdf_extract(algorithm: HashAlgorithm, ikm: &[u8], salt: &[u8]) -> Result {
    let Some(hash_len) = hash_output_size(algorithm) else {
        return Result::failure("Unsupported hash algorithm for HKDF");
    };
    if let Some(data) = hkdf_extract_with_crate(algorithm, ikm, salt) {
        return Result::ok(data);
    }

    let effective_salt = if salt.is_empty() {
        vec![0u8; hash_len]
    } else {
        salt.to_vec()
    };
    hmac(algorithm, ikm, &effective_salt)
}

pub fn hkdf_expand(algorithm: HashAlgorithm, prk: &[u8], info: &[u8], length: usize) -> Result {
    let Some(hash_len) = hash_output_size(algorithm) else {
        return Result::failure("Unsupported hash algorithm for HKDF");
    };
    if length > 255 * hash_len {
        return Result::failure("HKDF output length too large");
    }
    if prk.len() < hash_len {
        return Result::failure("PRK too short for HKDF-Expand");
    }
    if let Some(result) = hkdf_expand_with_crate(algorithm, prk, info, length) {
        return result;
    }

    let mut okm = Vec::with_capacity(length);
    let mut previous = Vec::new();
    let mut counter = 1u8;
    while okm.len() < length {
        let mut message = Vec::with_capacity(previous.len() + info.len() + 1);
        message.extend_from_slice(&previous);
        message.extend_from_slice(info);
        message.push(counter);

        let block = hmac(algorithm, &message, prk);
        if !block.success {
            return block;
        }
        previous = block.data;

        let to_copy = previous.len().min(length - okm.len());
        okm.extend_from_slice(&previous[..to_copy]);
        counter = counter.wrapping_add(1);
    }

    Result::ok(okm)
}

pub fn hkdf(
    algorithm: HashAlgorithm,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> Result {
    let prk = hkdf_extract(algorithm, ikm, salt);
    if !prk.success {
        return prk;
    }
    hkdf_expand(algorithm, &prk.data, info, length)
}

fn hkdf_extract_with_crate(algorithm: HashAlgorithm, ikm: &[u8], salt: &[u8]) -> Option<Vec<u8>> {
    match algorithm {
        HashAlgorithm::Sha256 => {
            let (prk, _) = ::hkdf::Hkdf::<Sha256>::extract(Some(salt), ikm);
            Some(prk.to_vec())
        }
        HashAlgorithm::Sha384 => {
            let (prk, _) = ::hkdf::Hkdf::<Sha384>::extract(Some(salt), ikm);
            Some(prk.to_vec())
        }
        HashAlgorithm::Sha512 => {
            let (prk, _) = ::hkdf::Hkdf::<Sha512>::extract(Some(salt), ikm);
            Some(prk.to_vec())
        }
        HashAlgorithm::Blake2b | HashAlgorithm::Keccak256 => None,
    }
}

fn hkdf_expand_with_crate(
    algorithm: HashAlgorithm,
    prk: &[u8],
    info: &[u8],
    length: usize,
) -> Option<Result> {
    match algorithm {
        HashAlgorithm::Sha256 => Some(expand_sha256(prk, info, length)),
        HashAlgorithm::Sha384 => Some(expand_sha384(prk, info, length)),
        HashAlgorithm::Sha512 => Some(expand_sha512(prk, info, length)),
        HashAlgorithm::Blake2b | HashAlgorithm::Keccak256 => None,
    }
}

fn expand_sha256(prk: &[u8], info: &[u8], length: usize) -> Result {
    let hkdf = match ::hkdf::Hkdf::<Sha256>::from_prk(prk) {
        Ok(hkdf) => hkdf,
        Err(_) => return Result::failure("PRK too short for HKDF-Expand"),
    };
    let mut okm = vec![0u8; length];
    match hkdf.expand(info, &mut okm) {
        Ok(()) => Result::ok(okm),
        Err(_) => Result::failure("HKDF output length too large"),
    }
}

fn expand_sha384(prk: &[u8], info: &[u8], length: usize) -> Result {
    let hkdf = match ::hkdf::Hkdf::<Sha384>::from_prk(prk) {
        Ok(hkdf) => hkdf,
        Err(_) => return Result::failure("PRK too short for HKDF-Expand"),
    };
    let mut okm = vec![0u8; length];
    match hkdf.expand(info, &mut okm) {
        Ok(()) => Result::ok(okm),
        Err(_) => Result::failure("HKDF output length too large"),
    }
}

fn expand_sha512(prk: &[u8], info: &[u8], length: usize) -> Result {
    let hkdf = match ::hkdf::Hkdf::<Sha512>::from_prk(prk) {
        Ok(hkdf) => hkdf,
        Err(_) => return Result::failure("PRK too short for HKDF-Expand"),
    };
    let mut okm = vec![0u8; length];
    match hkdf.expand(info, &mut okm) {
        Ok(()) => Result::ok(okm),
        Err(_) => Result::failure("HKDF output length too large"),
    }
}

fn hash_output_size(algorithm: HashAlgorithm) -> Option<usize> {
    match algorithm {
        HashAlgorithm::Sha256 => Some(32),
        HashAlgorithm::Sha384 => Some(48),
        HashAlgorithm::Sha512 => Some(64),
        HashAlgorithm::Blake2b | HashAlgorithm::Keccak256 => Some(32),
    }
}
