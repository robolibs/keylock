//! HKDF-SHA512 compatibility helper.

use crate::hash::HashAlgorithm;

use super::{
    Result, hkdf as hkdf_with_algorithm, hkdf_expand as expand_with_algorithm, hkdf_extract,
};

pub const BYTES: usize = 64;

pub fn extract(salt: &[u8], ikm: &[u8]) -> Result {
    hkdf_extract(HashAlgorithm::Sha512, ikm, salt)
}

pub fn expand(prk: &[u8], info: &[u8], length: usize) -> Result {
    expand_with_algorithm(HashAlgorithm::Sha512, prk, info, length)
}

pub fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Result {
    hkdf_with_algorithm(HashAlgorithm::Sha512, ikm, salt, info, length)
}
