pub mod compat;
pub mod crypto;
pub mod hash;
pub mod kdf;

#[allow(non_camel_case_types)]
pub type keylock = crypto::Context;
pub type CryptoResult = crypto::CryptoResult;
pub type KeyPair = crypto::KeyPair;
pub type Algorithm = crypto::Algorithm;
pub type HashAlgorithm = hash::HashAlgorithm;
pub type KeyType = crypto::KeyType;
pub type KeyFormat = crypto::KeyFormat;
