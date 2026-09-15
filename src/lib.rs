#![allow(clippy::collapsible_if, clippy::manual_is_multiple_of)]

pub mod compat;
pub mod crypto;
pub mod ffi;
pub mod hash;
pub mod kdf;

#[cfg(feature = "python")]
pub mod python;

#[allow(non_camel_case_types)]
pub type keylock = crypto::Context;
pub type CryptoResult = crypto::CryptoResult;
pub type KeyPair = crypto::KeyPair;
pub type Algorithm = crypto::Algorithm;
pub type HashAlgorithm = hash::HashAlgorithm;
pub type KeyType = crypto::KeyType;
pub type KeyFormat = crypto::KeyFormat;

/// Ergonomic top-level keypair generation helpers. Each delegates to
/// [`crypto::Context::generate_keypair`] for the matching [`Algorithm`].
pub fn generate_ed25519_keypair() -> Result<KeyPair, String> {
    crypto::Context::new(crypto::Algorithm::Ed25519).generate_keypair()
}

pub fn generate_ecdsa_p256_keypair() -> Result<KeyPair, String> {
    crypto::Context::new(crypto::Algorithm::EcdsaP256Sha256).generate_keypair()
}

pub fn generate_ecdsa_p384_keypair() -> Result<KeyPair, String> {
    crypto::Context::new(crypto::Algorithm::EcdsaP384Sha384).generate_keypair()
}

pub fn generate_ecdsa_p521_keypair() -> Result<KeyPair, String> {
    crypto::Context::new(crypto::Algorithm::EcdsaP521Sha512).generate_keypair()
}

pub fn generate_ecdsa_secp256k1_keypair() -> Result<KeyPair, String> {
    crypto::Context::new(crypto::Algorithm::EcdsaSecp256k1Compact).generate_keypair()
}

pub fn generate_ed448_keypair() -> Result<KeyPair, String> {
    crypto::Context::new(crypto::Algorithm::Ed448).generate_keypair()
}

pub fn generate_x25519_keypair() -> Result<KeyPair, String> {
    crypto::Context::new(crypto::Algorithm::X25519Box).generate_keypair()
}

/// 2048-bit RSA keypair using `Algorithm::RsaPkcs1v15Sha256` as the
/// representative variant (all RSA `Algorithm` variants share the same
/// `generate_keypair` path).
pub fn generate_rsa_keypair() -> Result<KeyPair, String> {
    generate_rsa_keypair_with_bits(2048)
}

/// RSA keypair with a caller-chosen bit length.
pub fn generate_rsa_keypair_with_bits(bits: usize) -> Result<KeyPair, String> {
    let (public_key, private_key) = crypto::rsa::generate_keypair_with_bits(bits)?;
    Ok(KeyPair {
        public_key,
        private_key,
        algorithm: crypto::Algorithm::RsaPkcs1v15Sha256,
    })
}

/// Keccak-256 convenience helper. Returns a fixed-size 32-byte digest;
/// `keylock::hash::keccak::hash_256` is the underlying `Vec<u8>` variant.
pub fn keccak256(message: &[u8]) -> [u8; 32] {
    let digest = hash::keccak::hash_256(message);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
