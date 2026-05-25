//! `keylock::crypto::Context` — the top-level dispatcher that mirrors the
//! C++ `keylock/crypto/context.hpp` API. Algorithm selection is held as
//! state; the same `encrypt` / `decrypt` / `sign` / `verify` / etc.
//! methods route to whichever primitive matches.

use std::fs;
use std::io::Write;
use std::path::Path;

use super::{
    aead_aes256gcm, aead_chacha20poly1305_ietf, aead_xchacha20poly1305_ietf, box_seal_x25519,
    ecdsa_p256, ecdsa_p384, ecdsa_p521, ed448, ed25519, rsa as ksrsa, secp256k1,
    secretbox_xsalsa20poly1305,
};
use crate::hash::{self, HashAlgorithm};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    XChaCha20Poly1305,
    ChaCha20Poly1305,
    Aes256Gcm,
    SecretBoxXSalsa20,
    X25519Box,
    Ed25519,
    RsaPkcs1v15Sha256,
    RsaPssSha256,
    RsaPkcs1v15Sha384,
    RsaPssSha384,
    RsaPkcs1v15Sha512,
    RsaPssSha512,
    RsaOaepSha256,
    RsaOaepSha384,
    RsaOaepSha512,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    EcdsaP521Sha512,
    EcdsaSecp256k1Compact,
    Ed448,
}

#[allow(non_upper_case_globals)]
impl Algorithm {
    pub const XChaCha20_Poly1305: Self = Self::XChaCha20Poly1305;
    pub const ChaCha20_Poly1305: Self = Self::ChaCha20Poly1305;
    pub const AES256_GCM: Self = Self::Aes256Gcm;
    pub const SecretBox_XSalsa20: Self = Self::SecretBoxXSalsa20;
    pub const X25519_Box: Self = Self::X25519Box;
    pub const RSA_PKCS1v15_SHA256: Self = Self::RsaPkcs1v15Sha256;
    pub const RSA_PSS_SHA256: Self = Self::RsaPssSha256;
    pub const RSA_PKCS1v15_SHA384: Self = Self::RsaPkcs1v15Sha384;
    pub const RSA_PSS_SHA384: Self = Self::RsaPssSha384;
    pub const RSA_PKCS1v15_SHA512: Self = Self::RsaPkcs1v15Sha512;
    pub const RSA_PSS_SHA512: Self = Self::RsaPssSha512;
    pub const RSA_OAEP_SHA256: Self = Self::RsaOaepSha256;
    pub const RSA_OAEP_SHA384: Self = Self::RsaOaepSha384;
    pub const RSA_OAEP_SHA512: Self = Self::RsaOaepSha512;
    pub const ECDSA_P256_SHA256: Self = Self::EcdsaP256Sha256;
    pub const ECDSA_P384_SHA384: Self = Self::EcdsaP384Sha384;
    pub const ECDSA_P521_SHA512: Self = Self::EcdsaP521Sha512;
    pub const ECDSA_SECP256K1_COMPACT: Self = Self::EcdsaSecp256k1Compact;
    pub const ED448: Self = Self::Ed448;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyType {
    Public,
    Private,
}

#[allow(non_upper_case_globals)]
impl KeyType {
    pub const PUBLIC: Self = Self::Public;
    pub const PRIVATE: Self = Self::Private;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum KeyFormat {
    #[default]
    Raw,
    Pem,
    Der,
}

#[allow(non_upper_case_globals)]
impl KeyFormat {
    pub const RAW: Self = Self::Raw;
    pub const PEM: Self = Self::Pem;
    pub const DER: Self = Self::Der;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CryptoResult {
    pub success: bool,
    pub data: Vec<u8>,
    pub error_message: String,
}

impl CryptoResult {
    pub fn ok(data: Vec<u8>) -> Self {
        Self {
            success: true,
            data,
            error_message: String::new(),
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            data: Vec::new(),
            error_message: error.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub algorithm: Algorithm,
}

impl Default for KeyPair {
    fn default() -> Self {
        Self {
            public_key: Vec::new(),
            private_key: Vec::new(),
            algorithm: Algorithm::XChaCha20Poly1305,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Context {
    current_algorithm: Algorithm,
    current_hash: HashAlgorithm,
}

impl Default for Context {
    fn default() -> Self {
        Self::new(Algorithm::XChaCha20Poly1305)
    }
}

impl Context {
    pub fn new(algorithm: Algorithm) -> Self {
        Self {
            current_algorithm: algorithm,
            current_hash: HashAlgorithm::Sha256,
        }
    }

    pub fn with_hash_algorithm(algorithm: Algorithm, hash_algorithm: HashAlgorithm) -> Self {
        Self {
            current_algorithm: algorithm,
            current_hash: hash_algorithm,
        }
    }

    pub fn set_algorithm(&mut self, algorithm: Algorithm) {
        self.current_algorithm = algorithm;
    }

    pub fn set_hash_algorithm(&mut self, hash_algorithm: HashAlgorithm) {
        self.current_hash = hash_algorithm;
    }

    pub fn get_algorithm(&self) -> Algorithm {
        self.current_algorithm
    }

    pub fn get_hash_algorithm(&self) -> HashAlgorithm {
        self.current_hash
    }

    // ---------- symmetric ----------

    pub fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> CryptoResult {
        self.encrypt_with_aad(plaintext, key, &[])
    }

    pub fn encrypt_with_aad(
        &self,
        plaintext: &[u8],
        key: &[u8],
        associated_data: &[u8],
    ) -> CryptoResult {
        match self.current_algorithm {
            Algorithm::XChaCha20Poly1305 => {
                aead_xchacha20poly1305_ietf::encrypt(plaintext, key, associated_data)
            }
            Algorithm::ChaCha20Poly1305 => {
                aead_chacha20poly1305_ietf::encrypt(plaintext, key, associated_data)
            }
            Algorithm::Aes256Gcm => aead_aes256gcm::encrypt(plaintext, key, associated_data),
            Algorithm::SecretBoxXSalsa20 => secretbox_xsalsa20poly1305::encrypt(plaintext, key),
            _ => {
                CryptoResult::failure("Current algorithm is not suitable for symmetric encryption")
            }
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> CryptoResult {
        self.decrypt_with_aad(ciphertext, key, &[])
    }

    pub fn decrypt_with_aad(
        &self,
        ciphertext: &[u8],
        key: &[u8],
        associated_data: &[u8],
    ) -> CryptoResult {
        match self.current_algorithm {
            Algorithm::XChaCha20Poly1305 => {
                aead_xchacha20poly1305_ietf::decrypt(ciphertext, key, associated_data)
            }
            Algorithm::ChaCha20Poly1305 => {
                aead_chacha20poly1305_ietf::decrypt(ciphertext, key, associated_data)
            }
            Algorithm::Aes256Gcm => aead_aes256gcm::decrypt(ciphertext, key, associated_data),
            Algorithm::SecretBoxXSalsa20 => secretbox_xsalsa20poly1305::decrypt(ciphertext, key),
            _ => {
                CryptoResult::failure("Current algorithm is not suitable for symmetric decryption")
            }
        }
    }

    // ---------- asymmetric encryption ----------

    pub fn encrypt_asymmetric(&self, plaintext: &[u8], public_key: &[u8]) -> CryptoResult {
        match self.current_algorithm {
            Algorithm::X25519Box => match box_seal_x25519::seal(plaintext, public_key) {
                Ok(ct) => CryptoResult::ok(ct),
                Err(e) => CryptoResult::failure(e),
            },
            Algorithm::RsaOaepSha256 | Algorithm::RsaOaepSha384 | Algorithm::RsaOaepSha512 => {
                match ksrsa::encrypt_oaep(
                    plaintext,
                    public_key,
                    rsa_hash_from_algorithm(self.current_algorithm),
                ) {
                    Ok(ct) => CryptoResult::ok(ct),
                    Err(e) => CryptoResult::failure(e),
                }
            }
            _ => CryptoResult::failure("Current algorithm does not support asymmetric encryption"),
        }
    }

    pub fn decrypt_asymmetric(&self, ciphertext: &[u8], private_key: &[u8]) -> CryptoResult {
        match self.current_algorithm {
            Algorithm::X25519Box => {
                if private_key.len()
                    != box_seal_x25519::PUBLICKEYBYTES + box_seal_x25519::SECRETKEYBYTES
                {
                    return CryptoResult::failure("Invalid X25519 private key material");
                }
                let pub_part = &private_key[..box_seal_x25519::PUBLICKEYBYTES];
                let sec_part = &private_key[box_seal_x25519::PUBLICKEYBYTES..];
                match box_seal_x25519::seal_open(ciphertext, pub_part, sec_part) {
                    Ok(pt) => CryptoResult::ok(pt),
                    Err(e) => CryptoResult::failure(e),
                }
            }
            Algorithm::RsaOaepSha256 | Algorithm::RsaOaepSha384 | Algorithm::RsaOaepSha512 => {
                match ksrsa::decrypt_oaep(
                    ciphertext,
                    private_key,
                    rsa_hash_from_algorithm(self.current_algorithm),
                ) {
                    Ok(pt) => CryptoResult::ok(pt),
                    Err(e) => CryptoResult::failure(e),
                }
            }
            _ => CryptoResult::failure("Current algorithm does not support asymmetric decryption"),
        }
    }

    // ---------- sign / verify ----------

    pub fn sign(&self, data: &[u8], private_key: &[u8]) -> CryptoResult {
        match self.current_algorithm {
            Algorithm::Ed25519 => match ed25519::sign_detached(data, private_key) {
                Ok(sig) => CryptoResult::ok(sig),
                Err(e) => CryptoResult::failure(e),
            },
            Algorithm::EcdsaP256Sha256 => match ecdsa_p256::sign_detached(data, private_key) {
                Ok(sig) => CryptoResult::ok(sig),
                Err(e) => CryptoResult::failure(e),
            },
            Algorithm::EcdsaSecp256k1Compact => secp256k1::sign(data, private_key),
            Algorithm::RsaPkcs1v15Sha256
            | Algorithm::RsaPkcs1v15Sha384
            | Algorithm::RsaPkcs1v15Sha512 => match ksrsa::sign_pkcs1v15(
                data,
                private_key,
                rsa_hash_from_algorithm(self.current_algorithm),
            ) {
                Ok(sig) => CryptoResult::ok(sig),
                Err(e) => CryptoResult::failure(e),
            },
            Algorithm::RsaPssSha256 | Algorithm::RsaPssSha384 | Algorithm::RsaPssSha512 => {
                match ksrsa::sign_pss(
                    data,
                    private_key,
                    rsa_hash_from_algorithm(self.current_algorithm),
                ) {
                    Ok(sig) => CryptoResult::ok(sig),
                    Err(e) => CryptoResult::failure(e),
                }
            }
            _ => CryptoResult::failure("Current algorithm does not support signing"),
        }
    }

    pub fn verify(&self, data: &[u8], signature: &[u8], public_key: &[u8]) -> CryptoResult {
        match self.current_algorithm {
            Algorithm::Ed25519 => {
                if ed25519::verify_detached(signature, data, public_key) {
                    CryptoResult::ok(Vec::new())
                } else {
                    CryptoResult::failure("Ed25519 signature verification failed")
                }
            }
            Algorithm::EcdsaP256Sha256 => {
                match ecdsa_p256::verify_detached(data, signature, public_key) {
                    Ok(true) => CryptoResult::ok(Vec::new()),
                    Ok(false) => CryptoResult::failure("ECDSA P-256 signature verification failed"),
                    Err(e) => CryptoResult::failure(e),
                }
            }
            Algorithm::EcdsaSecp256k1Compact => secp256k1::verify(data, signature, public_key),
            Algorithm::RsaPkcs1v15Sha256
            | Algorithm::RsaPkcs1v15Sha384
            | Algorithm::RsaPkcs1v15Sha512 => match ksrsa::verify_pkcs1v15(
                data,
                signature,
                public_key,
                rsa_hash_from_algorithm(self.current_algorithm),
            ) {
                Ok(true) => CryptoResult::ok(Vec::new()),
                Ok(false) => CryptoResult::failure("RSA PKCS1v15 signature verification failed"),
                Err(e) => CryptoResult::failure(e),
            },
            Algorithm::RsaPssSha256 | Algorithm::RsaPssSha384 | Algorithm::RsaPssSha512 => {
                match ksrsa::verify_pss(
                    data,
                    signature,
                    public_key,
                    rsa_hash_from_algorithm(self.current_algorithm),
                ) {
                    Ok(true) => CryptoResult::ok(Vec::new()),
                    Ok(false) => CryptoResult::failure("RSA PSS signature verification failed"),
                    Err(e) => CryptoResult::failure(e),
                }
            }
            _ => CryptoResult::failure("Current algorithm does not support verification"),
        }
    }

    // ---------- key generation ----------

    pub fn generate_keypair(&self) -> Result<KeyPair, String> {
        match self.current_algorithm {
            Algorithm::X25519Box => {
                let (public, private) = box_seal_x25519::keypair()?;
                let mut combined = public.clone();
                combined.extend_from_slice(&private);
                Ok(KeyPair {
                    public_key: public,
                    private_key: combined,
                    algorithm: self.current_algorithm,
                })
            }
            Algorithm::Ed25519 => {
                let (public, private) = ed25519::keypair()?;
                Ok(KeyPair {
                    public_key: public,
                    private_key: private,
                    algorithm: self.current_algorithm,
                })
            }
            Algorithm::EcdsaP256Sha256 => {
                let (public, private) = ecdsa_p256::keypair()?;
                Ok(KeyPair {
                    public_key: public,
                    private_key: private,
                    algorithm: self.current_algorithm,
                })
            }
            Algorithm::EcdsaP384Sha384 => {
                let (public, private) = ecdsa_p384::keypair()?;
                Ok(KeyPair {
                    public_key: public,
                    private_key: private,
                    algorithm: self.current_algorithm,
                })
            }
            Algorithm::EcdsaP521Sha512 => {
                let (public, private) = ecdsa_p521::keypair()?;
                Ok(KeyPair {
                    public_key: public,
                    private_key: private,
                    algorithm: self.current_algorithm,
                })
            }
            Algorithm::Ed448 => {
                let (public, private) = ed448::keypair()?;
                Ok(KeyPair {
                    public_key: public,
                    private_key: private,
                    algorithm: self.current_algorithm,
                })
            }
            Algorithm::EcdsaSecp256k1Compact => secp256k1::generate_keypair(),
            Algorithm::RsaPkcs1v15Sha256
            | Algorithm::RsaPssSha256
            | Algorithm::RsaPkcs1v15Sha384
            | Algorithm::RsaPssSha384
            | Algorithm::RsaPkcs1v15Sha512
            | Algorithm::RsaPssSha512
            | Algorithm::RsaOaepSha256
            | Algorithm::RsaOaepSha384
            | Algorithm::RsaOaepSha512 => {
                let (public, private) = ksrsa::generate_keypair()?;
                Ok(KeyPair {
                    public_key: public,
                    private_key: private,
                    algorithm: self.current_algorithm,
                })
            }
            _ => Err("Key generation not supported for this algorithm".to_string()),
        }
    }

    pub fn generate_symmetric_key(&self, key_size: usize) -> CryptoResult {
        let mut key = vec![0u8; key_size];
        match getrandom::getrandom(&mut key) {
            Ok(()) => CryptoResult::ok(key),
            Err(e) => CryptoResult::failure(e.to_string()),
        }
    }

    // ---------- hash / hmac ----------

    pub fn digest(&self, data: &[u8]) -> CryptoResult {
        let result = hash::digest(self.current_hash, data);
        if result.success {
            CryptoResult::ok(result.data)
        } else {
            CryptoResult::failure(result.error_message)
        }
    }

    pub fn hash(&self, data: &[u8]) -> CryptoResult {
        self.digest(data)
    }

    pub fn hmac(&self, data: &[u8], key: &[u8]) -> CryptoResult {
        let result = hash::hmac(self.current_hash, data, key);
        if result.success {
            CryptoResult::ok(result.data)
        } else {
            CryptoResult::failure(result.error_message)
        }
    }

    // ---------- file I/O ----------

    pub fn save_key_to_file(
        &self,
        key: &[u8],
        filename: impl AsRef<Path>,
        key_type: KeyType,
        format: KeyFormat,
    ) -> bool {
        let bytes = match format {
            KeyFormat::Raw => key.to_vec(),
            KeyFormat::Der => match self.key_to_der(key, key_type) {
                Some(der) => der,
                None => return false,
            },
            KeyFormat::Pem => match self.key_to_der(key, key_type) {
                Some(der) => der_to_pem(&der, pem_label(self.current_algorithm, key_type)),
                None => return false,
            },
        };
        match fs::File::create(filename.as_ref()) {
            Ok(mut file) => file.write_all(&bytes).is_ok(),
            Err(_) => false,
        }
    }

    pub fn load_key_from_file(
        &self,
        filename: impl AsRef<Path>,
        key_type: KeyType,
    ) -> CryptoResult {
        let data = match fs::read(filename.as_ref()) {
            Ok(d) => d,
            Err(e) => return CryptoResult::failure(e.to_string()),
        };
        if data.is_empty() {
            return CryptoResult::failure("File empty");
        }
        // Detect format heuristically: PEM starts with `-----BEGIN`, raw is the
        // expected key size for this algorithm; everything else is treated as
        // DER.
        let raw = if data.starts_with(b"-----BEGIN") {
            match pem_to_der(&data) {
                Some(der) => match self.der_to_key(&der, key_type) {
                    Some(k) => k,
                    None => return CryptoResult::failure("Failed to decode PEM key"),
                },
                None => return CryptoResult::failure("Malformed PEM"),
            }
        } else if let Some(expected) = self.expected_key_size(key_type) {
            if data.len() == expected {
                data.clone()
            } else {
                // not the right raw size — try DER
                match self.der_to_key(&data, key_type) {
                    Some(k) => k,
                    None => return CryptoResult::failure("Unexpected key size"),
                }
            }
        } else {
            // No fixed raw size (RSA): try DER, fall back to raw.
            self.der_to_key(&data, key_type).unwrap_or(data.clone())
        };
        if let Some(expected) = self.expected_key_size(key_type) {
            if raw.len() != expected {
                return CryptoResult::failure("Unexpected key size");
            }
        }
        CryptoResult::ok(raw)
    }

    fn key_to_der(&self, key: &[u8], key_type: KeyType) -> Option<Vec<u8>> {
        match (self.current_algorithm, key_type) {
            (Algorithm::Ed25519, KeyType::Public) => {
                let r = Self::encode_ed25519_public_key_spki_der(key);
                r.success.then_some(r.data)
            }
            (Algorithm::Ed25519, KeyType::Private) => {
                let r = Self::encode_ed25519_private_key_pkcs8_der(key);
                r.success.then_some(r.data)
            }
            (Algorithm::EcdsaP256Sha256, KeyType::Public) if key.len() == 64 => {
                let (x, y) = key.split_at(32);
                let r = Self::encode_ecdsa_p256_public_key_spki_der(x, y);
                r.success.then_some(r.data)
            }
            (Algorithm::EcdsaP256Sha256, KeyType::Private) => {
                let r = Self::encode_ecdsa_p256_private_key_pkcs8_der(key);
                r.success.then_some(r.data)
            }
            (Algorithm::RsaPkcs1v15Sha256, KeyType::Public)
            | (Algorithm::RsaPssSha256, KeyType::Public)
            | (Algorithm::RsaPkcs1v15Sha384, KeyType::Public)
            | (Algorithm::RsaPssSha384, KeyType::Public)
            | (Algorithm::RsaPkcs1v15Sha512, KeyType::Public)
            | (Algorithm::RsaPssSha512, KeyType::Public)
            | (Algorithm::RsaOaepSha256, KeyType::Public)
            | (Algorithm::RsaOaepSha384, KeyType::Public)
            | (Algorithm::RsaOaepSha512, KeyType::Public) => {
                ksrsa::public_blob_to_pkcs1_der(key).ok()
            }
            (Algorithm::RsaPkcs1v15Sha256, KeyType::Private)
            | (Algorithm::RsaPssSha256, KeyType::Private)
            | (Algorithm::RsaPkcs1v15Sha384, KeyType::Private)
            | (Algorithm::RsaPssSha384, KeyType::Private)
            | (Algorithm::RsaPkcs1v15Sha512, KeyType::Private)
            | (Algorithm::RsaPssSha512, KeyType::Private)
            | (Algorithm::RsaOaepSha256, KeyType::Private)
            | (Algorithm::RsaOaepSha384, KeyType::Private)
            | (Algorithm::RsaOaepSha512, KeyType::Private) => {
                ksrsa::private_blob_to_pkcs1_der(key).ok()
            }
            _ => None,
        }
    }

    fn der_to_key(&self, der: &[u8], key_type: KeyType) -> Option<Vec<u8>> {
        match (self.current_algorithm, key_type) {
            (Algorithm::Ed25519, KeyType::Public) => {
                let r = Self::decode_ed25519_public_key_spki_der(der);
                r.success.then_some(r.data)
            }
            (Algorithm::Ed25519, KeyType::Private) => {
                let r = Self::decode_ed25519_private_key_pkcs8_der(der);
                if !r.success {
                    return None;
                }
                // Expand 32-byte seed to 64-byte secret (seed‖pub).
                let (_, secret) = ed25519::keypair_from_seed(&r.data).ok()?;
                Some(secret)
            }
            (Algorithm::EcdsaP256Sha256, KeyType::Public) => {
                let r = Self::decode_ecdsa_p256_public_key_spki_der(der);
                r.success.then_some(r.data)
            }
            (Algorithm::EcdsaP256Sha256, KeyType::Private) => {
                let r = Self::decode_ecdsa_p256_private_key_pkcs8_der(der);
                r.success.then_some(r.data)
            }
            (Algorithm::RsaPkcs1v15Sha256, KeyType::Public)
            | (Algorithm::RsaPssSha256, KeyType::Public)
            | (Algorithm::RsaPkcs1v15Sha384, KeyType::Public)
            | (Algorithm::RsaPssSha384, KeyType::Public)
            | (Algorithm::RsaPkcs1v15Sha512, KeyType::Public)
            | (Algorithm::RsaPssSha512, KeyType::Public)
            | (Algorithm::RsaOaepSha256, KeyType::Public)
            | (Algorithm::RsaOaepSha384, KeyType::Public)
            | (Algorithm::RsaOaepSha512, KeyType::Public) => {
                ksrsa::public_blob_from_pkcs1_der(der).ok()
            }
            (Algorithm::RsaPkcs1v15Sha256, KeyType::Private)
            | (Algorithm::RsaPssSha256, KeyType::Private)
            | (Algorithm::RsaPkcs1v15Sha384, KeyType::Private)
            | (Algorithm::RsaPssSha384, KeyType::Private)
            | (Algorithm::RsaPkcs1v15Sha512, KeyType::Private)
            | (Algorithm::RsaPssSha512, KeyType::Private)
            | (Algorithm::RsaOaepSha256, KeyType::Private)
            | (Algorithm::RsaOaepSha384, KeyType::Private)
            | (Algorithm::RsaOaepSha512, KeyType::Private) => {
                ksrsa::private_blob_from_pkcs1_der(der).ok()
            }
            _ => None,
        }
    }

    pub fn save_keypair_to_files(
        &self,
        keypair: &KeyPair,
        public_filename: impl AsRef<Path>,
        private_filename: impl AsRef<Path>,
        format: KeyFormat,
    ) -> bool {
        self.save_key_to_file(
            &keypair.public_key,
            public_filename,
            KeyType::PUBLIC,
            format,
        ) && self.save_key_to_file(
            &keypair.private_key,
            private_filename,
            KeyType::PRIVATE,
            format,
        )
    }

    pub fn load_keypair_from_files(
        &self,
        public_filename: impl AsRef<Path>,
        private_filename: impl AsRef<Path>,
    ) -> CryptoResult {
        let pub_result = self.load_key_from_file(public_filename, KeyType::PUBLIC);
        if !pub_result.success {
            return pub_result;
        }
        self.load_key_from_file(private_filename, KeyType::PRIVATE)
    }

    fn expected_key_size(&self, key_type: KeyType) -> Option<usize> {
        match self.current_algorithm {
            Algorithm::X25519Box => Some(match key_type {
                KeyType::Public => box_seal_x25519::PUBLICKEYBYTES,
                KeyType::Private => {
                    box_seal_x25519::PUBLICKEYBYTES + box_seal_x25519::SECRETKEYBYTES
                }
            }),
            Algorithm::Ed25519 => Some(match key_type {
                KeyType::Public => ed25519::PUBLICKEYBYTES,
                KeyType::Private => ed25519::SECRETKEYBYTES,
            }),
            Algorithm::EcdsaP256Sha256 => Some(match key_type {
                KeyType::Public => ecdsa_p256::PUBLIC_KEY_BYTES,
                KeyType::Private => ecdsa_p256::PRIVATE_KEY_BYTES,
            }),
            Algorithm::EcdsaSecp256k1Compact => Some(match key_type {
                KeyType::Public => 65,
                KeyType::Private => secp256k1::PRIVATE_KEY_BYTES,
            }),
            _ => None,
        }
    }

    // ---------- hex helpers ----------

    pub fn to_hex(data: &[u8]) -> String {
        data.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    pub fn from_hex(text: &str) -> Vec<u8> {
        if !text.len().is_multiple_of(2) {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(text.len() / 2);
        for pair in text.as_bytes().chunks_exact(2) {
            let Some(high) = hex_value(pair[0]) else {
                return Vec::new();
            };
            let Some(low) = hex_value(pair[1]) else {
                return Vec::new();
            };
            out.push((high << 4) | low);
        }
        out
    }

    // ---------- secp256k1 statics (mirrors C++ Context::*) ----------

    pub fn recover_secp256k1_public_key(
        digest32: &[u8],
        sig64: &[u8],
        recovery_id: u8,
    ) -> secp256k1::RecoverResult {
        secp256k1::recover_public_key(digest32, sig64, recovery_id)
    }

    pub fn verify_secp256k1_compact_signature(
        digest32: &[u8],
        sig64: &[u8],
        public_key: &[u8],
    ) -> secp256k1::VerifyResult {
        secp256k1::verify_compact(digest32, sig64, public_key)
    }

    pub fn is_secp256k1_low_s(s32: &[u8]) -> bool {
        secp256k1::is_low_s(s32)
    }

    pub fn normalize_ethereum_recovery_id(v: u8) -> secp256k1::NormalizeVResult {
        secp256k1::normalize_recovery_id(v)
    }

    pub fn ethereum_address_from_uncompressed_pubkey(public_key: &[u8]) -> CryptoResult {
        let address = secp256k1::ethereum_address_from_uncompressed_pubkey(public_key);
        if address.is_empty() {
            CryptoResult::failure("Invalid secp256k1 public key")
        } else {
            CryptoResult::ok(address)
        }
    }

    pub fn keccak256(data: &[u8]) -> CryptoResult {
        let r = hash::keccak256(data);
        if r.success {
            CryptoResult::ok(r.data)
        } else {
            CryptoResult::failure(r.error_message)
        }
    }

    pub fn is_aes_gcm_available() -> bool {
        true // RustCrypto's aes-gcm runs everywhere; no AES-NI requirement.
    }

    // ---------- RSA blob / DER codecs ----------

    pub fn encode_rsa_public_key_blob(modulus: &[u8], public_exponent: &[u8]) -> Vec<u8> {
        ksrsa::encode_public_blob(modulus, public_exponent)
    }

    pub fn encode_rsa_private_key_blob(
        modulus: &[u8],
        public_exponent: &[u8],
        private_exponent: &[u8],
    ) -> Vec<u8> {
        ksrsa::encode_private_blob(modulus, public_exponent, private_exponent)
    }

    pub fn encode_rsa_public_key_pkcs1_der(modulus: &[u8], public_exponent: &[u8]) -> CryptoResult {
        match ksrsa::public_blob_to_pkcs1_der(&ksrsa::encode_public_blob(modulus, public_exponent))
        {
            Ok(der) => CryptoResult::ok(der),
            Err(e) => CryptoResult::failure(e),
        }
    }

    pub fn decode_rsa_public_key_pkcs1_der(der_bytes: &[u8]) -> CryptoResult {
        match ksrsa::public_blob_from_pkcs1_der(der_bytes) {
            Ok(blob) => CryptoResult::ok(blob),
            Err(e) => CryptoResult::failure(e),
        }
    }

    pub fn encode_rsa_private_key_pkcs1_der(
        modulus: &[u8],
        public_exponent: &[u8],
        private_exponent: &[u8],
    ) -> CryptoResult {
        Self::encode_rsa_private_key_pkcs1_der_full(
            modulus,
            public_exponent,
            private_exponent,
            &[],
            &[],
            &[],
            &[],
            &[],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn encode_rsa_private_key_pkcs1_der_full(
        modulus: &[u8],
        public_exponent: &[u8],
        private_exponent: &[u8],
        prime_p: &[u8],
        prime_q: &[u8],
        dp: &[u8],
        dq: &[u8],
        qinv: &[u8],
    ) -> CryptoResult {
        let blob = ksrsa::encode_private_blob_full(
            modulus,
            public_exponent,
            private_exponent,
            prime_p,
            prime_q,
            dp,
            dq,
            qinv,
        );
        match ksrsa::private_blob_to_pkcs1_der(&blob) {
            Ok(der) => CryptoResult::ok(der),
            Err(e) => CryptoResult::failure(e),
        }
    }

    pub fn decode_rsa_private_key_pkcs1_der(der_bytes: &[u8]) -> CryptoResult {
        match ksrsa::private_blob_from_pkcs1_der(der_bytes) {
            Ok(blob) => CryptoResult::ok(blob),
            Err(e) => CryptoResult::failure(e),
        }
    }

    // ---------- ECDSA P-256 blob / DER codecs ----------

    pub fn encode_ecdsa_p256_public_key_blob(x: &[u8], y: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend(left_pad(x, 32));
        out.extend(left_pad(y, 32));
        out
    }

    pub fn encode_ecdsa_p256_private_key_blob(d: &[u8]) -> Vec<u8> {
        left_pad(d, 32)
    }

    pub fn encode_ecdsa_p256_public_key_spki_der(x: &[u8], y: &[u8]) -> CryptoResult {
        let raw = Self::encode_ecdsa_p256_public_key_blob(x, y);
        if raw.len() != 64 {
            return CryptoResult::failure("Invalid ECDSA P-256 public key size");
        }
        let mut out = Vec::with_capacity(91);
        out.extend_from_slice(&[0x30, 0x59, 0x30, 0x13]);
        // ecPublicKey OID
        out.extend_from_slice(&[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
        // prime256v1 OID
        out.extend_from_slice(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
        out.push(0x03);
        out.push(0x42);
        out.push(0x00);
        out.push(0x04);
        out.extend_from_slice(&raw);
        CryptoResult::ok(out)
    }

    pub fn decode_ecdsa_p256_public_key_spki_der(der_bytes: &[u8]) -> CryptoResult {
        const EXPECTED_PREFIX: [u8; 26] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        if der_bytes.len() != EXPECTED_PREFIX.len() + 1 + 64
            || der_bytes[..EXPECTED_PREFIX.len()] != EXPECTED_PREFIX
            || der_bytes[EXPECTED_PREFIX.len()] != 0x04
        {
            return CryptoResult::failure("Invalid ECDSA P-256 SPKI DER");
        }
        CryptoResult::ok(der_bytes[EXPECTED_PREFIX.len() + 1..].to_vec())
    }

    pub fn encode_ecdsa_p256_private_key_pkcs8_der(d: &[u8]) -> CryptoResult {
        let raw = Self::encode_ecdsa_p256_private_key_blob(d);
        if raw.len() != 32 {
            return CryptoResult::failure("Invalid ECDSA P-256 private key size");
        }
        let mut out = vec![
            0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
            0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27,
            0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20,
        ];
        out.extend_from_slice(&raw);
        CryptoResult::ok(out)
    }

    pub fn decode_ecdsa_p256_private_key_pkcs8_der(der_bytes: &[u8]) -> CryptoResult {
        const PREFIX: [u8; 35] = [
            0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
            0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27,
            0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20,
        ];
        if der_bytes.len() != PREFIX.len() + 32 || der_bytes[..PREFIX.len()] != PREFIX {
            return CryptoResult::failure("Invalid ECDSA P-256 PKCS8 DER");
        }
        CryptoResult::ok(der_bytes[PREFIX.len()..].to_vec())
    }

    pub fn encode_ecdsa_p256_signature_der(raw: &[u8]) -> CryptoResult {
        match ecdsa_p256::signature_to_der(raw) {
            Ok(der) => CryptoResult::ok(der),
            Err(e) => CryptoResult::failure(e),
        }
    }

    pub fn decode_ecdsa_p256_signature_der(der: &[u8]) -> CryptoResult {
        match ecdsa_p256::signature_from_der(der) {
            Ok(raw) => CryptoResult::ok(raw),
            Err(e) => CryptoResult::failure(e),
        }
    }

    // ---------- Ed25519 SPKI / PKCS8 codecs ----------

    pub fn encode_ed25519_public_key_spki_der(public_key: &[u8]) -> CryptoResult {
        if public_key.len() != 32 {
            return CryptoResult::failure("Invalid Ed25519 public key size");
        }
        let mut out = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        out.extend_from_slice(public_key);
        CryptoResult::ok(out)
    }

    pub fn decode_ed25519_public_key_spki_der(der_bytes: &[u8]) -> CryptoResult {
        const PREFIX: [u8; 12] = [
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        if der_bytes.len() != PREFIX.len() + 32 || der_bytes[..PREFIX.len()] != PREFIX {
            return CryptoResult::failure("Invalid Ed25519 SPKI DER");
        }
        CryptoResult::ok(der_bytes[PREFIX.len()..].to_vec())
    }

    pub fn encode_ed25519_private_key_pkcs8_der(private_key: &[u8]) -> CryptoResult {
        if private_key.len() != 32 && private_key.len() != 64 {
            return CryptoResult::failure("Invalid Ed25519 private key size");
        }
        let mut out = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        out.extend_from_slice(&private_key[..32]);
        CryptoResult::ok(out)
    }

    pub fn decode_ed25519_private_key_pkcs8_der(der_bytes: &[u8]) -> CryptoResult {
        const PREFIX: [u8; 16] = [
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        if der_bytes.len() != PREFIX.len() + 32 || der_bytes[..PREFIX.len()] != PREFIX {
            return CryptoResult::failure("Invalid Ed25519 PKCS8 DER");
        }
        CryptoResult::ok(der_bytes[PREFIX.len()..].to_vec())
    }

    // ---------- pretty-print ----------

    pub fn algorithm_to_string(algorithm: Algorithm) -> &'static str {
        match algorithm {
            Algorithm::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            Algorithm::ChaCha20Poly1305 => "ChaCha20-Poly1305-IETF",
            Algorithm::Aes256Gcm => "AES-256-GCM",
            Algorithm::SecretBoxXSalsa20 => "SecretBox-XSalsa20-Poly1305",
            Algorithm::X25519Box => "X25519-Box",
            Algorithm::Ed25519 => "Ed25519",
            Algorithm::RsaPkcs1v15Sha256 => "RSA-PKCS1v1.5-SHA256",
            Algorithm::RsaPssSha256 => "RSA-PSS-SHA256",
            Algorithm::RsaPkcs1v15Sha384 => "RSA-PKCS1v1.5-SHA384",
            Algorithm::RsaPssSha384 => "RSA-PSS-SHA384",
            Algorithm::RsaPkcs1v15Sha512 => "RSA-PKCS1v1.5-SHA512",
            Algorithm::RsaPssSha512 => "RSA-PSS-SHA512",
            Algorithm::RsaOaepSha256 => "RSA-OAEP-SHA256",
            Algorithm::RsaOaepSha384 => "RSA-OAEP-SHA384",
            Algorithm::RsaOaepSha512 => "RSA-OAEP-SHA512",
            Algorithm::EcdsaP256Sha256 => "ECDSA-P256-SHA256",
            Algorithm::EcdsaP384Sha384 => "ECDSA-P384-SHA384",
            Algorithm::EcdsaP521Sha512 => "ECDSA-P521-SHA512",
            Algorithm::EcdsaSecp256k1Compact => "ECDSA-secp256k1-compact",
            Algorithm::Ed448 => "Ed448",
        }
    }

    pub fn hash_algorithm_to_string(hash_algorithm: HashAlgorithm) -> &'static str {
        match hash_algorithm {
            HashAlgorithm::Sha256 => "SHA-256",
            HashAlgorithm::Sha384 => "SHA-384",
            HashAlgorithm::Sha512 => "SHA-512",
            HashAlgorithm::Blake2b => "BLAKE2b",
            HashAlgorithm::Keccak256 => "Keccak-256",
        }
    }
}

fn pem_label(algorithm: Algorithm, key_type: KeyType) -> &'static str {
    match (algorithm, key_type) {
        (Algorithm::Ed25519, KeyType::Public) | (Algorithm::EcdsaP256Sha256, KeyType::Public) => {
            "PUBLIC KEY"
        }
        (Algorithm::Ed25519, KeyType::Private) | (Algorithm::EcdsaP256Sha256, KeyType::Private) => {
            "PRIVATE KEY"
        }
        (Algorithm::RsaPkcs1v15Sha256, KeyType::Public)
        | (Algorithm::RsaPssSha256, KeyType::Public)
        | (Algorithm::RsaPkcs1v15Sha384, KeyType::Public)
        | (Algorithm::RsaPssSha384, KeyType::Public)
        | (Algorithm::RsaPkcs1v15Sha512, KeyType::Public)
        | (Algorithm::RsaPssSha512, KeyType::Public)
        | (Algorithm::RsaOaepSha256, KeyType::Public)
        | (Algorithm::RsaOaepSha384, KeyType::Public)
        | (Algorithm::RsaOaepSha512, KeyType::Public) => "RSA PUBLIC KEY",
        (Algorithm::RsaPkcs1v15Sha256, KeyType::Private)
        | (Algorithm::RsaPssSha256, KeyType::Private)
        | (Algorithm::RsaPkcs1v15Sha384, KeyType::Private)
        | (Algorithm::RsaPssSha384, KeyType::Private)
        | (Algorithm::RsaPkcs1v15Sha512, KeyType::Private)
        | (Algorithm::RsaPssSha512, KeyType::Private)
        | (Algorithm::RsaOaepSha256, KeyType::Private)
        | (Algorithm::RsaOaepSha384, KeyType::Private)
        | (Algorithm::RsaOaepSha512, KeyType::Private) => "RSA PRIVATE KEY",
        _ => "KEY",
    }
}

fn der_to_pem(der: &[u8], label: &str) -> Vec<u8> {
    let b64 = base64_encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("ascii base64"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out.into_bytes()
}

fn pem_to_der(pem: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(pem).ok()?;
    let mut in_body = false;
    let mut body = String::new();
    for line in text.lines() {
        if line.starts_with("-----BEGIN") {
            in_body = true;
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if in_body {
            body.push_str(line.trim());
        }
    }
    base64_decode(&body)
}

const BASE64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        let triple = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(BASE64_ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(BASE64_ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            BASE64_ALPHABET[((triple >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            BASE64_ALPHABET[(triple & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let v0 = value(chunk[0])?;
        let v1 = value(chunk[1])?;
        let pad2 = chunk[2] == b'=';
        let pad3 = chunk[3] == b'=';
        let v2 = if pad2 { 0 } else { value(chunk[2])? };
        let v3 = if pad3 { 0 } else { value(chunk[3])? };
        let triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
        out.push(((triple >> 16) & 0xff) as u8);
        if !pad2 {
            out.push(((triple >> 8) & 0xff) as u8);
        }
        if !pad3 {
            out.push((triple & 0xff) as u8);
        }
    }
    Some(out)
}

fn left_pad(bytes: &[u8], width: usize) -> Vec<u8> {
    if bytes.len() >= width {
        bytes[bytes.len() - width..].to_vec()
    } else {
        let mut out = vec![0u8; width];
        out[width - bytes.len()..].copy_from_slice(bytes);
        out
    }
}

fn rsa_hash_from_algorithm(algorithm: Algorithm) -> HashAlgorithm {
    match algorithm {
        Algorithm::RsaPkcs1v15Sha256 | Algorithm::RsaPssSha256 | Algorithm::RsaOaepSha256 => {
            HashAlgorithm::Sha256
        }
        Algorithm::RsaPkcs1v15Sha384 | Algorithm::RsaPssSha384 | Algorithm::RsaOaepSha384 => {
            HashAlgorithm::Sha384
        }
        Algorithm::RsaPkcs1v15Sha512 | Algorithm::RsaPssSha512 | Algorithm::RsaOaepSha512 => {
            HashAlgorithm::Sha512
        }
        _ => HashAlgorithm::Sha256,
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
