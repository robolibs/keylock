//! secp256k1 compact ECDSA compatibility surface.
//!
//! The C++ dependency exposes this under `keylock/crypto/secp256k1`. The Rust
//! port keeps that module boundary and delegates the primitive to `k256`.

use k256::ecdsa::{
    RecoveryId, Signature, SigningKey, VerifyingKey,
    signature::hazmat::{PrehashSigner, PrehashVerifier},
};

use super::context::{Algorithm, CryptoResult, KeyPair};

pub const PRIVATE_KEY_BYTES: usize = 32;
pub const COMPACT_SIGNATURE_BYTES: usize = 64;
pub const RECOVERABLE_SIGNATURE_BYTES: usize = 65;
const ORDER_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
const HALF_ORDER_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

pub fn derive_public_key_from_secret(secret: &[u8]) -> Result<Vec<u8>, String> {
    if secret.len() != PRIVATE_KEY_BYTES {
        return Err(format!(
            "secp256k1 private key must be {PRIVATE_KEY_BYTES} bytes (got {})",
            secret.len()
        ));
    }
    let signing_key =
        SigningKey::from_slice(secret).map_err(|_| "Invalid secp256k1 private key".to_string())?;
    Ok(signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec())
}

pub fn generate_keypair() -> Result<KeyPair, String> {
    for _ in 0..64 {
        let mut secret = [0u8; PRIVATE_KEY_BYTES];
        getrandom::getrandom(&mut secret).map_err(|err| err.to_string())?;
        if let Ok(signing_key) = SigningKey::from_slice(&secret) {
            let public_key = signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();
            return Ok(KeyPair {
                public_key,
                private_key: secret.to_vec(),
                algorithm: Algorithm::EcdsaSecp256k1Compact,
            });
        }
    }
    Err("secp256k1 key generation failed".to_string())
}

pub fn sign(data: &[u8], private_key: &[u8]) -> CryptoResult {
    if private_key.len() != PRIVATE_KEY_BYTES {
        return CryptoResult::failure("Invalid secp256k1 private key size");
    }
    let signing_key = match SigningKey::from_slice(private_key) {
        Ok(signing_key) => signing_key,
        Err(_) => return CryptoResult::failure("Invalid secp256k1 private key"),
    };
    let digest = digest32(data);
    let (signature, recovery_id): (Signature, RecoveryId) = match signing_key.sign_prehash(&digest)
    {
        Ok(signed) => signed,
        Err(_) => return CryptoResult::failure("secp256k1 signing failed"),
    };
    let mut out = signature.to_bytes().to_vec();
    out.push(recovery_id.to_byte());
    CryptoResult::ok(out)
}

pub fn verify(data: &[u8], signature: &[u8], public_key: &[u8]) -> CryptoResult {
    let digest = digest32(data);
    let sig64 = if signature.len() == RECOVERABLE_SIGNATURE_BYTES {
        &signature[..COMPACT_SIGNATURE_BYTES]
    } else {
        signature
    };
    let result = verify_compact(&digest, sig64, public_key);
    if result.success {
        CryptoResult::ok(Vec::new())
    } else {
        CryptoResult::failure(result.error_message)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VerifyResult {
    pub success: bool,
    pub error_message: String,
}

impl VerifyResult {
    pub fn ok() -> Self {
        Self {
            success: true,
            error_message: String::new(),
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            error_message: error.into(),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecoverResult {
    pub success: bool,
    pub public_key_uncompressed: Vec<u8>,
    pub error_message: String,
}

impl RecoverResult {
    pub fn ok(public_key_uncompressed: Vec<u8>) -> Self {
        Self {
            success: true,
            public_key_uncompressed,
            error_message: String::new(),
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            public_key_uncompressed: Vec::new(),
            error_message: error.into(),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NormalizeVResult {
    pub success: bool,
    pub recovery_id: u8,
    pub error_message: String,
}

impl NormalizeVResult {
    pub fn ok(recovery_id: u8) -> Self {
        Self {
            success: true,
            recovery_id,
            error_message: String::new(),
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            recovery_id: 0,
            error_message: error.into(),
        }
    }
}

pub fn verify_compact(digest32: &[u8], sig64: &[u8], public_key: &[u8]) -> VerifyResult {
    if digest32.len() != 32 {
        return VerifyResult::failure("Invalid digest length: expected 32 bytes");
    }
    if sig64.len() != COMPACT_SIGNATURE_BYTES {
        return VerifyResult::failure("Invalid signature length: expected 64 bytes");
    }
    let verifying_key = match VerifyingKey::from_sec1_bytes(public_key) {
        Ok(verifying_key) => verifying_key,
        Err(_) => return VerifyResult::failure("Invalid secp256k1 public key"),
    };
    let signature = match Signature::from_slice(sig64) {
        Ok(signature) => signature,
        Err(_) => return VerifyResult::failure("Invalid secp256k1 signature"),
    };
    match verifying_key.verify_prehash(digest32, &signature) {
        Ok(()) => VerifyResult::ok(),
        Err(_) => VerifyResult::failure("Signature verification failed"),
    }
}

pub fn recover_public_key(digest32: &[u8], sig64: &[u8], recovery_id: u8) -> RecoverResult {
    if digest32.len() != 32 {
        return RecoverResult::failure("Invalid digest length: expected 32 bytes");
    }
    if sig64.len() != COMPACT_SIGNATURE_BYTES {
        return RecoverResult::failure("Invalid signature length: expected 64 bytes");
    }
    if recovery_id != 0 && recovery_id != 1 {
        return RecoverResult::failure("Invalid recovery id: expected 0 or 1");
    }
    let signature = match Signature::from_slice(sig64) {
        Ok(signature) => signature,
        Err(_) => return RecoverResult::failure("Invalid secp256k1 signature"),
    };
    let recovery_id = match RecoveryId::try_from(recovery_id) {
        Ok(recovery_id) => recovery_id,
        Err(_) => return RecoverResult::failure("Invalid recovery id: expected 0 or 1"),
    };
    match VerifyingKey::recover_from_prehash(digest32, &signature, recovery_id) {
        Ok(public_key) => RecoverResult::ok(public_key.to_encoded_point(false).as_bytes().to_vec()),
        Err(_) => RecoverResult::failure("Failed to recover secp256k1 public key"),
    }
}

pub fn normalize_recovery_id(v: u8) -> NormalizeVResult {
    match v {
        0 | 1 => NormalizeVResult::ok(v),
        27 | 28 => NormalizeVResult::ok(v - 27),
        _ => NormalizeVResult::failure("Invalid v: expected 0/1 or 27/28"),
    }
}

pub fn is_low_s(s32: &[u8]) -> bool {
    s32.len() == 32
        && !s32.iter().all(|byte| *byte == 0)
        && compare_be(s32, &ORDER_N) < 0
        && compare_be(s32, &HALF_ORDER_N) <= 0
}

pub fn ethereum_address_from_uncompressed_pubkey(public_key: &[u8]) -> Vec<u8> {
    if public_key.len() != 65 || public_key[0] != 0x04 {
        return Vec::new();
    }
    let digest = crate::hash::keccak::hash_256(&public_key[1..]);
    digest[12..].to_vec()
}

fn digest32(data: &[u8]) -> [u8; 32] {
    if data.len() == 32 {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(data);
        digest
    } else {
        let hashed = crate::hash::sha256::hash(data);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&hashed);
        digest
    }
}

fn compare_be(left: &[u8], right: &[u8]) -> i8 {
    for (l, r) in left.iter().zip(right.iter()) {
        if l < r {
            return -1;
        }
        if l > r {
            return 1;
        }
    }
    0
}
