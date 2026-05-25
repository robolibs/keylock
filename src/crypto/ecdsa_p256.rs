//! ECDSA over NIST P-256 (secp256r1) compatibility surface.
//!
//! Mirrors `keylock/crypto/ecdsa_p256/*`. The C++ implementation exposes:
//!   * sign / verify (SHA-256 of message, RFC6979 deterministic nonce)
//!   * raw 64-byte signature (r || s) and DER (ASN.1 SEQUENCE) encodings
//!   * 64-byte public-key blob (X || Y, big-endian) and 32-byte private scalar
//!
//! The primitive is delegated to the `p256` crate (RustCrypto), which provides
//! RFC6979 deterministic ECDSA with SHA-256 prehashing.

use p256::{
    EncodedPoint, SecretKey,
    ecdsa::{
        DerSignature, Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier,
    },
    elliptic_curve::{generic_array::GenericArray, sec1::ToEncodedPoint},
};

pub const PRIVATE_KEY_BYTES: usize = 32;
pub const PUBLIC_KEY_BYTES: usize = 64;
pub const SIGNATURE_BYTES: usize = 64;

pub fn keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    for _ in 0..64 {
        let mut secret_bytes = [0u8; PRIVATE_KEY_BYTES];
        getrandom::getrandom(&mut secret_bytes).map_err(|e| e.to_string())?;
        let Ok(secret) = SecretKey::from_bytes(&GenericArray::clone_from_slice(&secret_bytes))
        else {
            continue;
        };
        let public = secret.public_key();
        let encoded = public.to_encoded_point(false);
        let x = encoded.x().ok_or("missing x coordinate")?;
        let y = encoded.y().ok_or("missing y coordinate")?;
        let mut public_blob = Vec::with_capacity(PUBLIC_KEY_BYTES);
        public_blob.extend_from_slice(x);
        public_blob.extend_from_slice(y);
        return Ok((public_blob, secret_bytes.to_vec()));
    }
    Err("ECDSA P-256 key generation failed".to_string())
}

pub fn derive_public_key(private_key: &[u8]) -> Result<Vec<u8>, String> {
    if private_key.len() != PRIVATE_KEY_BYTES {
        return Err(format!(
            "ECDSA P-256 private key must be {PRIVATE_KEY_BYTES} bytes (got {})",
            private_key.len()
        ));
    }
    let secret = SecretKey::from_bytes(&GenericArray::clone_from_slice(private_key))
        .map_err(|_| "Invalid ECDSA P-256 private key".to_string())?;
    let encoded = secret.public_key().to_encoded_point(false);
    let x = encoded.x().ok_or("missing x coordinate")?;
    let y = encoded.y().ok_or("missing y coordinate")?;
    let mut out = Vec::with_capacity(PUBLIC_KEY_BYTES);
    out.extend_from_slice(x);
    out.extend_from_slice(y);
    Ok(out)
}

pub fn sign_detached(message: &[u8], private_key: &[u8]) -> Result<Vec<u8>, String> {
    if private_key.len() != PRIVATE_KEY_BYTES {
        return Err(format!(
            "ECDSA P-256 private key must be {PRIVATE_KEY_BYTES} bytes (got {})",
            private_key.len()
        ));
    }
    let signing_key = SigningKey::from_bytes(&GenericArray::clone_from_slice(private_key))
        .map_err(|_| "Invalid ECDSA P-256 private key".to_string())?;
    let signature: Signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

pub fn verify_detached(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, String> {
    if signature.len() != SIGNATURE_BYTES {
        return Err(format!(
            "ECDSA P-256 signature must be {SIGNATURE_BYTES} bytes (got {})",
            signature.len()
        ));
    }
    if public_key.len() != PUBLIC_KEY_BYTES {
        return Err(format!(
            "ECDSA P-256 public key must be {PUBLIC_KEY_BYTES} bytes (got {})",
            public_key.len()
        ));
    }
    let mut encoded = Vec::with_capacity(1 + PUBLIC_KEY_BYTES);
    encoded.push(0x04);
    encoded.extend_from_slice(public_key);
    let point = EncodedPoint::from_bytes(&encoded)
        .map_err(|_| "Invalid ECDSA P-256 point encoding".to_string())?;
    let verifying_key = VerifyingKey::from_encoded_point(&point)
        .map_err(|_| "Invalid ECDSA P-256 public key".to_string())?;
    let sig = Signature::from_slice(signature)
        .map_err(|_| "Invalid ECDSA P-256 signature".to_string())?;
    Ok(verifying_key.verify(message, &sig).is_ok())
}

pub fn signature_to_der(raw: &[u8]) -> Result<Vec<u8>, String> {
    if raw.len() != SIGNATURE_BYTES {
        return Err(format!(
            "ECDSA P-256 raw signature must be {SIGNATURE_BYTES} bytes (got {})",
            raw.len()
        ));
    }
    let sig =
        Signature::from_slice(raw).map_err(|_| "Invalid ECDSA P-256 signature".to_string())?;
    Ok(sig.to_der().as_bytes().to_vec())
}

pub fn signature_from_der(der: &[u8]) -> Result<Vec<u8>, String> {
    let sig =
        DerSignature::try_from(der).map_err(|_| "Invalid ECDSA P-256 DER signature".to_string())?;
    let raw: Signature = sig
        .try_into()
        .map_err(|_| "Invalid ECDSA P-256 signature components".to_string())?;
    Ok(raw.to_bytes().to_vec())
}
