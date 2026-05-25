//! ECDSA P-521 (SHA-512) primitive surface; delegates to RustCrypto's `p521`.

use p521::ecdsa::signature::{Signer as _, Verifier as _};

pub fn keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    for _ in 0..1024 {
        let mut private_key = [0u8; 66];
        getrandom::getrandom(&mut private_key).map_err(|e| e.to_string())?;
        if let Ok(public_key) = public_key_from_private(&private_key) {
            return Ok((public_key, private_key.to_vec()));
        }
    }
    Err("failed to generate valid ECDSA P-521 keypair".to_string())
}

pub fn public_key_from_private(private_key: &[u8]) -> Result<Vec<u8>, String> {
    let signing_key = signing_key(private_key)?;
    let verifying_key = p521::ecdsa::VerifyingKey::from(&signing_key);
    let point = verifying_key.to_encoded_point(false);
    let bytes = point.as_bytes();
    if bytes.len() != 133 || bytes[0] != 0x04 {
        return Err("invalid P-521 private key".to_string());
    }
    Ok(bytes[1..].to_vec())
}

pub fn sign_detached(message: &[u8], private_key: &[u8]) -> Result<Vec<u8>, String> {
    let signing_key = signing_key(private_key)?;
    let signature: p521::ecdsa::Signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

pub fn verify_detached(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, String> {
    let public_key = normalize_sec1_public_key(public_key)?;
    let verifying_key = p521::ecdsa::VerifyingKey::from_sec1_bytes(&public_key)
        .map_err(|_| "Invalid ECDSA P-521 public key format".to_string())?;
    let signature = if signature.len() == 132 {
        p521::ecdsa::Signature::from_slice(signature)
    } else {
        p521::ecdsa::Signature::from_der(signature)
    }
    .map_err(|_| "Invalid ECDSA P-521 signature format".to_string())?;
    Ok(verifying_key.verify(message, &signature).is_ok())
}

pub fn signature_to_der(raw: &[u8]) -> Result<Vec<u8>, String> {
    if raw.len() != 132 {
        return Err("Unexpected ECDSA raw signature size".to_string());
    }
    let signature = p521::ecdsa::Signature::from_slice(raw)
        .map_err(|_| "Invalid ECDSA P-521 signature format".to_string())?;
    Ok(signature.to_der().as_bytes().to_vec())
}

fn signing_key(private_key: &[u8]) -> Result<p521::ecdsa::SigningKey, String> {
    let scalar = scalar_bytes(private_key)?;
    p521::ecdsa::SigningKey::from_slice(&scalar)
        .map_err(|_| "invalid P-521 private key".to_string())
}

fn scalar_bytes(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut value = input;
    while value.len() > 1 && value.first() == Some(&0) {
        value = &value[1..];
    }
    if value.is_empty() || value.len() > 66 || value.iter().all(|byte| *byte == 0) {
        return Err("invalid P-521 private key".to_string());
    }
    let mut out = vec![0u8; 66];
    out[66 - value.len()..].copy_from_slice(value);
    Ok(out)
}

fn normalize_sec1_public_key(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() == 133 && input[0] == 0x04 {
        Ok(input.to_vec())
    } else if input.len() == 132 {
        let mut out = Vec::with_capacity(133);
        out.push(0x04);
        out.extend_from_slice(input);
        Ok(out)
    } else {
        Err("Invalid ECDSA P-521 public key format".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p521_round_trip() {
        let (public, private) = keypair().unwrap();
        let signature = sign_detached(b"p521", &private).unwrap();
        assert!(verify_detached(b"p521", &signature, &public).unwrap());
        let der = signature_to_der(&signature).unwrap();
        assert!(verify_detached(b"p521", &der, &public).unwrap());
    }
}
