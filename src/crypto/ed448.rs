//! Ed448 primitive surface; delegates to the `ed448-goldilocks-plus` crate.
//!
//! Secret-key layout mirrors Ed25519: `seed || public_key` (114 bytes total).

pub const PUBLICKEYBYTES: usize = 57;
pub const SECRETKEYBYTES: usize = 114;
pub const SEEDBYTES: usize = 57;
pub const BYTES: usize = 114;

pub fn keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut seed = [0u8; SEEDBYTES];
    getrandom::getrandom(&mut seed).map_err(|e| e.to_string())?;
    keypair_from_seed(&seed)
}

pub fn keypair_from_seed(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if seed.len() != SEEDBYTES {
        return Err(format!(
            "Ed448 seed must be {SEEDBYTES} bytes (got {})",
            seed.len()
        ));
    }
    let signing_key = ed448_goldilocks_plus::SigningKey::try_from(seed)
        .map_err(|_| "Invalid Ed448 seed size".to_string())?;
    let public_key = signing_key.verifying_key().to_bytes().to_vec();
    let mut secret = Vec::with_capacity(SECRETKEYBYTES);
    secret.extend_from_slice(seed);
    secret.extend_from_slice(&public_key);
    Ok((public_key, secret))
}

pub fn sign_detached(message: &[u8], private_key: &[u8]) -> Result<Vec<u8>, String> {
    let seed = secret_key_seed(private_key)?;
    let signing_key = ed448_goldilocks_plus::SigningKey::try_from(seed)
        .map_err(|_| "Invalid Ed448 private key size".to_string())?;
    Ok(signing_key.sign_raw(message).to_bytes().to_vec())
}

pub fn verify_detached(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    if public_key.len() != PUBLICKEYBYTES || signature.len() != BYTES {
        return false;
    }
    let mut pk_arr = [0u8; PUBLICKEYBYTES];
    pk_arr.copy_from_slice(public_key);
    let verifying_key = match ed448_goldilocks_plus::VerifyingKey::from_bytes(&pk_arr) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let mut sig_arr = [0u8; BYTES];
    sig_arr.copy_from_slice(signature);
    let signature = match ed448_goldilocks_plus::Signature::from_bytes(&sig_arr) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    verifying_key.verify_raw(&signature, message).is_ok()
}

pub fn public_key_from_seed(seed: &[u8]) -> Result<Vec<u8>, String> {
    let (public_key, _) = keypair_from_seed(seed)?;
    Ok(public_key)
}

fn secret_key_seed(private_key: &[u8]) -> Result<&[u8], String> {
    match private_key.len() {
        SEEDBYTES => Ok(private_key),
        SECRETKEYBYTES => {
            let seed = &private_key[..SEEDBYTES];
            let expected = public_key_from_seed(seed)?;
            if expected.as_slice() != &private_key[SEEDBYTES..] {
                return Err("Ed448 private key public half mismatch".to_string());
            }
            Ok(seed)
        }
        _ => Err("Invalid Ed448 private key size".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed448_round_trip() {
        let (public, private) = keypair_from_seed(&[0x42u8; SEEDBYTES]).unwrap();
        let signature = sign_detached(b"ed448-message", &private).unwrap();
        assert_eq!(signature.len(), BYTES);
        assert!(verify_detached(b"ed448-message", &signature, &public));

        let mut bad = signature;
        bad[0] ^= 1;
        assert!(!verify_detached(b"ed448-message", &bad, &public));
    }
}
