//! RSA compatibility surface (keygen, PKCS#1 v1.5, PSS, OAEP).
//!
//! Mirrors `keylock/crypto/rsa/*`. The C++ context serialises RSA keys with a
//! custom big-endian length-prefixed blob:
//!
//!   * public:  `len(n)|n|len(e)|e`
//!   * private: `len(n)|n|len(e)|e|len(d)|d`
//!
//! That layout is preserved here so callers can interoperate at the byte level.
//!
//! All math is delegated to the `rsa` crate (RustCrypto). We translate between
//! the keylock blob layout and `rsa`'s `RsaPublicKey`/`RsaPrivateKey` types.

use rsa::{
    BigUint, Oaep, Pkcs1v15Encrypt, Pkcs1v15Sign, Pss, RsaPrivateKey, RsaPublicKey,
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
    signature::{RandomizedSigner, SignatureEncoding, Signer},
    traits::{PrivateKeyParts, PublicKeyParts},
};
use sha2::{Sha256, Sha384, Sha512};

use crate::hash::HashAlgorithm;

const DEFAULT_BITS: usize = 2048;
const DEFAULT_EXPONENT: u64 = 65_537;

pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    generate_keypair_with_bits(DEFAULT_BITS)
}

pub fn generate_keypair_with_bits(bits: usize) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut rng = rand_core_rng();
    let exponent = BigUint::from(DEFAULT_EXPONENT);
    let private_key = RsaPrivateKey::new_with_exp(&mut rng, bits, &exponent)
        .map_err(|e| format!("RSA key generation failed: {e}"))?;
    let public_key = RsaPublicKey::from(&private_key);

    let n = public_key.n().to_bytes_be();
    let e = public_key.e().to_bytes_be();
    let d = private_key.d().to_bytes_be();
    let primes = private_key.primes();
    let p = primes.first().map(|p| p.to_bytes_be()).unwrap_or_default();
    let q = primes.get(1).map(|q| q.to_bytes_be()).unwrap_or_default();
    let dp = private_key.dp().map(|x| x.to_bytes_be()).unwrap_or_default();
    let dq = private_key.dq().map(|x| x.to_bytes_be()).unwrap_or_default();
    let qinv = private_key
        .qinv()
        .map(|x| x.to_bytes_be().1)
        .unwrap_or_default();
    Ok((
        encode_public_blob(&n, &e),
        encode_private_blob_full(&n, &e, &d, &p, &q, &dp, &dq, &qinv),
    ))
}

pub fn encrypt_oaep(
    plaintext: &[u8],
    public_blob: &[u8],
    hash: HashAlgorithm,
) -> Result<Vec<u8>, String> {
    let public_key = decode_public_blob(public_blob)?;
    let mut rng = rand_core_rng();
    let padding = match hash {
        HashAlgorithm::Sha256 => Oaep::new::<Sha256>(),
        HashAlgorithm::Sha384 => Oaep::new::<Sha384>(),
        HashAlgorithm::Sha512 => Oaep::new::<Sha512>(),
        _ => return Err("RSA-OAEP requires SHA-256/384/512".to_string()),
    };
    public_key
        .encrypt(&mut rng, padding, plaintext)
        .map_err(|e| format!("RSA-OAEP encryption failed: {e}"))
}

pub fn decrypt_oaep(
    ciphertext: &[u8],
    private_blob: &[u8],
    hash: HashAlgorithm,
) -> Result<Vec<u8>, String> {
    let private_key = decode_private_blob(private_blob)?;
    let padding = match hash {
        HashAlgorithm::Sha256 => Oaep::new::<Sha256>(),
        HashAlgorithm::Sha384 => Oaep::new::<Sha384>(),
        HashAlgorithm::Sha512 => Oaep::new::<Sha512>(),
        _ => return Err("RSA-OAEP requires SHA-256/384/512".to_string()),
    };
    private_key
        .decrypt(padding, ciphertext)
        .map_err(|e| format!("RSA-OAEP decryption failed: {e}"))
}

pub fn encrypt_pkcs1v15(plaintext: &[u8], public_blob: &[u8]) -> Result<Vec<u8>, String> {
    let public_key = decode_public_blob(public_blob)?;
    let mut rng = rand_core_rng();
    public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, plaintext)
        .map_err(|e| format!("RSA PKCS#1 v1.5 encryption failed: {e}"))
}

pub fn decrypt_pkcs1v15(ciphertext: &[u8], private_blob: &[u8]) -> Result<Vec<u8>, String> {
    let private_key = decode_private_blob(private_blob)?;
    private_key
        .decrypt(Pkcs1v15Encrypt, ciphertext)
        .map_err(|e| format!("RSA PKCS#1 v1.5 decryption failed: {e}"))
}

pub fn sign_pkcs1v15(
    message: &[u8],
    private_blob: &[u8],
    hash: HashAlgorithm,
) -> Result<Vec<u8>, String> {
    let private_key = decode_private_blob(private_blob)?;
    let signature = match hash {
        HashAlgorithm::Sha256 => rsa::pkcs1v15::SigningKey::<Sha256>::new(private_key)
            .sign(message)
            .to_vec(),
        HashAlgorithm::Sha384 => rsa::pkcs1v15::SigningKey::<Sha384>::new(private_key)
            .sign(message)
            .to_vec(),
        HashAlgorithm::Sha512 => rsa::pkcs1v15::SigningKey::<Sha512>::new(private_key)
            .sign(message)
            .to_vec(),
        _ => return Err("RSA PKCS#1 v1.5 requires SHA-256/384/512".to_string()),
    };
    Ok(signature)
}

pub fn verify_pkcs1v15(
    message: &[u8],
    signature: &[u8],
    public_blob: &[u8],
    hash: HashAlgorithm,
) -> Result<bool, String> {
    let public_key = decode_public_blob(public_blob)?;
    let padding = match hash {
        HashAlgorithm::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
        HashAlgorithm::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
        HashAlgorithm::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
        _ => return Err("RSA PKCS#1 v1.5 requires SHA-256/384/512".to_string()),
    };
    let digest = digest_message(message, hash);
    Ok(public_key.verify(padding, &digest, signature).is_ok())
}

pub fn sign_pss(
    message: &[u8],
    private_blob: &[u8],
    hash: HashAlgorithm,
) -> Result<Vec<u8>, String> {
    let private_key = decode_private_blob(private_blob)?;
    let mut rng = rand_core_rng();
    let signature = match hash {
        HashAlgorithm::Sha256 => rsa::pss::SigningKey::<Sha256>::new(private_key)
            .sign_with_rng(&mut rng, message)
            .to_vec(),
        HashAlgorithm::Sha384 => rsa::pss::SigningKey::<Sha384>::new(private_key)
            .sign_with_rng(&mut rng, message)
            .to_vec(),
        HashAlgorithm::Sha512 => rsa::pss::SigningKey::<Sha512>::new(private_key)
            .sign_with_rng(&mut rng, message)
            .to_vec(),
        _ => return Err("RSA-PSS requires SHA-256/384/512".to_string()),
    };
    Ok(signature)
}

pub fn verify_pss(
    message: &[u8],
    signature: &[u8],
    public_blob: &[u8],
    hash: HashAlgorithm,
) -> Result<bool, String> {
    let public_key = decode_public_blob(public_blob)?;
    let padding = match hash {
        HashAlgorithm::Sha256 => Pss::new::<Sha256>(),
        HashAlgorithm::Sha384 => Pss::new::<Sha384>(),
        HashAlgorithm::Sha512 => Pss::new::<Sha512>(),
        _ => return Err("RSA-PSS requires SHA-256/384/512".to_string()),
    };
    let digest = digest_message(message, hash);
    Ok(public_key.verify(padding, &digest, signature).is_ok())
}

pub fn encode_public_blob(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + modulus.len() + exponent.len());
    push_u32_be(&mut out, modulus.len() as u32);
    out.extend_from_slice(modulus);
    push_u32_be(&mut out, exponent.len() as u32);
    out.extend_from_slice(exponent);
    out
}

pub fn encode_private_blob(modulus: &[u8], exponent: &[u8], private_exponent: &[u8]) -> Vec<u8> {
    let mut out = encode_public_blob(modulus, exponent);
    push_u32_be(&mut out, private_exponent.len() as u32);
    out.extend_from_slice(private_exponent);
    out
}

/// Extended blob carrying CRT params: `n|e|d|p|q|dp|dq|qinv`. Optional fields
/// may be empty (zero-length prefix), in which case decode skips them.
#[allow(clippy::too_many_arguments)]
pub fn encode_private_blob_full(
    modulus: &[u8],
    exponent: &[u8],
    private_exponent: &[u8],
    prime_p: &[u8],
    prime_q: &[u8],
    dp: &[u8],
    dq: &[u8],
    qinv: &[u8],
) -> Vec<u8> {
    let mut out = encode_private_blob(modulus, exponent, private_exponent);
    // Append CRT only if at least one is non-empty; otherwise stay backward-
    // compatible with the short form.
    if prime_p.is_empty()
        && prime_q.is_empty()
        && dp.is_empty()
        && dq.is_empty()
        && qinv.is_empty()
    {
        return out;
    }
    push_u32_be(&mut out, prime_p.len() as u32);
    out.extend_from_slice(prime_p);
    push_u32_be(&mut out, prime_q.len() as u32);
    out.extend_from_slice(prime_q);
    push_u32_be(&mut out, dp.len() as u32);
    out.extend_from_slice(dp);
    push_u32_be(&mut out, dq.len() as u32);
    out.extend_from_slice(dq);
    push_u32_be(&mut out, qinv.len() as u32);
    out.extend_from_slice(qinv);
    out
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PrivateBlobFields {
    pub modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
    pub private_exponent: Vec<u8>,
    pub prime_p: Vec<u8>,
    pub prime_q: Vec<u8>,
    pub dp: Vec<u8>,
    pub dq: Vec<u8>,
    pub qinv: Vec<u8>,
}

pub fn decode_private_blob_full(blob: &[u8]) -> Result<PrivateBlobFields, String> {
    let (n, e, mut offset) = parse_public_blob(blob)?;
    let d = read_length_prefixed(blob, offset, "private exponent")?;
    if d.is_empty() {
        return Err("RSA private key blob has empty private exponent".to_string());
    }
    offset += 4 + d.len();

    let mut fields = PrivateBlobFields {
        modulus: n,
        public_exponent: e,
        private_exponent: d,
        ..Default::default()
    };

    if offset == blob.len() {
        return Ok(fields);
    }

    fields.prime_p = read_length_prefixed(blob, offset, "prime_p")?;
    offset += 4 + fields.prime_p.len();
    fields.prime_q = read_length_prefixed(blob, offset, "prime_q")?;
    offset += 4 + fields.prime_q.len();
    fields.dp = read_length_prefixed(blob, offset, "dp")?;
    offset += 4 + fields.dp.len();
    fields.dq = read_length_prefixed(blob, offset, "dq")?;
    offset += 4 + fields.dq.len();
    fields.qinv = read_length_prefixed(blob, offset, "qinv")?;
    offset += 4 + fields.qinv.len();

    if offset != blob.len() {
        return Err("RSA private key blob has trailing bytes".to_string());
    }
    Ok(fields)
}

pub fn decode_public_blob(blob: &[u8]) -> Result<RsaPublicKey, String> {
    let (n, e, _) = parse_public_blob(blob)?;
    RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e))
        .map_err(|e| format!("Invalid RSA public key: {e}"))
}

pub fn decode_private_blob(blob: &[u8]) -> Result<RsaPrivateKey, String> {
    let fields = decode_private_blob_full(blob)?;
    let mut primes = Vec::new();
    if !fields.prime_p.is_empty() {
        primes.push(BigUint::from_bytes_be(&fields.prime_p));
    }
    if !fields.prime_q.is_empty() {
        primes.push(BigUint::from_bytes_be(&fields.prime_q));
    }
    RsaPrivateKey::from_components(
        BigUint::from_bytes_be(&fields.modulus),
        BigUint::from_bytes_be(&fields.public_exponent),
        BigUint::from_bytes_be(&fields.private_exponent),
        primes,
    )
    .map_err(|e| format!("Invalid RSA private key: {e}"))
}

pub fn public_blob_to_pkcs1_der(blob: &[u8]) -> Result<Vec<u8>, String> {
    let key = decode_public_blob(blob)?;
    key.to_pkcs1_der()
        .map_err(|e| format!("RSA public PKCS#1 DER encode failed: {e}"))
        .map(|doc| doc.as_bytes().to_vec())
}

pub fn private_blob_to_pkcs1_der(blob: &[u8]) -> Result<Vec<u8>, String> {
    let key = decode_private_blob(blob)?;
    key.to_pkcs1_der()
        .map_err(|e| format!("RSA private PKCS#1 DER encode failed: {e}"))
        .map(|doc| doc.as_bytes().to_vec())
}

pub fn public_blob_from_pkcs1_der(der: &[u8]) -> Result<Vec<u8>, String> {
    let key = RsaPublicKey::from_pkcs1_der(der)
        .map_err(|e| format!("RSA public PKCS#1 DER decode failed: {e}"))?;
    Ok(encode_public_blob(
        &key.n().to_bytes_be(),
        &key.e().to_bytes_be(),
    ))
}

pub fn private_blob_from_pkcs1_der(der: &[u8]) -> Result<Vec<u8>, String> {
    let key = RsaPrivateKey::from_pkcs1_der(der)
        .map_err(|e| format!("RSA private PKCS#1 DER decode failed: {e}"))?;
    let primes = key.primes();
    let p = primes.first().map(|p| p.to_bytes_be()).unwrap_or_default();
    let q = primes.get(1).map(|q| q.to_bytes_be()).unwrap_or_default();
    let dp = key.dp().map(|x| x.to_bytes_be()).unwrap_or_default();
    let dq = key.dq().map(|x| x.to_bytes_be()).unwrap_or_default();
    let qinv = key.qinv().map(|x| x.to_bytes_be().1).unwrap_or_default();
    Ok(encode_private_blob_full(
        &key.n().to_bytes_be(),
        &key.e().to_bytes_be(),
        &key.d().to_bytes_be(),
        &p,
        &q,
        &dp,
        &dq,
        &qinv,
    ))
}

fn parse_public_blob(blob: &[u8]) -> Result<(Vec<u8>, Vec<u8>, usize), String> {
    let n = read_length_prefixed(blob, 0, "modulus")?;
    if n.is_empty() {
        return Err("RSA key blob has empty modulus".to_string());
    }
    let offset_after_n = 4 + n.len();
    let e = read_length_prefixed(blob, offset_after_n, "exponent")?;
    if e.is_empty() {
        return Err("RSA key blob has empty exponent".to_string());
    }
    let next_offset = offset_after_n + 4 + e.len();
    Ok((n, e, next_offset))
}

fn read_length_prefixed(blob: &[u8], offset: usize, field: &str) -> Result<Vec<u8>, String> {
    if offset + 4 > blob.len() {
        return Err(format!("RSA key blob missing {field} length"));
    }
    let len = u32::from_be_bytes([
        blob[offset],
        blob[offset + 1],
        blob[offset + 2],
        blob[offset + 3],
    ]) as usize;
    let start = offset + 4;
    if start + len > blob.len() {
        return Err(format!("RSA key blob {field} truncated"));
    }
    Ok(blob[start..start + len].to_vec())
}

fn push_u32_be(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn digest_message(message: &[u8], hash: HashAlgorithm) -> Vec<u8> {
    use sha2::Digest;
    match hash {
        HashAlgorithm::Sha256 => Sha256::digest(message).to_vec(),
        HashAlgorithm::Sha384 => Sha384::digest(message).to_vec(),
        HashAlgorithm::Sha512 => Sha512::digest(message).to_vec(),
        _ => Vec::new(),
    }
}

fn rand_core_rng() -> impl rand_core::CryptoRng + rand_core::RngCore {
    rand_core::OsRng
}
