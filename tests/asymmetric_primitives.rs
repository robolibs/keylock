use keylock::crypto::{Context, box_seal_x25519, ecdsa_p256, ed25519, rsa};
use keylock::{Algorithm, HashAlgorithm};

#[test]
fn ed25519_sign_verify_roundtrip() {
    let ctx = Context::new(Algorithm::Ed25519);
    let pair = ctx.generate_keypair().unwrap();
    assert_eq!(pair.public_key.len(), ed25519::PUBLICKEYBYTES);
    assert_eq!(pair.private_key.len(), ed25519::SECRETKEYBYTES);

    let message = b"keylock owns Ed25519";
    let signature = ctx.sign(message, &pair.private_key);
    assert!(signature.success, "{}", signature.error_message);
    assert_eq!(signature.data.len(), ed25519::BYTES);

    let verified = ctx.verify(message, &signature.data, &pair.public_key);
    assert!(verified.success, "{}", verified.error_message);

    let tampered = ctx.verify(b"tampered", &signature.data, &pair.public_key);
    assert!(!tampered.success);
}

#[test]
fn ed25519_spki_pkcs8_roundtrip() {
    let ctx = Context::new(Algorithm::Ed25519);
    let pair = ctx.generate_keypair().unwrap();

    let spki = Context::encode_ed25519_public_key_spki_der(&pair.public_key);
    assert!(spki.success);
    let decoded = Context::decode_ed25519_public_key_spki_der(&spki.data);
    assert!(decoded.success);
    assert_eq!(decoded.data, pair.public_key);

    let pkcs8 = Context::encode_ed25519_private_key_pkcs8_der(&pair.private_key);
    assert!(pkcs8.success);
    let decoded_priv = Context::decode_ed25519_private_key_pkcs8_der(&pkcs8.data);
    assert!(decoded_priv.success);
    assert_eq!(decoded_priv.data, pair.private_key[..32].to_vec());
}

#[test]
fn x25519_sealed_box_roundtrip() {
    let ctx = Context::new(Algorithm::X25519_Box);
    let pair = ctx.generate_keypair().unwrap();
    assert_eq!(pair.public_key.len(), box_seal_x25519::PUBLICKEYBYTES);
    assert_eq!(
        pair.private_key.len(),
        box_seal_x25519::PUBLICKEYBYTES + box_seal_x25519::SECRETKEYBYTES
    );

    let plaintext = b"sealed-box payload";
    let ciphertext = ctx.encrypt_asymmetric(plaintext, &pair.public_key);
    assert!(ciphertext.success, "{}", ciphertext.error_message);
    assert!(ciphertext.data.len() >= plaintext.len() + box_seal_x25519::SEALBYTES);

    let decrypted = ctx.decrypt_asymmetric(&ciphertext.data, &pair.private_key);
    assert!(decrypted.success, "{}", decrypted.error_message);
    assert_eq!(decrypted.data, plaintext);
}

#[test]
fn ecdsa_p256_sign_verify_roundtrip() {
    let ctx = Context::new(Algorithm::ECDSA_P256_SHA256);
    let pair = ctx.generate_keypair().unwrap();
    assert_eq!(pair.public_key.len(), ecdsa_p256::PUBLIC_KEY_BYTES);
    assert_eq!(pair.private_key.len(), ecdsa_p256::PRIVATE_KEY_BYTES);

    let message = b"keylock owns ECDSA P-256";
    let signature = ctx.sign(message, &pair.private_key);
    assert!(signature.success, "{}", signature.error_message);
    assert_eq!(signature.data.len(), ecdsa_p256::SIGNATURE_BYTES);

    let verified = ctx.verify(message, &signature.data, &pair.public_key);
    assert!(verified.success, "{}", verified.error_message);

    let der = Context::encode_ecdsa_p256_signature_der(&signature.data);
    assert!(der.success);
    let raw = Context::decode_ecdsa_p256_signature_der(&der.data);
    assert!(raw.success);
    assert_eq!(raw.data, signature.data);
}

#[test]
fn ecdsa_p256_spki_pkcs8_roundtrip() {
    let ctx = Context::new(Algorithm::ECDSA_P256_SHA256);
    let pair = ctx.generate_keypair().unwrap();

    let (x, y) = pair.public_key.split_at(32);
    let spki = Context::encode_ecdsa_p256_public_key_spki_der(x, y);
    assert!(spki.success);
    let decoded = Context::decode_ecdsa_p256_public_key_spki_der(&spki.data);
    assert!(decoded.success);
    assert_eq!(decoded.data, pair.public_key);

    let pkcs8 = Context::encode_ecdsa_p256_private_key_pkcs8_der(&pair.private_key);
    assert!(pkcs8.success);
    let decoded_priv = Context::decode_ecdsa_p256_private_key_pkcs8_der(&pkcs8.data);
    assert!(decoded_priv.success);
    assert_eq!(decoded_priv.data, pair.private_key);
}

#[test]
fn rsa_pkcs1v15_sign_verify_roundtrip() {
    // 2048-bit RSA keygen is slow; do one keygen and reuse it for all variants.
    let (public, private) = rsa::generate_keypair().unwrap();

    for algorithm in [
        Algorithm::RSA_PKCS1v15_SHA256,
        Algorithm::RSA_PKCS1v15_SHA384,
        Algorithm::RSA_PKCS1v15_SHA512,
    ] {
        let ctx = Context::new(algorithm);
        let message = b"keylock owns RSA";
        let signature = ctx.sign(message, &private);
        assert!(
            signature.success,
            "{algorithm:?}: {}",
            signature.error_message
        );
        let verified = ctx.verify(message, &signature.data, &public);
        assert!(
            verified.success,
            "{algorithm:?}: {}",
            verified.error_message
        );
    }
}

#[test]
fn rsa_pss_sign_verify_roundtrip() {
    let (public, private) = rsa::generate_keypair().unwrap();

    for algorithm in [
        Algorithm::RSA_PSS_SHA256,
        Algorithm::RSA_PSS_SHA384,
        Algorithm::RSA_PSS_SHA512,
    ] {
        let ctx = Context::new(algorithm);
        let message = b"keylock owns RSA-PSS";
        let signature = ctx.sign(message, &private);
        assert!(
            signature.success,
            "{algorithm:?}: {}",
            signature.error_message
        );
        let verified = ctx.verify(message, &signature.data, &public);
        assert!(
            verified.success,
            "{algorithm:?}: {}",
            verified.error_message
        );
    }
}

#[test]
fn rsa_oaep_encrypt_decrypt_roundtrip() {
    let (public, private) = rsa::generate_keypair().unwrap();
    let ctx = Context::new(Algorithm::RSA_OAEP_SHA256);
    let plaintext = b"keylock owns RSA-OAEP";
    let ciphertext = ctx.encrypt_asymmetric(plaintext, &public);
    assert!(ciphertext.success, "{}", ciphertext.error_message);
    let decrypted = ctx.decrypt_asymmetric(&ciphertext.data, &private);
    assert!(decrypted.success, "{}", decrypted.error_message);
    assert_eq!(decrypted.data, plaintext);
}

#[test]
fn rsa_blob_pkcs1_der_roundtrip() {
    let (public, _) = rsa::generate_keypair().unwrap();
    let der = Context::decode_rsa_public_key_pkcs1_der(
        &Context::encode_rsa_public_key_pkcs1_der(
            &public
                [4..4 + u32::from_be_bytes([public[0], public[1], public[2], public[3]]) as usize],
            // we use the helper round-tripping the blob through the public DER path
            &public[(4
                + u32::from_be_bytes([public[0], public[1], public[2], public[3]]) as usize
                + 4)..],
        )
        .data,
    );
    // Result equals the original blob (length-prefixed n||e) after a DER round-trip.
    assert!(der.success);
    assert_eq!(der.data, public);
}

#[test]
fn rsa_private_blob_preserves_crt_params_through_der_round_trip() {
    let (_, private) = rsa::generate_keypair().unwrap();
    let fields = rsa::decode_private_blob_full(&private).unwrap();
    assert!(!fields.prime_p.is_empty(), "p missing");
    assert!(!fields.prime_q.is_empty(), "q missing");
    assert!(!fields.dp.is_empty(), "dp missing");
    assert!(!fields.dq.is_empty(), "dq missing");
    assert!(!fields.qinv.is_empty(), "qinv missing");

    let der = rsa::private_blob_to_pkcs1_der(&private).unwrap();
    let round_tripped = rsa::private_blob_from_pkcs1_der(&der).unwrap();
    let round_fields = rsa::decode_private_blob_full(&round_tripped).unwrap();
    assert_eq!(fields.modulus, round_fields.modulus);
    assert_eq!(fields.public_exponent, round_fields.public_exponent);
    assert_eq!(fields.private_exponent, round_fields.private_exponent);
    assert_eq!(fields.prime_p, round_fields.prime_p);
    assert_eq!(fields.prime_q, round_fields.prime_q);
    assert_eq!(fields.dp, round_fields.dp);
    assert_eq!(fields.dq, round_fields.dq);
    assert_eq!(fields.qinv, round_fields.qinv);
}

#[test]
fn rsa_short_blob_still_decodes() {
    // Decoding a blob without CRT params must still work (backward compat).
    let (_, private) = rsa::generate_keypair().unwrap();
    let fields = rsa::decode_private_blob_full(&private).unwrap();
    let short_blob = rsa::encode_private_blob(
        &fields.modulus,
        &fields.public_exponent,
        &fields.private_exponent,
    );
    let parsed = rsa::decode_private_blob_full(&short_blob).unwrap();
    assert_eq!(parsed.modulus, fields.modulus);
    assert_eq!(parsed.private_exponent, fields.private_exponent);
    assert!(parsed.prime_p.is_empty());
    assert!(parsed.prime_q.is_empty());
}

#[test]
fn secp256k1_recover_and_low_s_via_context() {
    use keylock::crypto::secp256k1;
    use keylock::hash::sha256;
    let ctx = Context::new(Algorithm::ECDSA_SECP256K1_COMPACT);
    let pair = ctx.generate_keypair().unwrap();
    let message = b"keylock Ethereum-compatible signing path"; // !=32 bytes
    let signature = ctx.sign(message, &pair.private_key);
    assert!(signature.success);

    let digest = sha256::hash(message);
    let recovered =
        secp256k1::recover_public_key(&digest, &signature.data[..64], signature.data[64]);
    assert!(recovered.success, "{}", recovered.error_message);
    assert_eq!(recovered.public_key_uncompressed, pair.public_key);

    let verified = Context::verify_secp256k1_compact_signature(
        &digest,
        &signature.data[..64],
        &pair.public_key,
    );
    assert!(verified.success, "{}", verified.error_message);

    assert!(Context::is_secp256k1_low_s(&signature.data[32..64]));

    let normalize = Context::normalize_ethereum_recovery_id(27);
    assert!(normalize.success);
    assert_eq!(normalize.recovery_id, 0);
    let normalize = Context::normalize_ethereum_recovery_id(99);
    assert!(!normalize.success);

    let kec = Context::keccak256(b"abc");
    assert!(kec.success);
    assert_eq!(kec.data.len(), 32);
}

#[test]
fn context_symmetric_keygen_and_hmac() {
    let ctx = Context::with_hash_algorithm(Algorithm::AES256_GCM, HashAlgorithm::SHA256);
    let key = ctx.generate_symmetric_key(32);
    assert!(key.success);
    assert_eq!(key.data.len(), 32);

    let mac = ctx.hmac(b"keylock data", &key.data);
    assert!(mac.success);
    assert_eq!(mac.data.len(), 32);

    assert!(Context::is_aes_gcm_available());
}
