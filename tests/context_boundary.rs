use ::keylock::{
    Algorithm, HashAlgorithm,
    crypto::{Context, secp256k1},
    hash::sha256,
};

#[test]
fn root_aliases_and_names_are_available_from_keylock_crate() {
    let ctx = Context::new(Algorithm::XChaCha20_Poly1305);
    assert_eq!(ctx.get_algorithm(), Algorithm::XChaCha20Poly1305);

    assert_eq!(
        Context::algorithm_to_string(Algorithm::AES256_GCM),
        "AES-256-GCM"
    );
    assert_eq!(
        Context::algorithm_to_string(Algorithm::ECDSA_SECP256K1_COMPACT),
        "ECDSA-secp256k1-compact"
    );
    assert_eq!(
        Context::algorithm_to_string(Algorithm::ChaCha20_Poly1305),
        "ChaCha20-Poly1305-IETF"
    );
    assert_eq!(
        Context::algorithm_to_string(Algorithm::SecretBox_XSalsa20),
        "SecretBox-XSalsa20-Poly1305"
    );
    assert_eq!(
        Context::algorithm_to_string(Algorithm::RSA_PKCS1v15_SHA256),
        "RSA-PKCS1v1.5-SHA256"
    );
    assert_eq!(
        Context::hash_algorithm_to_string(HashAlgorithm::BLAKE2b),
        "BLAKE2b"
    );
}

#[test]
fn context_encrypt_decrypt_covers_keylock_symmetric_algorithms() {
    let plaintext = b"context boundary: keylock crypto only";
    let key = [0x31; 32];

    for algorithm in [
        Algorithm::XChaCha20_Poly1305,
        Algorithm::ChaCha20_Poly1305,
        Algorithm::AES256_GCM,
        Algorithm::SecretBox_XSalsa20,
    ] {
        let ctx = Context::new(algorithm);
        let ciphertext = ctx.encrypt(plaintext, &key);
        assert!(
            ciphertext.success,
            "{algorithm:?}: {}",
            ciphertext.error_message
        );
        assert_ne!(ciphertext.data, plaintext);

        let decrypted = ctx.decrypt(&ciphertext.data, &key);
        assert!(
            decrypted.success,
            "{algorithm:?}: {}",
            decrypted.error_message
        );
        assert_eq!(decrypted.data, plaintext);
    }
}

#[test]
fn context_digest_hex_and_non_keylock_algorithm_errors_are_explicit() {
    let mut ctx = Context::with_hash_algorithm(Algorithm::AES256_GCM, HashAlgorithm::SHA256);
    let digest = ctx.digest(b"abc");
    assert!(digest.success, "{}", digest.error_message);
    assert_eq!(
        Context::to_hex(&digest.data),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(Context::from_hex("00abcdef"), vec![0x00, 0xab, 0xcd, 0xef]);
    assert!(Context::from_hex("abc").is_empty());
    assert!(Context::from_hex("zz").is_empty());

    // Switching to a signature algorithm and then asking it to do symmetric
    // encryption should fail with a clear message.
    ctx.set_algorithm(Algorithm::Ed25519);
    let ciphertext = ctx.encrypt(b"data", b"key");
    assert!(!ciphertext.success);
    assert!(ciphertext.error_message.contains("symmetric"));

    // Likewise, asking a symmetric algorithm to sign should fail.
    let mut sym_ctx = Context::new(Algorithm::AES256_GCM);
    sym_ctx.set_hash_algorithm(HashAlgorithm::SHA256);
    let sig = sym_ctx.sign(b"data", b"key");
    assert!(!sig.success);
    assert!(sig.error_message.contains("signing"));
}

#[test]
fn secp256k1_context_sign_verify_recover_and_eth_address_stay_in_keylock() {
    let ctx = Context::new(Algorithm::ECDSA_SECP256K1_COMPACT);
    let pair = ctx.generate_keypair().unwrap();
    assert_eq!(pair.private_key.len(), secp256k1::PRIVATE_KEY_BYTES);
    assert_eq!(pair.public_key.len(), 65);

    let message = b"keylock owns compact secp256k1";
    let signature = ctx.sign(message, &pair.private_key);
    assert!(signature.success, "{}", signature.error_message);
    assert_eq!(signature.data.len(), secp256k1::RECOVERABLE_SIGNATURE_BYTES);

    let verified = ctx.verify(message, &signature.data, &pair.public_key);
    assert!(verified.success, "{}", verified.error_message);

    let digest = sha256::hash(message);
    let recovered =
        secp256k1::recover_public_key(&digest, &signature.data[..64], signature.data[64]);
    assert!(recovered.success, "{}", recovered.error_message);
    assert_eq!(recovered.public_key_uncompressed, pair.public_key);

    let address = Context::ethereum_address_from_uncompressed_pubkey(&pair.public_key);
    assert!(address.success, "{}", address.error_message);
    assert_eq!(address.data.len(), 20);
}
