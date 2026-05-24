//! Signature & KEM known-answer vectors (RFC 8032, RFC 7748).

use keylock::crypto::{ecdsa_p256, ed25519, secp256k1};

fn hex_bytes(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        let h = char::from(bytes[i]).to_digit(16).unwrap() as u8;
        let l = char::from(bytes[i + 1]).to_digit(16).unwrap() as u8;
        out.push((h << 4) | l);
        i += 2;
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// RFC 8032 §7.1 Ed25519 test vector 2 (one-byte message)
#[test]
fn ed25519_rfc8032_test_vector_2() {
    let seed = hex_bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let expected_pk = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    let message = hex_bytes("72");
    let expected_sig = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

    let (pk, sk) = ed25519::keypair_from_seed(&seed).unwrap();
    assert_eq!(hex(&pk), expected_pk);
    let sig = ed25519::sign_detached(&message, &sk).unwrap();
    assert_eq!(hex(&sig), expected_sig);
    assert!(ed25519::verify_detached(&sig, &message, &pk));
}

// RFC 8032 §7.1 Ed25519 test vector 3 (two-byte message)
#[test]
fn ed25519_rfc8032_test_vector_3() {
    let seed = hex_bytes("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
    let expected_pk = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
    let message = hex_bytes("af82");
    let expected_sig = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";

    let (pk, sk) = ed25519::keypair_from_seed(&seed).unwrap();
    assert_eq!(hex(&pk), expected_pk);
    let sig = ed25519::sign_detached(&message, &sk).unwrap();
    assert_eq!(hex(&sig), expected_sig);
    assert!(ed25519::verify_detached(&sig, &message, &pk));
}

// Ed25519 wrong message → verify fails.
#[test]
fn ed25519_wrong_message_fails_verification() {
    let seed = hex_bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let (pk, sk) = ed25519::keypair_from_seed(&seed).unwrap();
    let sig = ed25519::sign_detached(b"keylock", &sk).unwrap();
    assert!(!ed25519::verify_detached(&sig, b"keyl0ck", &pk));
}

// Ed25519 tampered signature → verify fails.
#[test]
fn ed25519_tampered_signature_fails_verification() {
    let seed = hex_bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let (pk, sk) = ed25519::keypair_from_seed(&seed).unwrap();
    let mut sig = ed25519::sign_detached(b"keylock", &sk).unwrap();
    sig[0] ^= 0x01;
    assert!(!ed25519::verify_detached(&sig, b"keylock", &pk));
}

// ECDSA P-256: deterministic-style round-trip plus DER round-trip.
#[test]
fn ecdsa_p256_round_trip_and_der_round_trip_for_random_keys() {
    let (pub_blob, priv_blob) = ecdsa_p256::keypair().unwrap();
    let sig = ecdsa_p256::sign_detached(b"keylock P-256 KAT", &priv_blob).unwrap();
    assert!(ecdsa_p256::verify_detached(b"keylock P-256 KAT", &sig, &pub_blob).unwrap());

    let der = ecdsa_p256::signature_to_der(&sig).unwrap();
    assert!(der.starts_with(&[0x30])); // ASN.1 SEQUENCE
    let raw = ecdsa_p256::signature_from_der(&der).unwrap();
    assert_eq!(raw, sig);
}

// secp256k1 derive-then-sign cross-check against a known private key (1).
#[test]
fn secp256k1_derive_pubkey_for_private_key_1() {
    let pk = secp256k1::derive_public_key_from_secret(&hex_bytes(
        "0000000000000000000000000000000000000000000000000000000000000001",
    ))
    .unwrap();
    // Expected uncompressed pubkey for k=1 is the generator G: 04 || Gx || Gy.
    let expected = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    assert_eq!(hex(&pk), expected);
}

// secp256k1 derive-then-sign cross-check for private key = 2 (G doubled).
#[test]
fn secp256k1_derive_pubkey_for_private_key_2() {
    let pk = secp256k1::derive_public_key_from_secret(&hex_bytes(
        "0000000000000000000000000000000000000000000000000000000000000002",
    ))
    .unwrap();
    let expected = "04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a";
    assert_eq!(hex(&pk), expected);
}

// secp256k1 low-s and recovery_id normalization sanity.
#[test]
fn secp256k1_normalize_recovery_id_edge_cases() {
    assert_eq!(secp256k1::normalize_recovery_id(0).recovery_id, 0);
    assert_eq!(secp256k1::normalize_recovery_id(1).recovery_id, 1);
    assert_eq!(secp256k1::normalize_recovery_id(27).recovery_id, 0);
    assert_eq!(secp256k1::normalize_recovery_id(28).recovery_id, 1);
    assert!(!secp256k1::normalize_recovery_id(2).success);
    assert!(!secp256k1::normalize_recovery_id(255).success);
}

// secp256k1 sign / recover for a non-32-byte message (forces internal SHA-256).
#[test]
fn secp256k1_sign_and_recover_short_message() {
    let pair = secp256k1::generate_keypair().unwrap();
    let message = b"short keylock msg";
    let signature = secp256k1::sign(message, &pair.private_key);
    assert!(signature.success);
    // The internal digest is SHA-256(message), per Context::sign convention.
    use keylock::hash::sha256;
    let digest = sha256::hash(message);
    let recovered =
        secp256k1::recover_public_key(&digest, &signature.data[..64], signature.data[64]);
    assert!(recovered.success);
    assert_eq!(recovered.public_key_uncompressed, pair.public_key);
}
