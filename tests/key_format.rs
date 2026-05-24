use keylock::crypto::Context;
use keylock::{Algorithm, KeyFormat, KeyType};
use std::env;
use std::path::PathBuf;

fn tmp_path(name: &str) -> PathBuf {
    let mut p = env::temp_dir();
    p.push(format!("keylock-test-{}-{}", std::process::id(), name));
    p
}

#[test]
fn ed25519_pem_der_roundtrip() {
    let ctx = Context::new(Algorithm::Ed25519);
    let pair = ctx.generate_keypair().unwrap();

    let pub_pem = tmp_path("ed25519_pub.pem");
    let priv_pem = tmp_path("ed25519_priv.pem");
    let pub_der = tmp_path("ed25519_pub.der");
    let priv_der = tmp_path("ed25519_priv.der");

    assert!(ctx.save_key_to_file(&pair.public_key, &pub_pem, KeyType::PUBLIC, KeyFormat::Pem));
    assert!(ctx.save_key_to_file(
        &pair.private_key,
        &priv_pem,
        KeyType::PRIVATE,
        KeyFormat::Pem,
    ));
    assert!(ctx.save_key_to_file(&pair.public_key, &pub_der, KeyType::PUBLIC, KeyFormat::Der));
    assert!(ctx.save_key_to_file(
        &pair.private_key,
        &priv_der,
        KeyType::PRIVATE,
        KeyFormat::Der,
    ));

    let pem_data = std::fs::read_to_string(&pub_pem).unwrap();
    assert!(pem_data.starts_with("-----BEGIN PUBLIC KEY-----"));
    assert!(pem_data.contains("-----END PUBLIC KEY-----"));

    let pub_loaded_pem = ctx.load_key_from_file(&pub_pem, KeyType::PUBLIC);
    assert!(pub_loaded_pem.success, "{}", pub_loaded_pem.error_message);
    assert_eq!(pub_loaded_pem.data, pair.public_key);

    let priv_loaded_pem = ctx.load_key_from_file(&priv_pem, KeyType::PRIVATE);
    assert!(priv_loaded_pem.success, "{}", priv_loaded_pem.error_message);
    assert_eq!(priv_loaded_pem.data, pair.private_key);

    let pub_loaded_der = ctx.load_key_from_file(&pub_der, KeyType::PUBLIC);
    assert!(pub_loaded_der.success, "{}", pub_loaded_der.error_message);
    assert_eq!(pub_loaded_der.data, pair.public_key);

    let priv_loaded_der = ctx.load_key_from_file(&priv_der, KeyType::PRIVATE);
    assert!(priv_loaded_der.success, "{}", priv_loaded_der.error_message);
    assert_eq!(priv_loaded_der.data, pair.private_key);

    for p in [&pub_pem, &priv_pem, &pub_der, &priv_der] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn ecdsa_p256_pem_roundtrip() {
    let ctx = Context::new(Algorithm::ECDSA_P256_SHA256);
    let pair = ctx.generate_keypair().unwrap();
    let pub_pem = tmp_path("p256_pub.pem");
    let priv_pem = tmp_path("p256_priv.pem");
    assert!(ctx.save_key_to_file(&pair.public_key, &pub_pem, KeyType::PUBLIC, KeyFormat::Pem));
    assert!(ctx.save_key_to_file(
        &pair.private_key,
        &priv_pem,
        KeyType::PRIVATE,
        KeyFormat::Pem,
    ));
    assert_eq!(
        ctx.load_key_from_file(&pub_pem, KeyType::PUBLIC).data,
        pair.public_key
    );
    assert_eq!(
        ctx.load_key_from_file(&priv_pem, KeyType::PRIVATE).data,
        pair.private_key
    );
    let _ = std::fs::remove_file(&pub_pem);
    let _ = std::fs::remove_file(&priv_pem);
}

#[test]
fn raw_format_unchanged() {
    let ctx = Context::new(Algorithm::Ed25519);
    let pair = ctx.generate_keypair().unwrap();
    let pub_raw = tmp_path("ed25519_pub.raw");
    assert!(ctx.save_key_to_file(&pair.public_key, &pub_raw, KeyType::PUBLIC, KeyFormat::Raw));
    let on_disk = std::fs::read(&pub_raw).unwrap();
    assert_eq!(on_disk, pair.public_key);
    let _ = std::fs::remove_file(&pub_raw);
}
