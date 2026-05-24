use keylock::compat;
use keylock::crypto::rng;

#[test]
fn libsodium_constants_match_documented_values() {
    assert_eq!(compat::CRYPTO_GENERICHASH_BYTES, 32);
    assert_eq!(compat::CRYPTO_GENERICHASH_BYTES_MAX, 64);
    assert_eq!(compat::CRYPTO_HASH_SHA256_BYTES, 32);
    assert_eq!(compat::CRYPTO_HASH_SHA512_BYTES, 64);
    assert_eq!(compat::CRYPTO_SIGN_BYTES, 64);
    assert_eq!(compat::CRYPTO_SIGN_PUBLICKEYBYTES, 32);
    assert_eq!(compat::CRYPTO_SIGN_SECRETKEYBYTES, 64);
    assert_eq!(compat::CRYPTO_BOX_PUBLICKEYBYTES, 32);
    assert_eq!(compat::CRYPTO_BOX_SECRETKEYBYTES, 32);
    assert_eq!(compat::CRYPTO_BOX_SEALBYTES, 48);
}

#[test]
fn libsodium_style_ed25519_roundtrip() {
    let (pk, sk) = compat::crypto_sign_keypair().unwrap();
    assert_eq!(pk.len(), compat::CRYPTO_SIGN_PUBLICKEYBYTES);
    assert_eq!(sk.len(), compat::CRYPTO_SIGN_SECRETKEYBYTES);
    let message = b"libsodium-compat path";
    let sig = compat::crypto_sign_detached(message, &sk).unwrap();
    assert_eq!(sig.len(), compat::CRYPTO_SIGN_BYTES);
    assert!(compat::crypto_sign_verify_detached(&sig, message, &pk));
}

#[test]
fn randombytes_buf_fills_and_does_not_zero() {
    let mut buf = [0u8; 32];
    rng::randombytes_buf(&mut buf).unwrap();
    assert_ne!(buf, [0u8; 32], "randombytes_buf must overwrite buffer");
}

#[test]
fn randombytes_uniform_respects_upper_bound() {
    for _ in 0..32 {
        let x = rng::randombytes_uniform(7);
        assert!(x < 7);
    }
    // Edge case: upper_bound 0 → 0
    assert_eq!(rng::randombytes_uniform(0), 0);
    assert_eq!(rng::randombytes_uniform(1), 0);
}
