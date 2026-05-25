//! AEAD known-answer vectors.

use keylock::crypto::{aead_aes256gcm, aead_chacha20poly1305_ietf, aead_xchacha20poly1305_ietf};

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

// ChaCha20-Poly1305 IETF RFC 8439 §2.8.2 KAT
#[test]
fn chacha20_poly1305_ietf_rfc8439_test_vector() {
    let key = hex_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce = hex_bytes("070000004041424344454647");
    let aad = hex_bytes("50515253c0c1c2c3c4c5c6c7");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    let expected_ct = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
    let expected_tag = "1ae10b594f09e26a7e902ecbd0600691";

    let detached = aead_chacha20poly1305_ietf::encrypt_detached(plaintext, &key, &aad, &nonce);
    assert!(detached.success, "{}", detached.error);
    assert_eq!(hex(&detached.ciphertext), expected_ct);
    assert_eq!(hex(&detached.mac), expected_tag);

    let decrypted = aead_chacha20poly1305_ietf::decrypt_detached(
        &detached.ciphertext,
        &detached.mac,
        &key,
        &aad,
        &nonce,
    );
    assert!(decrypted.success);
    assert_eq!(decrypted.data, plaintext);
}

// XChaCha20-Poly1305 round-trip with libsodium-style nonce length (24 bytes).
#[test]
fn xchacha20_poly1305_round_trip_with_24_byte_nonce() {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 24];
    let aad = b"keylock";
    let plaintext = b"24-byte nonce path";
    let result = aead_xchacha20poly1305_ietf::encrypt_detached(plaintext, &key, aad, &nonce);
    assert!(result.success);
    let opened = aead_xchacha20poly1305_ietf::decrypt_detached(
        &result.ciphertext,
        &result.mac,
        &key,
        aad,
        &nonce,
    );
    assert!(opened.success);
    assert_eq!(opened.data, plaintext);
}

// AES-256-GCM NIST CAVP test vector (gcmEncryptExtIV256.rsp, count 0)
#[test]
fn aes256_gcm_nist_cavp_test_vector() {
    let key = hex_bytes("b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4");
    let iv = hex_bytes("516c33929df5a3284ff463d7");
    let plaintext: Vec<u8> = Vec::new();
    let aad: Vec<u8> = Vec::new();
    let expected_tag = "bdc1ac884d332457a1d2664f168c76f0";

    let result = aead_aes256gcm::encrypt_detached(&plaintext, &key, &aad, &iv);
    assert!(result.success, "{}", result.error);
    assert!(result.ciphertext.is_empty());
    assert_eq!(hex(&result.mac), expected_tag);
}

// AEAD modifications must fail to authenticate.
#[test]
fn aead_modified_ciphertext_fails_authentication() {
    let key = [0x33u8; aead_chacha20poly1305_ietf::KEYBYTES];
    let nonce = [0x44u8; aead_chacha20poly1305_ietf::NPUBBYTES];
    let aad = b"";
    let plaintext = b"secret payload";
    let result = aead_chacha20poly1305_ietf::encrypt_with_nonce(plaintext, &key, aad, &nonce);
    assert!(result.success);
    let mut tampered = result.data.clone();
    tampered[0] ^= 0x01;
    let opened = aead_chacha20poly1305_ietf::decrypt_with_nonce(&tampered, &key, aad, &nonce);
    assert!(!opened.success);
}

#[test]
fn aead_wrong_aad_fails_authentication() {
    let key = [0x55u8; aead_chacha20poly1305_ietf::KEYBYTES];
    let nonce = [0x66u8; aead_chacha20poly1305_ietf::NPUBBYTES];
    let result =
        aead_chacha20poly1305_ietf::encrypt_with_nonce(b"payload", &key, b"original AAD", &nonce);
    assert!(result.success);
    let opened = aead_chacha20poly1305_ietf::decrypt_with_nonce(
        &result.data,
        &key,
        b"different AAD",
        &nonce,
    );
    assert!(!opened.success);
}
