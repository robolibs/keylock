use keylock::crypto::{
    aead_aes256gcm, aead_chacha20poly1305_ietf, aead_xchacha20poly1305_ietf, aes, chacha20,
    constant_time, poly1305, secretbox_xsalsa20poly1305,
};

fn hex(input: &str) -> Vec<u8> {
    assert!(input.len().is_multiple_of(2));
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).unwrap();
            let low = (pair[1] as char).to_digit(16).unwrap();
            ((high << 4) | low) as u8
        })
        .collect()
}

#[test]
fn aes_block_uses_standard_fips197_vector() {
    let key = hex("000102030405060708090a0b0c0d0e0f");
    let plaintext = hex("00112233445566778899aabbccddeeff");
    let expected = hex("69c4e0d86a7b0430d8cdb78070b4c55a");

    let ctx = aes::init(&key);
    let encrypted = aes::encrypt_block(&ctx, &plaintext);
    assert_eq!(encrypted, expected);
    assert_eq!(aes::decrypt_block(&ctx, &encrypted), plaintext);
}

#[test]
fn aes_ctr_and_cbc_roundtrip_stays_in_keylock() {
    let key = [0x42; aes::KEY_SIZE_256];
    let nonce = [0x24; aes::BLOCK_SIZE];
    let plaintext = b"thirty two byte plaintext block!";

    let ctx = aes::init(&key);
    let ctr = aes::ctr_crypt(&ctx, &nonce, plaintext);
    assert_ne!(ctr, plaintext);
    assert_eq!(aes::ctr_crypt(&ctx, &nonce, &ctr), plaintext);

    let cbc = aes::cbc_encrypt(&ctx, &nonce, plaintext);
    assert_ne!(cbc, plaintext);
    assert_eq!(aes::cbc_decrypt(&ctx, &nonce, &cbc), plaintext);
}

#[test]
fn aead_modules_cover_explicit_nonce_and_detached_shapes() {
    let plaintext = b"keylock keeps crypto over here";
    let aad = b"did-pki-json stay outside keylock";

    let aes_key = [0x11; aead_aes256gcm::KEYBYTES];
    let aes_nonce = [0x22; aead_aes256gcm::NPUBBYTES];
    let aes_ciphertext = aead_aes256gcm::encrypt_with_nonce(plaintext, &aes_key, aad, &aes_nonce);
    assert!(aes_ciphertext.success, "{}", aes_ciphertext.error_message);
    let aes_plain =
        aead_aes256gcm::decrypt_with_nonce(&aes_ciphertext.data, &aes_key, aad, &aes_nonce);
    assert_eq!(aes_plain.data, plaintext);
    let aes_detached = aead_aes256gcm::encrypt_detached(plaintext, &aes_key, aad, &aes_nonce);
    assert!(aes_detached.success, "{}", aes_detached.error);
    assert_eq!(
        aead_aes256gcm::decrypt_detached(
            &aes_detached.ciphertext,
            &aes_detached.mac,
            &aes_key,
            aad,
            &aes_nonce,
        )
        .data,
        plaintext
    );

    let chacha_key = [0x33; aead_chacha20poly1305_ietf::KEYBYTES];
    let chacha_nonce = [0x44; aead_chacha20poly1305_ietf::NPUBBYTES];
    let chacha_ciphertext =
        aead_chacha20poly1305_ietf::encrypt_with_nonce(plaintext, &chacha_key, aad, &chacha_nonce);
    assert!(
        chacha_ciphertext.success,
        "{}",
        chacha_ciphertext.error_message
    );
    assert_eq!(
        aead_chacha20poly1305_ietf::decrypt_with_nonce(
            &chacha_ciphertext.data,
            &chacha_key,
            aad,
            &chacha_nonce,
        )
        .data,
        plaintext
    );

    let x_key = [0x55; aead_xchacha20poly1305_ietf::KEYBYTES];
    let x_nonce = [0x66; aead_xchacha20poly1305_ietf::NPUBBYTES];
    let x_detached =
        aead_xchacha20poly1305_ietf::encrypt_detached(plaintext, &x_key, aad, &x_nonce);
    assert!(x_detached.success, "{}", x_detached.error);
    assert_eq!(
        aead_xchacha20poly1305_ietf::decrypt_detached(
            &x_detached.ciphertext,
            &x_detached.mac,
            &x_key,
            aad,
            &x_nonce,
        )
        .data,
        plaintext
    );
}

#[test]
fn stream_cipher_and_secretbox_roundtrip() {
    let key = [0x17; chacha20::KEYBYTES];
    let djb_nonce = [0x23; chacha20::NONCEBYTES_DJB];
    let ietf_nonce = [0x42; chacha20::NONCEBYTES_IETF];
    let x_nonce = [0x99; chacha20::NONCEBYTES_XCHACHA20];
    let plaintext = b"stream cipher boundary test";

    let djb_ciphertext =
        chacha20::chacha20_djb(Some(plaintext), plaintext.len(), &key, &djb_nonce, 7);
    assert_eq!(
        chacha20::chacha20_djb(
            Some(&djb_ciphertext),
            djb_ciphertext.len(),
            &key,
            &djb_nonce,
            7
        ),
        plaintext
    );

    let ietf_ciphertext =
        chacha20::chacha20_ietf(Some(plaintext), plaintext.len(), &key, &ietf_nonce, 9);
    assert_eq!(
        chacha20::chacha20_ietf(
            Some(&ietf_ciphertext),
            ietf_ciphertext.len(),
            &key,
            &ietf_nonce,
            9,
        ),
        plaintext
    );

    assert_eq!(
        chacha20::hchacha20(&key, &[0x55; 16]).len(),
        chacha20::KEYBYTES
    );

    let x_ciphertext = chacha20::xchacha20(Some(plaintext), plaintext.len(), &key, &x_nonce, 3);
    assert_eq!(
        chacha20::xchacha20(Some(&x_ciphertext), x_ciphertext.len(), &key, &x_nonce, 3),
        plaintext
    );

    let boxed = secretbox_xsalsa20poly1305::encrypt(plaintext, &key);
    assert!(boxed.success, "{}", boxed.error_message);
    assert_eq!(
        secretbox_xsalsa20poly1305::decrypt(&boxed.data, &key).data,
        plaintext
    );
}

#[test]
fn poly1305_matches_rfc8439_vector_and_incremental_api() {
    let key = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    let message = b"Cryptographic Forum Research Group";
    let expected = hex("a8061dc1305136c6c22b8baf0c0127a9");

    assert_eq!(poly1305::authenticate(message, &key), expected);

    let mut ctx = poly1305::init(&key);
    poly1305::update(&mut ctx, b"Cryptographic Forum ");
    poly1305::update(&mut ctx, b"Research Group");
    assert_eq!(poly1305::final_bytes(&ctx), expected);
}

#[test]
fn constant_time_verify_and_wipe_surfaces_work() {
    let left32 = [7u8; 32];
    let right32 = [7u8; 32];
    let different32 = [8u8; 32];
    assert_eq!(constant_time::verify::verify32(&left32, &right32), 0);
    assert_eq!(constant_time::verify::verify32(&left32, &different32), -1);
    assert!(constant_time::verify::secure_compare(&left32, &right32));
    assert!(!constant_time::verify::secure_compare(
        &left32,
        &different32
    ));

    let mut secret = [0x5a; 64];
    constant_time::wipe::wipe_container(&mut secret);
    assert_eq!(secret, [0; 64]);
}
