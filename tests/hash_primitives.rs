use keylock::hash::{
    self, HashAlgorithm, blake2b, blake2s, generichash, hkdf, hmac, keccak, kmac, sha3, sha256,
    sha512, shake,
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
fn sha2_and_keccak_known_vectors_live_in_keylock() {
    assert_eq!(
        sha256::hash(b"abc"),
        hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    assert_eq!(
        sha512::hash(b"abc"),
        hex("ddaf35a193617abacc417349ae204131\
             12e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd\
             454d4423643ce80e2a9ac94fa54ca49f"
            .split_whitespace()
            .collect::<String>()
            .as_str())
    );
    assert_eq!(
        keccak::hash_256(b""),
        hex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    );
}

#[test]
fn sha3_shake_blake_helpers_are_public_keylock_tests_now() {
    assert_eq!(
        sha3::hash_256(b"abc"),
        hex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
    );
    assert_eq!(shake::shake128(b"abc", 32).len(), 32);
    assert_ne!(shake::shake128(b"abc", 32), shake::shake128(b"abcd", 32));

    assert_eq!(blake2b::generichash(b"abc").len(), 32);
    assert_eq!(blake2b::hash(b"abc", 64).unwrap().len(), blake2b::BYTES);
    assert_eq!(blake2s::hash(b"abc").len(), blake2s::BYTES);
    assert_ne!(
        blake2s::keyed(b"key", b"abc"),
        blake2s::keyed(b"key2", b"abc")
    );
    assert_eq!(generichash::generichash(b"abc").len(), generichash::BYTES);
}

#[test]
fn hmac_and_hkdf_vectors_stay_with_keylock_hash() {
    let key = vec![0x0b; 20];
    assert_eq!(
        hmac::hmac_sha256::hmac(&key, b"Hi There"),
        hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );

    let ikm = vec![0x0b; 22];
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");
    let okm = hkdf::hkdf(HashAlgorithm::Sha256, &ikm, &salt, &info, 42);
    assert!(okm.success, "{}", okm.error_message);
    assert_eq!(
        okm.data,
        hex("3cb25f25faacd57a90434f64d0362f2a\
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
            .split_whitespace()
            .collect::<String>()
            .as_str())
    );

    let unsupported = hash::hmac(HashAlgorithm::Keccak256, b"data", b"key");
    assert!(!unsupported.success);
}

#[test]
fn unified_hash_dispatch_and_kmac_are_keylock_owned() {
    assert_eq!(hash::detail::hash_output_size(HashAlgorithm::Sha384), 48);
    assert_eq!(
        hash::digest(HashAlgorithm::Sha256, b"abc").data,
        sha256::hash(b"abc")
    );
    assert_eq!(hash::keccak256(b"abc").data, keccak::hash_256(b"abc"));

    let one_shot = kmac::kmac128(b"My Tagged Application", b"", b"hello", 32);
    let mut ctx = kmac::init_128(b"My Tagged Application", b"", 32);
    kmac::update(&mut ctx, b"he");
    kmac::update(&mut ctx, b"llo");
    assert_eq!(kmac::final_bytes(&mut ctx), one_shot);
    assert_eq!(kmac::kmac256(b"k", b"custom", b"hello", 64).len(), 64);
}
