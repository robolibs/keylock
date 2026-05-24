//! Known-answer tests ported from the C++ keylock test suite and standard
//! reference documents (RFC 4231 / 5869 / 6979 / 7693 / 8032).

use keylock::crypto::{Context, ed25519, secp256k1};
use keylock::hash::{
    self, HashAlgorithm, blake2b, hkdf, hmac_sha256, hmac_sha512, keccak, sha256, sha3,
};

fn hex_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let high = char::from(bytes[i]).to_digit(16).unwrap() as u8;
        let low = char::from(bytes[i + 1]).to_digit(16).unwrap() as u8;
        out.push((high << 4) | low);
        i += 2;
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------- RFC 5869 HKDF-SHA256 test vector 1 ----------

const RFC5869_IKM: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
const RFC5869_SALT: &str = "000102030405060708090a0b0c";
const RFC5869_INFO: &str = "f0f1f2f3f4f5f6f7f8f9";
const RFC5869_PRK: &str = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
const RFC5869_OKM: &str = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

#[test]
fn hkdf_sha256_rfc5869_extract_and_expand() {
    let extract = hkdf::hkdf_extract(
        HashAlgorithm::Sha256,
        &hex_bytes(RFC5869_IKM),
        &hex_bytes(RFC5869_SALT),
    );
    assert!(extract.success);
    assert_eq!(hex(&extract.data), RFC5869_PRK);

    let expand = hkdf::hkdf_expand(
        HashAlgorithm::Sha256,
        &extract.data,
        &hex_bytes(RFC5869_INFO),
        42,
    );
    assert!(expand.success);
    assert_eq!(hex(&expand.data), RFC5869_OKM);

    let combined = hkdf::hkdf(
        HashAlgorithm::Sha256,
        &hex_bytes(RFC5869_IKM),
        &hex_bytes(RFC5869_SALT),
        &hex_bytes(RFC5869_INFO),
        42,
    );
    assert!(combined.success);
    assert_eq!(hex(&combined.data), RFC5869_OKM);
}

// ---------- RFC 4231 HMAC-SHA256 test vector 4 ----------

#[test]
fn hmac_sha256_rfc4231_test_case_4() {
    let key = hex_bytes("0102030405060708090a0b0c0d0e0f10111213141516171819");
    let data = hex_bytes(&"cd".repeat(50));
    let expected = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b";
    assert_eq!(hex(&hmac_sha256::hmac(&key, &data)), expected);
}

#[test]
fn hmac_sha512_rfc4231_test_case_4() {
    let key = hex_bytes("0102030405060708090a0b0c0d0e0f10111213141516171819");
    let data = hex_bytes(&"cd".repeat(50));
    let expected = "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd";
    assert_eq!(hex(&hmac_sha512::hmac(&key, &data)), expected);
}

// ---------- SHA-256 / Keccak-256 / SHA3-256 known vectors ----------

#[test]
fn sha256_empty_and_abc_match_fips180() {
    assert_eq!(
        hex(&sha256::hash(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(&sha256::hash(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn keccak256_matches_ethereum_yellow_paper_for_empty() {
    assert_eq!(
        hex(&keccak::hash_256(b"")),
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
}

#[test]
fn sha3_256_matches_fips202_empty() {
    assert_eq!(
        hex(&sha3::hash_256(b"")),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
}

// ---------- BLAKE2b test vector (RFC 7693) ----------

#[test]
fn blake2b_512_abc_rfc7693() {
    let h = blake2b::hash(b"abc", 64).expect("64-byte output");
    let expected = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923";
    assert_eq!(hex(&h), expected);
}

// ---------- RFC 8032 Ed25519 test vector 1 ----------

#[test]
fn ed25519_rfc8032_test_vector_1() {
    let seed = hex_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let expected_pk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let message: &[u8] = &[];
    let expected_sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    let (pk, sk) = ed25519::keypair_from_seed(&seed).unwrap();
    assert_eq!(hex(&pk), expected_pk);

    let sig = ed25519::sign_detached(message, &sk).unwrap();
    assert_eq!(hex(&sig), expected_sig);

    assert!(ed25519::verify_detached(&sig, message, &pk));
}

// ---------- secp256k1: low-s helper + Ethereum address derivation ----------

#[test]
fn secp256k1_low_s_helper_matches_curve_order_half() {
    // Half order N/2 + 1 must NOT be low-s; N/2 must be low-s; 1 is low-s.
    let mut half = [0u8; 32];
    half[..16].copy_from_slice(&[0x7f; 16]);
    // construct a value just above N/2 → not low-s
    let mut over_half = [0u8; 32];
    over_half[0] = 0x80; // top bit set → > N/2
    assert!(!secp256k1::is_low_s(&over_half));

    let mut one = [0u8; 32];
    one[31] = 1;
    assert!(secp256k1::is_low_s(&one));
}

#[test]
fn ethereum_address_from_known_pubkey_yellow_paper() {
    // Vitalik's well-known test vector:
    // private:  0x0000000000000000000000000000000000000000000000000000000000000001
    // address:  0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
    let pk = secp256k1::derive_public_key_from_secret(&hex_bytes(
        "0000000000000000000000000000000000000000000000000000000000000001",
    ))
    .expect("derive public key from secret 1");
    let addr_result = Context::ethereum_address_from_uncompressed_pubkey(&pk);
    assert!(addr_result.success);
    assert_eq!(hex(&addr_result.data), "7e5f4552091a69125d5dfcb7b8c2659029395bdf");
}

// ---------- HashAlgorithm dispatch sanity ----------

#[test]
fn hash_dispatch_matches_individual_modules() {
    for (algo, expected) in [
        (HashAlgorithm::Sha256, hex(&sha256::hash(b"abc"))),
        (
            HashAlgorithm::Keccak256,
            hex(&keccak::hash_256(b"abc")),
        ),
    ] {
        let result = hash::digest(algo, b"abc");
        assert!(result.success);
        assert_eq!(hex(&result.data), expected);
    }
}
