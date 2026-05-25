use keylock::hash::{blake2x, legacy, skein};
use keylock::kdf::argon2 as kargon2;

#[test]
fn argon2id_derive_returns_requested_length() {
    let key = kargon2::derive(
        b"correct horse battery staple",
        b"keylock-salt-1234",
        kargon2::Config {
            algorithm: kargon2::Algorithm::Argon2id,
            nb_blocks: 256,
            nb_passes: 1,
            nb_lanes: 1,
        },
        32,
    )
    .expect("Argon2id derivation succeeds");
    assert_eq!(key.len(), 32);

    let key2 = kargon2::derive(
        b"correct horse battery staple",
        b"keylock-salt-1234",
        kargon2::Config {
            algorithm: kargon2::Algorithm::Argon2id,
            nb_blocks: 256,
            nb_passes: 1,
            nb_lanes: 1,
        },
        32,
    )
    .expect("Argon2id derivation succeeds");
    assert_eq!(
        key, key2,
        "Argon2id output must be deterministic for fixed inputs"
    );
}

#[test]
fn blake2xb_xof_supports_variable_output_lengths() {
    let short = blake2x::xof(b"keylock blake2x test", 16).unwrap();
    let medium = blake2x::xof(b"keylock blake2x test", 64).unwrap();
    let long = blake2x::xof(b"keylock blake2x test", 200).unwrap();
    assert_eq!(short.len(), 16);
    assert_eq!(medium.len(), 64);
    assert_eq!(long.len(), 200);
    // Different output lengths derive distinct domains.
    assert_ne!(short, medium[..16]);
}

#[test]
fn skein_streebog_whirlpool_sm3_produce_expected_sizes() {
    let data = b"keylock legacy hash coverage";

    assert_eq!(skein::hash_256(data).len(), skein::BYTES_256);
    assert_eq!(skein::hash_512(data).len(), skein::BYTES_512);

    assert_eq!(legacy::sm3::hash(data).len(), legacy::sm3::BYTES);
    assert_eq!(
        legacy::streebog::hash_256(data).len(),
        legacy::streebog::BYTES_256
    );
    assert_eq!(
        legacy::streebog::hash_512(data).len(),
        legacy::streebog::BYTES_512
    );
    assert_eq!(
        legacy::whirlpool::hash(data).len(),
        legacy::whirlpool::BYTES
    );
}

#[test]
fn whirlpool_matches_known_empty_string_vector() {
    // Reference output for Whirlpool("") (a well-known test vector).
    let expected = "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3";
    let computed: String = legacy::whirlpool::hash(b"")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(computed, expected);
}

#[test]
fn sm3_matches_known_abc_vector() {
    let expected = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
    let computed: String = legacy::sm3::hash(b"abc")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(computed, expected);
}
