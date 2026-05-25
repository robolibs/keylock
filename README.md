# keylock

A pure-Rust port of the C++ [`robolibs_cpp/keylock`](https://github.com/robolibs/keylock)
library: a one-stop crypto compatibility surface covering symmetric AEADs,
asymmetric signatures and encryption, hashes, KDFs, and Ethereum-style
secp256k1 helpers.

Every primitive is delegated to a well-reviewed Rust crate (RustCrypto,
`dalek-cryptography`, etc.); keylock is the thin shell that mirrors the
C++ public API — same module hierarchy, same enum names, same blob
layouts, same error-message shapes — so callers can move between the two
implementations byte-for-byte.

The sibling [`authbox`](../authbox) crate (PKI + DID toolkit) consumes
keylock for **every** cryptographic primitive — keygen, sign, verify, hash,
AEAD. If a project needs primitives it pulls keylock; if it needs X.509 /
DID framing it pulls authbox.

## At a glance

- **Status:** 101 tests passing, clippy clean
- **MSRV:** Rust 1.85 (uses edition 2024)
- **License:** MIT

## Algorithms

| Category | Algorithms |
|----------|------------|
| AEAD | XChaCha20-Poly1305, ChaCha20-Poly1305 IETF, AES-256-GCM, SecretBox (XSalsa20-Poly1305) |
| Block / stream | AES (block, CTR, CBC), ChaCha20, Poly1305 |
| Signatures | Ed25519, Ed448, ECDSA P-256 (RFC6979), ECDSA P-384, ECDSA P-521, ECDSA secp256k1 compact + recovery, RSA-PKCS1v1.5, RSA-PSS — SHA-256 / 384 / 512 each |
| Asymmetric encryption | X25519 sealed box, RSA-OAEP (SHA-256 / 384 / 512) |
| Hashes | SHA-256, SHA-384, SHA-512, SHA-3, Keccak-256, BLAKE2b, BLAKE2s, BLAKE2xb XOF, SHAKE, KMAC, Skein-512, SM3, Streebog, Whirlpool |
| MAC / KDF | HMAC (SHA-2 + BLAKE2b), HKDF (SHA-256 / 384 / 512), Argon2d / Argon2i / Argon2id |
| Ethereum helpers | secp256k1 public-key recovery, low-s helper, recovery-id normalisation, `keccak256`, address derivation |
| Misc | Elligator2 forward / reverse maps for Curve25519 |

## Quick start

```toml
[dependencies]
keylock = { path = "../keylock" }
```

### Generate keypairs

The ergonomic top-level helpers cover every asymmetric algorithm. They all
return [`keylock::KeyPair`] (`{ public_key, private_key, algorithm }`).

```rust
let ed25519 = keylock::generate_ed25519_keypair()?;
let ed448   = keylock::generate_ed448_keypair()?;
let p256    = keylock::generate_ecdsa_p256_keypair()?;
let p384    = keylock::generate_ecdsa_p384_keypair()?;
let p521    = keylock::generate_ecdsa_p521_keypair()?;
let k1      = keylock::generate_ecdsa_secp256k1_keypair()?;
let x25519  = keylock::generate_x25519_keypair()?;
let rsa     = keylock::generate_rsa_keypair()?;                 // 2048-bit
let rsa3072 = keylock::generate_rsa_keypair_with_bits(3072)?;
```

For full algorithm dispatch (sign / verify / encrypt / decrypt / file I/O)
use the [`Context`] surface.

### Encrypt and decrypt with an AEAD

```rust
use keylock::{Algorithm, crypto::Context};

let ctx = Context::new(Algorithm::XChaCha20_Poly1305);
let key = ctx.generate_symmetric_key(32);
assert!(key.success);

let ciphertext = ctx.encrypt(b"hello", &key.data);
let plaintext = ctx.decrypt(&ciphertext.data, &key.data);
assert_eq!(plaintext.data, b"hello");
```

### Sign and verify

```rust
use keylock::{Algorithm, crypto::Context};

let ctx = Context::new(Algorithm::Ed25519);
let pair = ctx.generate_keypair().unwrap();
let sig = ctx.sign(b"keylock", &pair.private_key);
let ok = ctx.verify(b"keylock", &sig.data, &pair.public_key);
assert!(ok.success);
```

### Hash convenience

```rust
let digest = keylock::keccak256(b"hello, web3");        // [u8; 32]
let sha256 = keylock::hash::sha256::hash(b"message");   // Vec<u8>
let sha384 = keylock::hash::sha384::hash(b"message");   // Vec<u8>
let blake  = keylock::hash::blake2b::hash(b"message", 32).unwrap();
```

### Ethereum: recover a public key from a signature

```rust
use keylock::crypto::{Context, secp256k1};
use keylock::hash::sha256;

let pair = secp256k1::generate_keypair().unwrap();
let message = b"hello, web3";
let signature = secp256k1::sign(message, &pair.private_key);
let digest = sha256::hash(message);

let recovered = Context::recover_secp256k1_public_key(
    &digest,
    &signature.data[..64],
    signature.data[64],
);
assert_eq!(recovered.public_key_uncompressed, pair.public_key);

let address = Context::ethereum_address_from_uncompressed_pubkey(&pair.public_key);
assert_eq!(address.data.len(), 20);
```

### RSA-OAEP

```rust
use keylock::{Algorithm, crypto::Context};

let ctx = Context::new(Algorithm::RSA_OAEP_SHA256);
let pair = ctx.generate_keypair().unwrap();
let ct = ctx.encrypt_asymmetric(b"secret", &pair.public_key);
let pt = ctx.decrypt_asymmetric(&ct.data, &pair.private_key);
assert_eq!(pt.data, b"secret");
```

### Argon2 with pepper + associated data

```rust
use keylock::kdf::argon2;

let key = argon2::derive_with_extras(
    b"correct horse battery staple",
    b"unique salt here",
    b"server-side pepper",
    b"associated data",
    argon2::Config {
        algorithm: argon2::Algorithm::Argon2id,
        nb_blocks: 19_456,
        nb_passes: 2,
        nb_lanes: 1,
    },
    32,
)
.unwrap();
```

### Read / write PEM and DER

```rust
use keylock::{Algorithm, KeyFormat, KeyType, crypto::Context};

let ctx = Context::new(Algorithm::Ed25519);
let pair = ctx.generate_keypair().unwrap();

ctx.save_key_to_file(&pair.public_key, "pub.pem", KeyType::PUBLIC, KeyFormat::Pem);
let loaded = ctx.load_key_from_file("pub.pem", KeyType::PUBLIC); // auto-detects PEM/DER/raw
assert_eq!(loaded.data, pair.public_key);
```

## Module map

```
keylock
├── (top-level)                 — generate_*_keypair helpers + keccak256
├── crypto
│   ├── Context                 — dispatcher matching keylock-cpp::Context
│   ├── aead_aes256gcm          — AES-256-GCM
│   ├── aead_chacha20poly1305_ietf
│   ├── aead_xchacha20poly1305_ietf
│   ├── aes                     — block / CTR / CBC primitives
│   ├── box_seal_x25519         — anonymous sealed box (libsodium-shaped)
│   ├── chacha20                — DJB / IETF / X variants
│   ├── constant_time           — wipe + verify
│   ├── ecdsa_p256              — sign / verify / DER
│   ├── ecdsa_p384              — sign / verify / DER
│   ├── ecdsa_p521              — sign / verify / DER
│   ├── ed25519
│   ├── ed448
│   ├── elligator               — Elligator2 for Curve25519
│   ├── poly1305
│   ├── rng                     — randombytes_buf / randombytes_uniform
│   ├── rsa                     — keygen / PKCS1v1.5 / PSS / OAEP / PKCS#1 DER
│   ├── secp256k1               — sign / verify / recover / low-s / address
│   └── secretbox_xsalsa20poly1305
├── hash
│   ├── blake2b / blake2s / blake2x (XOF)
│   ├── generichash / hkdf / hmac
│   ├── keccak / kmac / shake
│   ├── sha256 / sha384 / sha512 / sha3
│   ├── skein
│   └── legacy/                 — sm3, streebog, whirlpool
├── kdf
│   └── argon2                  — Argon2d / Argon2i / Argon2id
└── compat                      — libsodium-style constants + wrappers
```

## API parity with `robolibs_cpp/keylock`

- The `Algorithm` enum entries are reproduced verbatim, including both
  the modern `EcdsaSecp256k1Compact` and the C++-style alias
  `ECDSA_SECP256K1_COMPACT`. P-384 / P-521 / Ed448 are added as
  `EcdsaP384Sha384` / `EcdsaP521Sha512` / `Ed448` to extend the surface
  needed by the sibling `authbox` crate.
- `Context::algorithm_to_string` returns the exact strings the C++ port
  uses (e.g. `"ECDSA-secp256k1-compact"`, `"RSA-PKCS1v1.5-SHA256"`,
  `"ChaCha20-Poly1305-IETF"`).
- RSA private-key blob format: `n‖e‖d` (short) or `n‖e‖d‖p‖q‖dp‖dq‖qinv`
  (extended) — both decode; extended round-trips through PKCS#1 DER.
- X25519 sealed-box wire format matches the keylock-cpp choice:
  `ephemeral_pk(32) ‖ ciphertext ‖ tag(16)` with key/nonce derived as
  `BLAKE2b-256(shared‖epk‖rpk)` / `BLAKE2b-192(epk‖rpk)`, using
  XChaCha20-Poly1305 as the cipher.
- DER/SPKI/PKCS#8 frames for Ed25519, ECDSA P-256, RSA PKCS#1 — all
  byte-compatible with the C++ static encode/decode methods.
- `compat::*` exposes the libsodium-style names
  (`CRYPTO_SIGN_PUBLICKEYBYTES`, `crypto_sign_detached`, etc.) the C++ port
  forwards from `compat_constants.hpp`.

## Test coverage

```
$ cargo test --release
   running 101 tests across 16 test files
   test result: ok. 101 passed; 0 failed
```

Vectors include:

- **FIPS 197** AES-128 / 256 block KATs
- **FIPS 180-4** SHA-256 / SHA-512 KATs
- **FIPS 202** SHA3-512, SHAKE128, SHAKE256
- **NIST SP 800-38A** AES-256-CTR / CBC
- **NIST CAVP** AES-256-GCM
- **NIST** KMAC128 / KMAC256
- **RFC 4231** HMAC-SHA-256 / 384 / 512
- **RFC 5869** HKDF-SHA-256 vectors 1 & 2
- **RFC 7693** BLAKE2b / BLAKE2s
- **RFC 8032** Ed25519 vectors 1, 2, 3
- **RFC 8439** ChaCha20-Poly1305 ("sunscreen") with full ciphertext + tag
- **RFC 9106** Argon2d / Argon2i / Argon2id all three §5 KATs
- **secp256k1** generator-point cross-check (k=1 → 04‖Gx‖Gy)
- **Ethereum yellow paper** Keccak-256 empty + Vitalik address vector

## Acknowledgments

Every external crate is listed in [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md),
including references for the framing code keylock owns directly
(sealed-box KDF, Elligator2, DER/SPKI/PKCS#8 layouts, Ethereum helpers).

## License

MIT.
