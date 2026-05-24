# Acknowledgments

`keylock` (Rust) is a port of the C++ `robolibs_cpp/keylock` library that
mirrors its public API (algorithms, namespaces, enum values, blob layouts,
error-message shapes). Whenever a primitive already exists as a well-reviewed
Rust crate, we delegate to it rather than re-implementing the algorithm. The
keylock layer is the thin compatibility shell that translates between the C++
shape and the underlying crate.

This file lists every external project we lean on, plus the source of any
algorithm description that informed our framing code (parameter packing,
KDF inputs, serialization layouts, etc.).

---

## Upstream C++ project

* [`robolibs_cpp/keylock`](https://github.com/robolibs/keylock) — the C++
  library whose public API we mirror byte-for-byte. Algorithm choices,
  blob layouts, error-message conventions and module hierarchy are all
  reproduced from there.

## RustCrypto crates

Maintained by the [RustCrypto](https://github.com/RustCrypto) organization
(MIT or Apache-2.0). These crates provide the actual cryptographic primitives
behind every algorithm we expose:

| Primitive                            | Crate                                                                                       |
|--------------------------------------|---------------------------------------------------------------------------------------------|
| AES (block, CTR, CBC)                | [`aes`](https://crates.io/crates/aes)                                                       |
| AES-GCM (AEAD)                       | [`aes-gcm`](https://crates.io/crates/aes-gcm)                                               |
| Argon2 KDF                           | [`argon2`](https://crates.io/crates/argon2)                                                 |
| BLAKE2b / BLAKE2s / BLAKE2bMac       | [`blake2`](https://crates.io/crates/blake2)                                                 |
| ChaCha20 stream cipher               | [`chacha20`](https://crates.io/crates/chacha20)                                             |
| ChaCha20-Poly1305 / XChaCha20-Poly1305 | [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305)                           |
| SecretBox (XSalsa20-Poly1305)        | [`crypto_secretbox`](https://crates.io/crates/crypto_secretbox)                             |
| Constant-time primitives             | [`subtle`](https://crates.io/crates/subtle)                                                 |
| HKDF                                 | [`hkdf`](https://crates.io/crates/hkdf)                                                     |
| HMAC                                 | [`hmac`](https://crates.io/crates/hmac)                                                     |
| Poly1305 MAC                         | [`poly1305`](https://crates.io/crates/poly1305)                                             |
| SHA-2 (SHA-256/384/512)              | [`sha2`](https://crates.io/crates/sha2)                                                     |
| SHA-3 / Keccak / SHAKE / KMAC        | [`sha3`](https://crates.io/crates/sha3)                                                     |
| secp256k1 ECDSA                      | [`k256`](https://crates.io/crates/k256)                                                     |
| NIST P-256 ECDSA                     | [`p256`](https://crates.io/crates/p256)                                                     |
| RSA (keygen, PKCS#1 v1.5, PSS, OAEP) | [`rsa`](https://crates.io/crates/rsa)                                                       |
| PKCS#8 / SPKI helpers                | [`pkcs8`](https://crates.io/crates/pkcs8)                                                   |
| SM3 (GM/T 0004-2012)                 | [`sm3`](https://crates.io/crates/sm3)                                                       |
| Streebog (GOST R 34.11-2012)         | [`streebog`](https://crates.io/crates/streebog)                                             |
| Skein-512                            | [`skein`](https://crates.io/crates/skein)                                                   |
| Whirlpool                            | [`whirlpool`](https://crates.io/crates/whirlpool)                                           |
| Secure memory wipes                  | [`zeroize`](https://crates.io/crates/zeroize)                                               |

## dalek-cryptography crates

Maintained by [dalek-cryptography](https://github.com/dalek-cryptography)
(BSD-3-Clause). Used for Curve25519-based primitives:

* [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) — Ed25519 sign /
  verify / keypair. Used by `keylock::crypto::ed25519`.
* [`x25519-dalek`](https://crates.io/crates/x25519-dalek) — X25519 key
  agreement. Used by `keylock::crypto::box_seal_x25519` for the sealed-box
  ephemeral DH step.

## Randomness

* [`getrandom`](https://crates.io/crates/getrandom) — OS RNG abstraction
  (MIT/Apache-2.0). Used for keypair generation, AEAD nonces, sealed-box
  ephemeral secrets.
* [`rand_core`](https://crates.io/crates/rand_core) — RNG trait surface used
  to drive the `rsa` crate's keygen.

## Big-integer arithmetic

* [`num-bigint`](https://crates.io/crates/num-bigint),
  [`num-integer`](https://crates.io/crates/num-integer),
  [`num-traits`](https://crates.io/crates/num-traits) — used by the Elligator2
  module for arithmetic in GF(2^255 - 19). Not constant-time; the C++ port
  shares the same caveat for this primitive.

## Algorithm references (for framing code we own)

A few modules contain framing / parameter-packing logic that we wrote
ourselves on top of the primitive crates. The descriptions below cite the
references we followed.

### `crypto::box_seal_x25519`

Reproduces the libsodium `crypto_box_seal` wire format, but with the cipher
swapped to XChaCha20-Poly1305 (the C++ keylock made the same swap because
it does not ship XSalsa20). The KDF inputs (`BLAKE2b-256(shared || epk ||
recipient_pk)` for key; `BLAKE2b-192(epk || recipient_pk)` for nonce) match
the C++ `box_seal_kdf` layout.

References:
* libsodium [`crypto_box_seal`](https://doc.libsodium.org/public-key_cryptography/sealed_boxes)
  reference documentation.
* `robolibs_cpp/keylock/include/keylock/crypto/box_seal_x25519/{seal,kdf}.hpp`
  for the keylock-specific key/nonce derivation and the choice of
  XChaCha20-Poly1305 over XSalsa20-Poly1305.

### `crypto::rsa` blob layout

The big-endian length-prefixed RSA key blob (`u32_be(len) || n || u32_be(len) || e [|| u32_be(len) || d]`)
matches the C++ keylock layout from `keylock/crypto/context.hpp`
(`encode_rsa_public_key_blob_raw` / `encode_rsa_private_key_blob_raw`). The
PKCS#1 DER encode/decode side is delegated to the `rsa` crate.

### `crypto::ecdsa_p256` SPKI / PKCS#8 framing

The SPKI public-key and PKCS#8 private-key DER frames mirror the static
byte arrays in the C++ context (RFC 5480 `ecPublicKey` + `prime256v1` OIDs).
References:
* RFC 5480 (Elliptic Curve Cryptography Subject Public Key Information).
* RFC 5915 (Elliptic Curve Private Key Structure).

### `crypto::ed25519` SPKI / PKCS#8 framing

The 12-byte SPKI prefix and 16-byte PKCS#8 prefix match the static byte
arrays in `keylock/crypto/context.hpp` and follow:
* RFC 8410 (Algorithm Identifiers for Ed25519 / Ed448 / X25519 / X448).

### `crypto::elligator`

Curve25519 Elligator2 forward + reverse maps. The C++ port (and Monocypher,
which it adapts from, Copyright (c) 2017-2020 Loup Vaillant, BSD-2-Clause /
CC0-1.0) implements the field arithmetic in radix 2^25.5; we instead use
`num-bigint` for clarity. The non-square is `Z = 2`, matching the C++ port,
and the masking conventions (`fe_frombytes_mask(..., 2)` for representatives,
`fe_frombytes` for u-coordinates) are preserved.

References:
* Bernstein, Hamburg, Krasnova, Lange — *Elligator: Elliptic-curve points
  indistinguishable from uniform random strings* (CCS '13).
* Monocypher `crypto_hidden_to_curve` / `crypto_curve_to_hidden`.

### `hash::blake2x`

The XOF construction follows the BLAKE2X reference design (Aumasson, Neves,
Wilcox-O'Hearn, Winnerlein, 2016). Our implementation chains
`BLAKE2bVar(output_len_le || node_offset || root)` per 32-byte output block,
which is byte-compatible with the parameter-block override technique used
in the C++ keylock `blake2xb` module.

### `hash::keccak` and `crypto::secp256k1` Ethereum helpers

`ethereum_address_from_uncompressed_pubkey` follows
[EIP-55](https://eips.ethereum.org/EIPS/eip-55) /
[Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf) §4.1:
`keccak256(pub_xy_64bytes)[12..]`. `normalize_recovery_id` accepts the
classic 27/28 plus the modern 0/1 recovery-id encodings used by EIP-155.

## Older keylock C++ acknowledgments

The C++ project bundles its own `ACKNOWLEDGMENTS.md` covering Monocypher,
plusaes, and digestpp. We deliberately do **not** vendor those projects
here — every algorithm they implement is provided by a maintained Rust
crate listed above. The original C++ acknowledgments remain authoritative
for the C++ build.

## Licensing

Each crate listed above is dual-licensed under MIT and/or Apache-2.0 and is
used unmodified through its public Cargo dependency. The keylock Rust crate
itself is MIT-licensed.
