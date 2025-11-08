# Changelog

## [0.2.0] - 2025-06-12

### <!-- 0 -->⛰️  Features

- Migrate Lockey to libsodium-only primitives (XChaCha20, SecretBox, X25519, Ed25519, SHA-256/SHA-512/BLAKE2b)
- Remove legacy RSA/ECDSA/AES engines along with every OpenSSL comparison helper
- Add authenticated key-exchange envelopes for file/shared-memory transport
- Add examples comparing Lockey with OpenSSL chains
- Implement support for elliptic curve cryptography
- Feat: Add BLAKE2b hash and improve crypto tests
- Refine and standardize deterministic cryptography functions
- Add asymmetric encryption key persistence
- Add unit tests
- Of build system or dependencies.
- Reinit
- Reinit
- Add cryptographic algorithms and demos
- Implement common cryptographic hashing algorithms
- Add key I/O example
- Feat: Add universal cryptographic support to Lockey
- Feat(crypto): Implement RSA encryption and signing
- Init
- Init

### <!-- 2 -->🚜 Refactor

- Remove unused simple RSA implementation usage
- Refactor crypto implementation details
- Replace internal crypto header
- Consolidate lockey and simplify testing examples

### <!-- 3 -->📚 Documentation

- Rewrite README to describe the libsodium-only surface and updated examples
- Document the new envelope-based key exchange helpers
- Update README with comprehensive library documentation
- Add comprehensive README documentation

### <!-- 7 -->⚙️ Miscellaneous Tasks

- Ignore unused files created during testing

### Build

- Set up build system infrastructure
