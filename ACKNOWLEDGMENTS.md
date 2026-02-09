# Acknowledgements

This project includes internal implementations and adaptations informed by public specifications and battle-tested open-source references.

- **[Monocypher](https://github.com/LoupVaillant/Monocypher)** - Loup Vaillant wrote crypto code so clean it makes you question everything you've ever committed. The field arithmetic, the scalar operations, the curve gymnastics - when you need X25519 and Ed25519 done right, you study this. Some of that wisdom lives here now.

- **[digestpp](https://github.com/kerukuro/digestpp)** - A C++11 header-only hash library that just works. SHA-256, SHA-512, BLAKE2b, and more exotic specimens. No dependencies, no drama, no "please install OpenSSL first." The hash implementations tip their hat.

- **[plusaes](https://github.com/kkAyataka/plusaes)** - AES-GCM in a single header. ECB, CBC, CTR, GCM - pick your mode, include the file, done. When you need symmetric encryption without the baggage, this delivers.

- **[RFC 8017](https://www.rfc-editor.org/rfc/rfc8017)** - RSA PKCS#1 v1.5 and PSS encoding/verification requirements.

- **[RFC 6979](https://www.rfc-editor.org/rfc/rfc6979)** - Deterministic nonce derivation for ECDSA.

- **[FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final)** - Digital signature standard guidance.

- **[Project Wycheproof](https://github.com/C2SP/wycheproof)** - Negative and malformed signature test-case patterns used for robustness testing.

We acknowledge the original authors and standards bodies that made these implementations and tests possible.
