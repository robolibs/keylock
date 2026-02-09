<img align="right" width="26%" src="./misc/logo.png">

# keylock

Lightweight C++20 crypto primitives library.

## Overview

`keylock` is now crypto-only. It provides modern authenticated encryption, signatures,
hashing, KDFs, and RNG utilities with no OpenSSL dependency.

Current scope:
- Symmetric encryption: XChaCha20-Poly1305, ChaCha20-Poly1305 (IETF), AES-256-GCM, SecretBox
- Asymmetric encryption: X25519 sealed boxes
- Signatures: Ed25519
- Hashing: SHA-256, SHA-512, BLAKE2b, plus HMAC
- KDFs and key derivation helpers
- Key I/O in RAW binary format

Out of scope (moved out of this repository):
- X.509 / PKI / cert chain validation / trust stores / CSR / CRL / verify protocol
- DID integration

Those identity and trust capabilities now belong in `authbox`.

## Installation

### CMake FetchContent

```cmake
include(FetchContent)

FetchContent_Declare(
  keylock
  GIT_REPOSITORY https://github.com/robolibs/keylock.git
  GIT_TAG main
)

FetchContent_MakeAvailable(keylock)
target_link_libraries(your_target PRIVATE keylock)
```

## Usage

```cpp
#include <keylock/keylock.hpp>

int main() {
    keylock::keylock crypto(keylock::Algorithm::XChaCha20_Poly1305);

    auto key = crypto.generate_symmetric_key();
    std::vector<uint8_t> message = {'h', 'e', 'l', 'l', 'o'};

    auto ciphertext = crypto.encrypt(message, key.data);
    auto plaintext = crypto.decrypt(ciphertext.data, key.data);

    keylock::keylock signer(keylock::Algorithm::Ed25519);
    auto keys = signer.generate_keypair();

    auto sig = signer.sign(message, keys.private_key);
    auto ok = signer.verify(message, sig.data, keys.public_key);
    return ok.success ? 0 : 1;
}
```

## Key I/O format

`KeyFormat` is kept for forward compatibility, but currently supports only:
- `KeyFormat::RAW`

`PKCS8` is no longer part of `keylock` after PKI extraction.

## Features

- Modern crypto-only API (no legacy RSA/ECDSA surface)
- Result-based error handling (`{success, data, error_message}`)
- Header-first C++20 interface with internal implementations
- No OpenSSL dependency for core crypto operations

## Building

```bash
make config
make
make test
```

With CMake directly:

```bash
cmake -S . -B build -Dkeylock_BUILD_EXAMPLES=ON -Dkeylock_ENABLE_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

## Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `keylock_BUILD_EXAMPLES` | OFF | Build 3 crypto examples |
| `keylock_ENABLE_TESTS` | OFF | Build test suite |
| `keylock_ENABLE_SIMD` | ON | Enable SIMD optimizations |

## Examples

Current examples in `examples/`:
- `main.cpp`
- `test_lockey.cpp`
- `test_comprehensive.cpp`

## Documentation

This README reflects the crypto-only API in this repository.

Legacy PKI docs under `misc/` are historical and will be migrated to `authbox`.

## License

MIT License - see [LICENSE](./LICENSE).

## Acknowledgments

- [datapod](https://github.com/robolibs/datapod)
- [doctest](https://github.com/doctest/doctest)
