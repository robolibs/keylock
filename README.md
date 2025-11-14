<img align="right" width="26%" src="./misc/logo.png">

# Lockey

**A tiny, header-only C++20 libsodium facade with an Ed25519-focused X.509 toolkit**

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/yourusername/lockey)
[![Language](https://img.shields.io/badge/language-C%2B%2B20-blue)](https://en.cppreference.com/w/cpp/20)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Header Only](https://img.shields.io/badge/header--only-yes-orange)](https://github.com/yourusername/lockey)

## Overview

Lockey wraps the battle-tested **libsodium** library in a clean C++20 API. Only modern, authenticated primitives: XChaCha20-Poly1305, X25519 sealed boxes, Ed25519 signatures, and SHA-256/SHA-512/BLAKE2b. No RSA, no ECDSA, no legacy baggage.

**Key Features:**
- **Header-only** - Include `lockey/lockey.hpp` and go, zero compilation
- **Modern crypto** - XChaCha20-Poly1305 AEAD, X25519 boxes, Ed25519 signatures
- **Complete X.509 stack** - DER/PEM parsing, certificate builder, CSR/CRL support
- **Trust store** - System integration, chain validation, hostname verification
- **Verification protocol** - Optional gRPC-based OCSP alternative (requires `LOCKEY_HAS_VERIFY=ON`)
- **Type-safe** - Result types for error handling, no exceptions by default
- **Enterprise PKI** - Policy extensions, name constraints, extended key usage

## Quick Start

```cpp
#include "lockey/lockey.hpp"

int main() {
    lockey::Lockey crypto(lockey::Lockey::Algorithm::XChaCha20_Poly1305);
    
    auto key = crypto.generate_symmetric_key();
    auto ciphertext = crypto.encrypt({'H','e','l','l','o'}, key.data);
    auto plaintext = crypto.decrypt(ciphertext.data, key.data);
}
```

## Core Primitives

| Primitive | Purpose | Algorithm |
|-----------|---------|-----------|
| `XChaCha20_Poly1305` | Symmetric AEAD encryption | 256-bit key, 192-bit nonce |
| `SecretBox_XSalsa20` | Symmetric secretbox | XSalsa20-Poly1305 |
| `X25519_Box` | Public-key sealed boxes | Curve25519 |
| `Ed25519` | Digital signatures | EdDSA on Curve25519 |
| `SHA256/SHA512/BLAKE2b` | Hashing & HMAC | Multiple hash algorithms |

## Quick Start

```cpp
#include "lockey/lockey.hpp"
#include <iostream>

int main() {
    lockey::Lockey crypto(lockey::Lockey::Algorithm::XChaCha20_Poly1305);

    auto key = crypto.generate_symmetric_key();               // 32 random bytes
    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o'};

    auto ciphertext = crypto.encrypt(message, key.data);      // nonce || ciphertext
    auto plaintext  = crypto.decrypt(ciphertext.data, key.data);

    std::cout << "Round-trip success: " << std::boolalpha
              << (plaintext.success && plaintext.data == message) << "\n";
}
```

## Cryptographic Primitives

| Primitive                       | Purpose                     | libsodium call                                  |
|---------------------------------|-----------------------------|-------------------------------------------------|
| `XChaCha20_Poly1305`            | Symmetric AEAD              | `crypto_aead_xchacha20poly1305_ietf_*`          |
| `SecretBox_XSalsa20`            | Symmetric secretbox         | `crypto_secretbox_easy/open_easy`               |
| `X25519_Box`                    | Public-key sealed boxes     | `crypto_box_keypair`, `crypto_box_seal(_open)`  |
| `Ed25519`                       | Deterministic signatures    | `crypto_sign_ed25519_*`                         |
| `SHA256`, `SHA512`, `BLAKE2b`   | Hashing/HMAC                | `crypto_hash_*`, `crypto_generichash`, `crypto_auth_*` |

## Usage Guide

### Symmetric Encryption (XChaCha20-Poly1305)

```cpp
lockey::Lockey crypto(lockey::Lockey::Algorithm::XChaCha20_Poly1305);
auto key = crypto.generate_symmetric_key().data;

auto ciphertext = crypto.encrypt(plaintext, key, /*aad=*/{});
auto decrypted  = crypto.decrypt(ciphertext.data, key);
```

### SecretBox (XSalsa20-Poly1305)

```cpp
lockey::Lockey secretbox(lockey::Lockey::Algorithm::SecretBox_XSalsa20);
auto key = secretbox.generate_symmetric_key(lockey::utils::Common::SECRETBOX_KEY_SIZE).data;
auto cipher = secretbox.encrypt(data, key);
auto plain  = secretbox.decrypt(cipher.data, key);
```

### X25519 Sealed Boxes

```cpp
lockey::Lockey box(lockey::Lockey::Algorithm::X25519_Box);
auto recipient = box.generate_keypair();

auto sealed = box.encrypt_asymmetric(data, recipient.public_key);
auto plain  = box.decrypt_asymmetric(sealed.data, recipient.private_key);
```

### Ed25519 Signatures

```cpp
lockey::Lockey signer(lockey::Lockey::Algorithm::Ed25519);
auto keypair = signer.generate_keypair();

auto signature = signer.sign(data, keypair.private_key);
auto verified  = signer.verify(data, signature.data, keypair.public_key);
```

### Hashing & HMAC

```cpp
lockey::Lockey sha512(lockey::Lockey::Algorithm::XChaCha20_Poly1305,
                      lockey::Lockey::HashAlgorithm::SHA512);
auto digest = sha512.hash(data);

auto mac = sha512.hmac(data, key_material);
```

### Utility Functions

```cpp
// Hex encoding/decoding
auto hex = lockey::Lockey::to_hex(bytes);
auto raw = lockey::Lockey::from_hex(hex);

// Key file I/O
lockey::Lockey crypto(lockey::Lockey::Algorithm::X25519_Box);
auto keypair = crypto.generate_keypair();
crypto.save_keypair_to_files(keypair, "pub.bin", "priv.bin");
auto priv = crypto.load_key_from_file("priv.bin", lockey::Lockey::KeyType::PRIVATE);

// Secure operations
auto random = lockey::utils::Common::generate_random_bytes(32);
bool equal = lockey::utils::Common::secure_compare(data1, data2, size);
lockey::utils::Common::secure_clear(sensitive_data, size);

// PKCS#7 padding
auto padded = lockey::utils::Common::pkcs7_pad(data, 16);
auto unpadded = lockey::utils::Common::pkcs7_unpad(padded);

// XOR operations
auto result = lockey::utils::Common::xor_bytes(vec1, vec2);
```

### Secure Key Exchange Envelopes

Lockey provides a complete envelope system for securely exchanging data through files or shared memory:

```cpp
#include "lockey/io/key_exchange.hpp"

lockey::Lockey box(lockey::Lockey::Algorithm::X25519_Box);
auto recipient = box.generate_keypair();

std::vector<uint8_t> payload = {'s', 'e', 'c', 'r', 'e', 't'};
std::vector<uint8_t> aad = {'f', 'i', 'l', 'e'};

lockey::io::key_exchange::write_envelope_to_file(payload, recipient.public_key,
                                             "/tmp/lockey.envelope", aad);

std::vector<uint8_t> recovered_aad;
auto decrypted = lockey::io::key_exchange::read_envelope_from_file("/tmp/lockey.envelope",
                                                               recipient.private_key,
                                                               &recovered_aad);
```

Shared-memory flows use the same envelope bytes with additional safety features:

```cpp
// Create envelope in memory
std::vector<uint8_t> envelope =
    lockey::io::key_exchange::create_envelope(payload, recipient.public_key, aad).data;
auto opened = lockey::io::key_exchange::consume_envelope(envelope, recipient.private_key);

// Direct memory buffer operations with capacity checking
uint8_t buffer[4096];
size_t written;
lockey::io::key_exchange::write_envelope_to_memory(buffer, sizeof(buffer), written,
                                                   payload, recipient.public_key, aad);
                                                   
auto result = lockey::io::key_exchange::read_envelope_from_memory(buffer, written,
                                                                 recipient.private_key);
```

## Certificate Verification Protocol (LVP)

When compiled with `LOCKEY_HAS_VERIFY=ON`, Lockey includes a modern certificate revocation checking system:

```cpp
#include <lockey/verify/client.hpp>
#include <lockey/verify/server.hpp>

// Client-side verification
lockey::verify::Client client("localhost:50051");
auto response = client.verify_chain(certificate_chain);
if (response.success && response.value.valid) {
    std::cout << "Certificate is valid\n";
}

// Server-side handler
class MyHandler : public lockey::verify::VerificationHandler {
    wire::VerifyResponse verify_chain(const std::vector<cert::Certificate> &chain,
                                     std::chrono::system_clock::time_point validation_time) override {
        // Custom verification logic
        return response;
    }
};

// Start verification server
lockey::verify::ServerConfig config;
config.address = "0.0.0.0:50051";
auto handler = std::make_shared<MyHandler>();
lockey::verify::Server server(handler, config);
server.start();
```

Features:
- gRPC/HTTP2 transport with optional TLS
- Custom binary wire format optimized for Ed25519
- Batch verification support for efficiency  
- Nonce-based replay protection
- Ed25519 signed responses
- Built-in health checks
- In-memory revocation list management

See [`docs/VERIFY_PROTOCOL.md`](docs/VERIFY_PROTOCOL.md) for protocol specification.

## Building & Testing

```bash
# CMake-only workflow
cmake -S . -B build -DLOCKEY_BUILD_EXAMPLES=ON -DLOCKEY_ENABLE_TESTS=ON
cmake --build build
cd build && ctest --output-on-failure

# Or use the convenience targets
make config   # configures with tests/examples enabled
make          # builds everything under ./build
make test     # wraps ctest
```

### Test Coverage

Comprehensive test suite with 20+ test files covering:
- **Cryptography**: Symmetric/asymmetric encryption, signatures, hashing, HMAC
- **Certificates**: Parsing, generation, validation, chain verification
- **Extensions**: Basic Constraints, Key Usage, Extended Key Usage, Alternative Names
- **Enterprise PKI**: Policy extensions, CRL handling, trust store operations
- **ASN.1**: DER encoding/decoding for all supported types
- **Key Management**: Generation, I/O, format conversions
- **Envelopes**: File and memory-based secure exchange
- **Utilities**: Padding, hex encoding, secure comparisons

Each test file becomes its own executable when `LOCKEY_ENABLE_TESTS=ON`, allowing focused testing.

### Requirements

- C++20 compatible compiler (GCC 10+, Clang 11+, MSVC 2019+)
- libsodium 1.0.18+ installed
- CMake 3.14+ for building
- Optional: gRPC for verification protocol (`LOCKEY_HAS_VERIFY=ON`)

## Enterprise PKI Features

Lockey includes advanced PKI features typically found in enterprise certificate management:

### Policy Extensions
- **Policy Mappings**: Map issuer domain policies to subject domain policies
- **Policy Constraints**: Control policy requirements down the certificate chain
- **Inhibit Any-Policy**: Restrict the use of anyPolicy OID in certificate chains

### Advanced Extensions
- **Issuer Alternative Name**: Multiple identities for certificate issuers
- **Name Constraints**: Restrict the namespace for sub-CAs
- **CRL Distribution Points**: Specify where to obtain revocation information
- **Authority Information Access**: OCSP and CA issuer URLs

### Enterprise Use Cases
- Multi-level CA hierarchies with constrained delegation
- Cross-certification between organizations
- Policy-aware certificate validation
- Complex trust models with bridge CAs

## Examples

All examples live in [`examples/`](examples/) and demonstrate real-world usage:

### Basic Cryptography
- `main.cpp` - Complete walkthrough of symmetric encryption, hashing, signing
- `test_comprehensive.cpp` - Exercises every libsodium primitive end-to-end
- `test_lockey.cpp` - Minimal smoke test for quick verification

### Certificate Operations
- `cert_generate_self_signed.cpp` - Build self-signed Ed25519 certificates
- `cert_generate_ca.cpp` - Create CA certificates with proper constraints
- `csr_generate.cpp` - Generate PKCS#10 Certificate Signing Requests
- `cert_sign_csr.cpp` - Issue certificates from CSRs
- `cert_verify_chain.cpp` - Complete chain validation example
- `cert_parse_and_print.cpp` - Parse and inspect certificate details
- `trust_store_usage.cpp` - Programmatic trust store management

### Advanced Features
- `enterprise.cpp` - Enterprise PKI extensions demonstration
- `simple_verify_client.cpp` - Certificate verification protocol client
- `simple_verify_server.cpp` - Certificate verification protocol server
- `verify_grpc.cpp` - gRPC-based verification implementation

## API Quick Reference

### Core Types
```cpp
lockey::Lockey                    // Main crypto context
lockey::CryptoResult              // Result<vector<uint8_t>, string>
lockey::KeyPair                   // Public + private key pair
lockey::cert::Certificate         // X.509 certificate
lockey::cert::CertificateBuilder  // Fluent certificate builder
lockey::cert::CsrBuilder          // CSR builder
lockey::cert::CrlBuilder          // CRL builder
lockey::cert::TrustStore          // Certificate trust store
lockey::cert::DistinguishedName   // X.500 DN
lockey::verify::Client            // Verification client
lockey::verify::Server            // Verification server
```

### Common Operations
```cpp
// Encryption
crypto.encrypt(plaintext, key, aad)
crypto.decrypt(ciphertext, key, aad)

// Signatures
crypto.sign(data, private_key)
crypto.verify(data, signature, public_key)

// Certificates
Certificate::load(path)
Certificate::save(path)
certificate.validate_chain(intermediates, trust_store)
certificate.match_hostname(hostname)

// Key Management
crypto.generate_keypair()
crypto.generate_symmetric_key()
crypto.save_keypair_to_files(keypair, pub_file, priv_file)
```

## License

Licensed under the [MIT License](LICENSE).

---

Lockey keeps the fast libsodium internals and leaves the legacy interfaces behind. If you need modern crypto primitives without a heavyweight dependency graph, this is it.
