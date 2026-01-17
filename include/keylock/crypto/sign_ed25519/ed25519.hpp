#pragma once

// Ed25519 Digital Signatures (RFC 8032)
// Uses SHA-512 for hashing (required by RFC 8032)
//
// This implementation MUST be bit-exact compatible with libsodium because
// signatures are transmitted over the wire in the verify protocol.

#include <cstddef>
#include <cstdint>

// Include the Monocypher implementation for X25519/Ed25519 primitives
#define MONOCYPHER_CPP_NAMESPACE keylock_monocypher_internal
#include "keylock/crypto/monocypher_impl.hpp"

// Include SHA-512 for Ed25519 (RFC 8032 requires SHA-512)
#include "keylock/crypto/constant_time/wipe.hpp"
#include "keylock/crypto/rng/randombytes.hpp"
#include "keylock/hash/sha512/sha512.hpp"

namespace keylock::crypto::ed25519 {

    // Constants matching libsodium
    inline constexpr size_t PUBLICKEYBYTES = 32;
    inline constexpr size_t SECRETKEYBYTES = 64;
    inline constexpr size_t BYTES = 64; // signature size
    inline constexpr size_t SEEDBYTES = 32;

    namespace detail {

        using namespace keylock_monocypher_internal;

        // Hash and reduce modulo L for Ed25519
        inline void hash_reduce(uint8_t h[32], const uint8_t *a, size_t a_size, const uint8_t *b, size_t b_size,
                                const uint8_t *c, size_t c_size, const uint8_t *d, size_t d_size) {
            uint8_t hash[64];
            keylock::hash::sha512::Context ctx;
            keylock::hash::sha512::init(&ctx);
            if (a && a_size > 0)
                keylock::hash::sha512::update(&ctx, a, a_size);
            if (b && b_size > 0)
                keylock::hash::sha512::update(&ctx, b, b_size);
            if (c && c_size > 0)
                keylock::hash::sha512::update(&ctx, c, c_size);
            if (d && d_size > 0)
                keylock::hash::sha512::update(&ctx, d, d_size);
            keylock::hash::sha512::final(&ctx, hash);
            crypto_eddsa_reduce(h, hash);
            constant_time::wipe(hash, sizeof(hash));
        }

    } // namespace detail

    // Generate Ed25519 keypair from seed
    // secret_key is 64 bytes: first 32 are the seed, last 32 are the public key
    inline void seed_keypair(uint8_t public_key[32], uint8_t secret_key[64], const uint8_t seed[32]) {
        using namespace keylock_monocypher_internal;

        uint8_t a[64];
        // Copy seed to secret key first half
        for (int i = 0; i < 32; i++) {
            secret_key[i] = seed[i];
        }

        // Hash seed with SHA-512 to get scalar (first 32 bytes) and prefix (last 32 bytes)
        keylock::hash::sha512::hash(a, seed, 32);

        // Clamp the scalar (first 32 bytes)
        crypto_eddsa_trim_scalar(a, a);

        // Compute public key = [scalar]B
        crypto_eddsa_scalarbase(public_key, a);

        // Store public key in secret_key (second half)
        for (int i = 0; i < 32; i++) {
            secret_key[32 + i] = public_key[i];
        }

        constant_time::wipe(a, sizeof(a));
    }

    // Generate Ed25519 keypair with random seed
    inline void keypair(uint8_t public_key[32], uint8_t secret_key[64]) {
        uint8_t seed[32];
        rng::randombytes_buf(seed, sizeof(seed));
        seed_keypair(public_key, secret_key, seed);
        constant_time::wipe(seed, sizeof(seed));
    }

    // Sign message with Ed25519 (detached signature)
    // Returns 0 on success
    inline int sign_detached(uint8_t signature[64], unsigned long long *siglen, const uint8_t *message,
                             unsigned long long message_size, const uint8_t secret_key[64]) {
        using namespace keylock_monocypher_internal;

        uint8_t a[64]; // secret scalar (clamped) and prefix
        uint8_t r[32]; // secret deterministic nonce
        uint8_t h[32]; // hash for verification
        uint8_t R[32]; // first half of signature
        const uint8_t *pk = secret_key + 32;

        // Hash the secret key seed to get scalar and prefix
        keylock::hash::sha512::hash(a, secret_key, 32);
        crypto_eddsa_trim_scalar(a, a);

        // r = H(prefix || message) mod L
        detail::hash_reduce(r, a + 32, 32, message, message_size, nullptr, 0, nullptr, 0);

        // R = [r]B
        crypto_eddsa_scalarbase(R, r);

        // h = H(R || pk || message) mod L
        detail::hash_reduce(h, R, 32, pk, 32, message, message_size, nullptr, 0);

        // Copy R to first half of signature
        for (int i = 0; i < 32; i++) {
            signature[i] = R[i];
        }

        // s = (r + h * a) mod L
        crypto_eddsa_mul_add(signature + 32, h, a, r);

        constant_time::wipe(a, sizeof(a));
        constant_time::wipe(r, sizeof(r));

        if (siglen) {
            *siglen = 64;
        }
        return 0;
    }

    // Verify Ed25519 signature (detached)
    // Returns 0 if valid, -1 if invalid
    inline int verify_detached(const uint8_t signature[64], const uint8_t *message, unsigned long long message_size,
                               const uint8_t public_key[32]) {
        using namespace keylock_monocypher_internal;

        // Compute h = H(R || pk || message) mod L
        uint8_t h_ram[32];
        detail::hash_reduce(h_ram, signature, 32, public_key, 32, message, message_size, nullptr, 0);

        // Verify the signature equation: [s]B = R + [h]A
        return crypto_eddsa_check_equation(signature, public_key, h_ram);
    }

} // namespace keylock::crypto::ed25519
