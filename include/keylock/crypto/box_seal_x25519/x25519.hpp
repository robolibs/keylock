#pragma once

// X25519 key exchange
// This is a header-only wrapper that includes the complete Monocypher implementation

#include <cstddef>
#include <cstdint>

// Include the full Monocypher implementation
#define MONOCYPHER_CPP_NAMESPACE keylock_monocypher_internal
#include "keylock/crypto/monocypher_impl.hpp"

#include "keylock/crypto/constant_time/wipe.hpp"

namespace keylock::crypto::x25519 {

    // Constants matching libsodium
    inline constexpr size_t PUBLICKEYBYTES = 32;
    inline constexpr size_t SECRETKEYBYTES = 32;
    inline constexpr size_t SCALARBYTES = 32;

    // Generate public key from secret key
    inline void public_key(uint8_t pk[32], const uint8_t sk[32]) {
        keylock_monocypher_internal::crypto_x25519_public_key(pk, sk);
    }

    // Scalar multiplication (Diffie-Hellman)
    inline void scalarmult(uint8_t shared[32], const uint8_t sk[32], const uint8_t pk[32]) {
        keylock_monocypher_internal::crypto_x25519(shared, sk, pk);
    }

    // Generate keypair
    inline void keypair(uint8_t pk[32], uint8_t sk[32]) {
        // Caller must fill sk with random bytes first
        public_key(pk, sk);
    }

} // namespace keylock::crypto::x25519
