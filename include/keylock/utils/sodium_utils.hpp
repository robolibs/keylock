#pragma once

// This header provides initialization for keylock crypto
// No external dependencies - uses our own implementations

namespace keylock::utils {

    // No-op: our implementations don't require initialization
    inline void ensure_sodium_init() {
        // Our crypto implementations are header-only and don't need init
    }

} // namespace keylock::utils
