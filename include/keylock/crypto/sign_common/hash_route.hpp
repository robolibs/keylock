#pragma once

#include <cstddef>
#include <utility>

#include "keylock/crypto/sign_common/dp_echo_compat.hpp"

#include "keylock/hash/sha256/sha256.hpp"
#include "keylock/hash/sha512/sha512.hpp"

namespace keylock::crypto::sign_common {

    enum class SignatureHashAlgorithm { SHA256, SHA384, SHA512 };

    using Bytes = dp::Vector<dp::u8>;
    using HashResult = dp::Result<Bytes>;

    inline dp::usize digest_size(SignatureHashAlgorithm algorithm) {
        switch (algorithm) {
        case SignatureHashAlgorithm::SHA256:
            return 32;
        case SignatureHashAlgorithm::SHA384:
            return 48;
        case SignatureHashAlgorithm::SHA512:
            return 64;
        }
        return 0;
    }

    inline HashResult hash_message(SignatureHashAlgorithm algorithm, const Bytes &message) {
        Bytes digest;

        switch (algorithm) {
        case SignatureHashAlgorithm::SHA256: {
            digest.resize(32);
            hash::sha256::hash(digest.data(), message.data(), message.size());
            return HashResult::ok(std::move(digest));
        }
        case SignatureHashAlgorithm::SHA384: {
            echo::warn("hash_message: SHA384 is not implemented yet in keylock hash primitives");
            return HashResult::err(dp::Error::invalid_argument("sha384 not implemented"));
        }
        case SignatureHashAlgorithm::SHA512: {
            digest.resize(64);
            hash::sha512::hash(digest.data(), message.data(), message.size());
            return HashResult::ok(std::move(digest));
        }
        }

        echo::error("hash_message: unsupported signature hash algorithm");
        return HashResult::err(dp::Error::invalid_argument("unsupported signature hash algorithm"));
    }

} // namespace keylock::crypto::sign_common
