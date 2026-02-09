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
            hash::sha512::Context ctx;
            hash::sha512::init(&ctx);

            // SHA-384 IV (FIPS 180-4)
            ctx.hash[0] = 0xcbbb9d5dc1059ed8ULL;
            ctx.hash[1] = 0x629a292a367cd507ULL;
            ctx.hash[2] = 0x9159015a3070dd17ULL;
            ctx.hash[3] = 0x152fecd8f70e5939ULL;
            ctx.hash[4] = 0x67332667ffc00b31ULL;
            ctx.hash[5] = 0x8eb44a8768581511ULL;
            ctx.hash[6] = 0xdb0c2e0d64f98fa7ULL;
            ctx.hash[7] = 0x47b5481dbefa4fa4ULL;

            hash::sha512::update(&ctx, message.data(), message.size());

            Bytes full(64);
            hash::sha512::final(&ctx, full.data());

            digest.resize(48);
            for (dp::usize i = 0; i < 48; ++i) {
                digest[i] = full[i];
            }

            return HashResult::ok(std::move(digest));
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
