#include <doctest/doctest.h>

#include "keylock/crypto/sign_common/hash_route.hpp"

TEST_SUITE("Signature Hash Routing") {
    using keylock::crypto::sign_common::SignatureHashAlgorithm;

    TEST_CASE("digest sizes are correct") {
        CHECK(keylock::crypto::sign_common::digest_size(SignatureHashAlgorithm::SHA256) == 32);
        CHECK(keylock::crypto::sign_common::digest_size(SignatureHashAlgorithm::SHA384) == 48);
        CHECK(keylock::crypto::sign_common::digest_size(SignatureHashAlgorithm::SHA512) == 64);
    }

    TEST_CASE("sha256 hash of abc") {
        dp::Vector<dp::u8> msg{'a', 'b', 'c'};
        const auto result = keylock::crypto::sign_common::hash_message(SignatureHashAlgorithm::SHA256, msg);
        REQUIRE(result.is_ok());

        dp::Vector<dp::u8> expected = {
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        };

        CHECK(result.value() == expected);
    }
}
