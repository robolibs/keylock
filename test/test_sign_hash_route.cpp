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

    TEST_CASE("sha384 hash of abc") {
        dp::Vector<dp::u8> msg{'a', 'b', 'c'};
        const auto result = keylock::crypto::sign_common::hash_message(SignatureHashAlgorithm::SHA384, msg);
        REQUIRE(result.is_ok());

        dp::Vector<dp::u8> expected = {
            0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
            0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
            0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
        };

        CHECK(result.value() == expected);
    }
}
