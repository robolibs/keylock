#include <doctest/doctest.h>

#include "keylock/crypto/rng/randombytes.hpp"
#include "keylock/crypto/sign_ecdsa_p256/ecdsa_der.hpp"

TEST_SUITE("Signature Fuzz") {
    TEST_CASE("ECDSA DER decoder survives random byte corpus") {
        for (int i = 0; i < 2000; ++i) {
            const size_t len = static_cast<size_t>(i % 96);
            dp::Vector<dp::u8> buf(len);
            if (!buf.empty()) {
                keylock::crypto::rng::randombytes_buf(buf.data(), buf.size());
            }

            auto decoded = keylock::crypto::sign_ecdsa_p256::der::decode_der_to_raw(buf);
            if (decoded.is_ok()) {
                // If parsing succeeded, encoding and decoding should remain stable.
                auto re_der = keylock::crypto::sign_ecdsa_p256::der::encode_raw_to_der(decoded.value());
                REQUIRE(re_der.is_ok());
                auto re_decoded = keylock::crypto::sign_ecdsa_p256::der::decode_der_to_raw(re_der.value());
                REQUIRE(re_decoded.is_ok());
                CHECK(re_decoded.value() == decoded.value());
            }
        }
    }
}
