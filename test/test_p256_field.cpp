#include <doctest/doctest.h>

#include "keylock/crypto/sign_ecdsa_p256/p256_field.hpp"

TEST_SUITE("P256 Field") {
    using keylock::crypto::sign_ecdsa_p256::field::Bytes;

    TEST_CASE("mod_p normalizes to 32 bytes") {
        Bytes x{0x01, 0x02, 0x03};
        auto r = keylock::crypto::sign_ecdsa_p256::field::mod_p(x);
        REQUIRE(r.is_ok());
        CHECK(r.value().size() == 32);
        CHECK(r.value()[31] == 0x03);
    }

    TEST_CASE("add/sub inverse property") {
        Bytes a{0x12, 0x34, 0x56};
        Bytes b{0x09, 0xab, 0xcd};

        auto s = keylock::crypto::sign_ecdsa_p256::field::add_p(a, b);
        REQUIRE(s.is_ok());

        auto d = keylock::crypto::sign_ecdsa_p256::field::sub_p(s.value(), b);
        REQUIRE(d.is_ok());

        auto a_norm = keylock::crypto::sign_ecdsa_p256::field::mod_p(a);
        REQUIRE(a_norm.is_ok());
        CHECK(d.value() == a_norm.value());
    }

    TEST_CASE("mul and inverse property for non-zero element") {
        Bytes a{0x05};

        auto inv = keylock::crypto::sign_ecdsa_p256::field::inv_p(a);
        REQUIRE(inv.is_ok());

        auto one = keylock::crypto::sign_ecdsa_p256::field::mul_p(a, inv.value());
        REQUIRE(one.is_ok());

        Bytes expected(32, 0x00);
        expected[31] = 0x01;
        CHECK(one.value() == expected);
    }
}
