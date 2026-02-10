#include <doctest/doctest.h>

#include "keylock/crypto/rsa/rsa_math.hpp"

TEST_SUITE("RSA Math Foundations") {
    using namespace keylock::crypto::sign_rsa::math;

    TEST_CASE("add and sub big-endian integers") {
        Bytes a{0x01, 0x00};
        Bytes b{0x00, 0x01};

        auto sum = add_be(a, b);
        REQUIRE(sum.is_ok());
        CHECK(sum.value() == Bytes{0x01, 0x01});

        auto diff = sub_be(sum.value(), b);
        REQUIRE(diff.is_ok());
        CHECK(diff.value() == a);
    }

    TEST_CASE("mul and mod big-endian integers") {
        Bytes x{0x00, 0x13}; // 19
        Bytes y{0x00, 0x17}; // 23

        auto product = mul_be(x, y);
        REQUIRE(product.is_ok());
        CHECK(product.value() == Bytes{0x01, 0xb5}); // 437

        auto rem = mod_be(product.value(), Bytes{0x00, 0x61}); // mod 97
        REQUIRE(rem.is_ok());
        CHECK(rem.value() == Bytes{0x31}); // 49
    }

    TEST_CASE("modular exponent known vector") {
        // 4^13 mod 497 = 445
        auto out = mod_exp_be(Bytes{0x04}, Bytes{0x0d}, Bytes{0x01, 0xf1});
        REQUIRE(out.is_ok());
        CHECK(out.value() == Bytes{0x01, 0xbd});
    }

    TEST_CASE("modular inverse small known vector") {
        // 3^-1 mod 11 = 4
        auto inv = mod_inverse_be(Bytes{0x03}, Bytes{0x0b});
        REQUIRE(inv.is_ok());
        CHECK(inv.value() == Bytes{0x04});
    }
}
