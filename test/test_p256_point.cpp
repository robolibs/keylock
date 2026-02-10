#include <doctest/doctest.h>

#include "keylock/crypto/ecdsa_p256/p256_point.hpp"

TEST_SUITE("P256 Point") {
    using keylock::crypto::sign_ecdsa_p256::point::Bytes;
    using keylock::crypto::sign_ecdsa_p256::point::Point;

    TEST_CASE("generator is on curve") {
        Point g = keylock::crypto::sign_ecdsa_p256::point::generator();
        auto ok = keylock::crypto::sign_ecdsa_p256::point::is_on_curve(g);
        REQUIRE(ok.is_ok());
        CHECK(ok.value());
    }

    TEST_CASE("infinity add identity") {
        auto g = keylock::crypto::sign_ecdsa_p256::point::generator();
        auto inf = keylock::crypto::sign_ecdsa_p256::point::infinity();

        auto s1 = keylock::crypto::sign_ecdsa_p256::point::add(inf, g);
        auto s2 = keylock::crypto::sign_ecdsa_p256::point::add(g, inf);
        REQUIRE(s1.is_ok());
        REQUIRE(s2.is_ok());
        CHECK(keylock::crypto::sign_ecdsa_p256::point::equal(s1.value(), g));
        CHECK(keylock::crypto::sign_ecdsa_p256::point::equal(s2.value(), g));
    }

    TEST_CASE("scalar multiplication by one and two") {
        auto g = keylock::crypto::sign_ecdsa_p256::point::generator();

        Bytes one(32, 0x00);
        one[31] = 0x01;
        Bytes two(32, 0x00);
        two[31] = 0x02;

        auto g1 = keylock::crypto::sign_ecdsa_p256::point::scalar_mul(g, one);
        REQUIRE(g1.is_ok());
        CHECK(keylock::crypto::sign_ecdsa_p256::point::equal(g1.value(), g));

        auto g2a = keylock::crypto::sign_ecdsa_p256::point::scalar_mul(g, two);
        auto g2b = keylock::crypto::sign_ecdsa_p256::point::double_point(g);
        REQUIRE(g2a.is_ok());
        REQUIRE(g2b.is_ok());
        CHECK(keylock::crypto::sign_ecdsa_p256::point::equal(g2a.value(), g2b.value()));
    }
}
