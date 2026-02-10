#include <doctest/doctest.h>

#include "keylock/crypto/ecdsa_p256/ecdsa_impl.hpp"

TEST_SUITE("ECDSA P256") {
    using keylock::crypto::sign_ecdsa_p256::Bytes;
    using keylock::crypto::sign_ecdsa_p256::PrivateKey;

    TEST_CASE("derive public key from private scalar") {
        PrivateKey sk;
        sk.d = Bytes(32, 0x00);
        sk.d[31] = 0x01;

        auto pk = keylock::crypto::sign_ecdsa_p256::derive_public_key(sk);
        REQUIRE(pk.is_ok());

        auto on_curve = keylock::crypto::sign_ecdsa_p256::point::is_on_curve(pk.value().q);
        REQUIRE(on_curve.is_ok());
        CHECK(on_curve.value());
    }

    TEST_CASE("sign and verify detached") {
        PrivateKey sk;
        sk.d = Bytes(32, 0x00);
        sk.d[31] = 0x03;

        auto pk = keylock::crypto::sign_ecdsa_p256::derive_public_key(sk);
        REQUIRE(pk.is_ok());

        Bytes message{'e', 'c', 'd', 's', 'a'};
        auto sig = keylock::crypto::sign_ecdsa_p256::sign_detached(message, sk);
        REQUIRE(sig.is_ok());
        CHECK(sig.value().size() == 64);

        auto ok = keylock::crypto::sign_ecdsa_p256::verify_detached(message, sig.value(), pk.value());
        REQUIRE(ok.is_ok());
        CHECK(ok.value());

        sig.value()[0] ^= 0x01;
        auto bad = keylock::crypto::sign_ecdsa_p256::verify_detached(message, sig.value(), pk.value());
        REQUIRE(bad.is_ok());
        CHECK_FALSE(bad.value());
    }

    TEST_CASE("deterministic signatures via RFC6979") {
        PrivateKey sk;
        sk.d = Bytes(32, 0x00);
        sk.d[31] = 0x07;

        Bytes message{'d', 'e', 't', 'e', 'r', 'm', 'i', 'n', 'i', 's', 't', 'i', 'c'};
        auto s1 = keylock::crypto::sign_ecdsa_p256::sign_detached(message, sk);
        auto s2 = keylock::crypto::sign_ecdsa_p256::sign_detached(message, sk);
        REQUIRE(s1.is_ok());
        REQUIRE(s2.is_ok());
        CHECK(s1.value() == s2.value());
    }
}
