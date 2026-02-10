#include <doctest/doctest.h>

#include <keylock/keylock.hpp>

TEST_SUITE("RSA Context Integration") {
    TEST_CASE("Context signs and verifies RSA PKCS1v1.5 SHA256") {
        keylock::keylock ctx(keylock::Algorithm::RSA_PKCS1v15_SHA256);
        auto kp = ctx.generate_keypair();

        std::vector<uint8_t> message{'k', 'e', 'y', 'l', 'o', 'c', 'k'};
        auto sig = ctx.sign(message, kp.private_key);
        REQUIRE(sig.success);

        auto ok = ctx.verify(message, sig.data, kp.public_key);
        REQUIRE(ok.success);

        message[0] ^= 0x01;
        auto bad = ctx.verify(message, sig.data, kp.public_key);
        CHECK_FALSE(bad.success);
    }

    TEST_CASE("Context signs and verifies RSA PSS SHA256") {
        keylock::keylock ctx(keylock::Algorithm::RSA_PSS_SHA256);
        auto kp = ctx.generate_keypair();

        std::vector<uint8_t> message{'r', 's', 'a'};
        auto sig = ctx.sign(message, kp.private_key);
        REQUIRE(sig.success);

        auto ok = ctx.verify(message, sig.data, kp.public_key);
        REQUIRE(ok.success);

        sig.data[10] ^= 0x55;
        auto bad = ctx.verify(message, sig.data, kp.public_key);
        CHECK_FALSE(bad.success);
    }
}
