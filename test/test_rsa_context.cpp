#include <doctest/doctest.h>

#include <keylock/keylock.hpp>

TEST_SUITE("RSA Context Integration") {
    TEST_CASE("Context signs and verifies RSA PKCS1v1.5 SHA256") {
        keylock::keylock ctx(keylock::Algorithm::RSA_PKCS1v15_SHA256);

        std::vector<uint8_t> modulus(128, 0xff);
        modulus[0] = 0x80;
        modulus.back() = 0x03;

        std::vector<uint8_t> e{0x01};
        std::vector<uint8_t> d{0x01};

        auto public_blob = keylock::keylock::encode_rsa_public_key_blob(modulus, e);
        auto private_blob = keylock::keylock::encode_rsa_private_key_blob(modulus, e, d);

        std::vector<uint8_t> message{'k', 'e', 'y', 'l', 'o', 'c', 'k'};
        auto sig = ctx.sign(message, private_blob);
        REQUIRE(sig.success);

        auto ok = ctx.verify(message, sig.data, public_blob);
        REQUIRE(ok.success);

        message[0] ^= 0x01;
        auto bad = ctx.verify(message, sig.data, public_blob);
        CHECK_FALSE(bad.success);
    }

    TEST_CASE("Context signs and verifies RSA PSS SHA256") {
        keylock::keylock ctx(keylock::Algorithm::RSA_PSS_SHA256);

        std::vector<uint8_t> modulus(128, 0xff);
        modulus[0] = 0x80;
        modulus.back() = 0x03;

        std::vector<uint8_t> e{0x01};
        std::vector<uint8_t> d{0x01};

        auto public_blob = keylock::keylock::encode_rsa_public_key_blob(modulus, e);
        auto private_blob = keylock::keylock::encode_rsa_private_key_blob(modulus, e, d);

        std::vector<uint8_t> message{'r', 's', 'a'};
        auto sig = ctx.sign(message, private_blob);
        REQUIRE(sig.success);

        auto ok = ctx.verify(message, sig.data, public_blob);
        REQUIRE(ok.success);

        sig.data[10] ^= 0x55;
        auto bad = ctx.verify(message, sig.data, public_blob);
        CHECK_FALSE(bad.success);
    }
}
