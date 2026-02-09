#include <doctest/doctest.h>

#include <keylock/keylock.hpp>

TEST_SUITE("Signature Negative Cases") {
    TEST_CASE("RSA rejects malformed private key blob") {
        keylock::keylock ctx(keylock::Algorithm::RSA_PKCS1v15_SHA256);
        std::vector<uint8_t> msg{'b', 'a', 'd'};

        std::vector<uint8_t> malformed = {0x00, 0x00, 0x00, 0x04, 0xaa}; // truncated modulus
        auto sig = ctx.sign(msg, malformed);
        CHECK_FALSE(sig.success);
    }

    TEST_CASE("RSA rejects malformed public key blob") {
        keylock::keylock ctx(keylock::Algorithm::RSA_PSS_SHA256);
        std::vector<uint8_t> msg{'b', 'a', 'd'};
        std::vector<uint8_t> sig(128, 0x00);

        std::vector<uint8_t> malformed = {0x00, 0x00, 0x00, 0x00}; // empty modulus
        auto ok = ctx.verify(msg, sig, malformed);
        CHECK_FALSE(ok.success);
    }

    TEST_CASE("ECDSA rejects invalid key sizes") {
        keylock::keylock ctx(keylock::Algorithm::ECDSA_P256_SHA256);
        std::vector<uint8_t> msg{'k'};

        std::vector<uint8_t> short_priv(31, 0x01);
        auto sig = ctx.sign(msg, short_priv);
        CHECK_FALSE(sig.success);

        std::vector<uint8_t> sig_blob(64, 0x00);
        std::vector<uint8_t> short_pub(63, 0x02);
        auto ok = ctx.verify(msg, sig_blob, short_pub);
        CHECK_FALSE(ok.success);
    }
}
