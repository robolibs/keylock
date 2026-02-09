#include <doctest/doctest.h>

#include <keylock/keylock.hpp>

TEST_SUITE("RSA SHA384 Context") {
    TEST_CASE("RSA PKCS1v1.5 SHA384 round-trip") {
        keylock::keylock ctx(keylock::Algorithm::RSA_PKCS1v15_SHA384);

        std::vector<uint8_t> modulus(128, 0xff);
        modulus[0] = 0x80;
        modulus.back() = 0x03;
        std::vector<uint8_t> e{0x01};
        std::vector<uint8_t> d{0x01};

        auto pub = keylock::keylock::encode_rsa_public_key_blob(modulus, e);
        auto priv = keylock::keylock::encode_rsa_private_key_blob(modulus, e, d);

        std::vector<uint8_t> msg{'s', 'h', 'a', '3', '8', '4'};
        auto sig = ctx.sign(msg, priv);
        REQUIRE(sig.success);

        auto ok = ctx.verify(msg, sig.data, pub);
        REQUIRE(ok.success);
    }

    TEST_CASE("RSA PSS SHA384 round-trip") {
        keylock::keylock ctx(keylock::Algorithm::RSA_PSS_SHA384);

        std::vector<uint8_t> modulus(128, 0xff);
        modulus[0] = 0x80;
        modulus.back() = 0x03;
        std::vector<uint8_t> e{0x01};
        std::vector<uint8_t> d{0x01};

        auto pub = keylock::keylock::encode_rsa_public_key_blob(modulus, e);
        auto priv = keylock::keylock::encode_rsa_private_key_blob(modulus, e, d);

        std::vector<uint8_t> msg{'p', 's', 's', '3', '8', '4'};
        auto sig = ctx.sign(msg, priv);
        REQUIRE(sig.success);

        auto ok = ctx.verify(msg, sig.data, pub);
        REQUIRE(ok.success);
    }
}
