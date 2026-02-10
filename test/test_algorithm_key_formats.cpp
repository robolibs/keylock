#include <doctest/doctest.h>

#include <keylock/keylock.hpp>

TEST_SUITE("Algorithm Key Formats") {
    TEST_CASE("Ed25519 SPKI and PKCS8 encode/decode") {
        keylock::keylock ctx(keylock::Algorithm::Ed25519);
        auto kp = ctx.generate_keypair();

        auto spki = keylock::keylock::encode_ed25519_public_key_spki_der(kp.public_key);
        REQUIRE(spki.success);
        auto pub_back = keylock::keylock::decode_ed25519_public_key_spki_der(spki.data);
        REQUIRE(pub_back.success);
        CHECK(pub_back.data == kp.public_key);

        auto pkcs8 = keylock::keylock::encode_ed25519_private_key_pkcs8_der(kp.private_key);
        REQUIRE(pkcs8.success);
        auto priv_back = keylock::keylock::decode_ed25519_private_key_pkcs8_der(pkcs8.data);
        REQUIRE(priv_back.success);
        CHECK(priv_back.data.size() == 32);
    }

    TEST_CASE("ECDSA P-256 SPKI and PKCS8 encode/decode") {
        keylock::keylock ctx(keylock::Algorithm::ECDSA_P256_SHA256);
        auto kp = ctx.generate_keypair();

        std::vector<uint8_t> x(kp.public_key.begin(), kp.public_key.begin() + 32);
        std::vector<uint8_t> y(kp.public_key.begin() + 32, kp.public_key.end());

        auto spki = keylock::keylock::encode_ecdsa_p256_public_key_spki_der(x, y);
        REQUIRE(spki.success);
        auto pub_back = keylock::keylock::decode_ecdsa_p256_public_key_spki_der(spki.data);
        REQUIRE(pub_back.success);
        CHECK(pub_back.data == kp.public_key);

        auto pkcs8 = keylock::keylock::encode_ecdsa_p256_private_key_pkcs8_der(kp.private_key);
        REQUIRE(pkcs8.success);
        auto priv_back = keylock::keylock::decode_ecdsa_p256_private_key_pkcs8_der(pkcs8.data);
        REQUIRE(priv_back.success);
        CHECK(priv_back.data == kp.private_key);
    }

    TEST_CASE("Ed25519 and ECDSA format helpers are strict") {
        auto bad_ed = keylock::keylock::decode_ed25519_public_key_spki_der(std::vector<uint8_t>{0x30, 0x00});
        CHECK_FALSE(bad_ed.success);

        auto bad_ec = keylock::keylock::decode_ecdsa_p256_public_key_spki_der(std::vector<uint8_t>{0x30, 0x00});
        CHECK_FALSE(bad_ec.success);
    }
}
