#include <doctest/doctest.h>

#include <keylock/crypto/ecdsa_p256/ecdsa_der.hpp>
#include <keylock/keylock.hpp>

TEST_SUITE("ECDSA DER") {
    TEST_CASE("raw to DER and back round-trip") {
        dp::Vector<dp::u8> raw(64, 0x00);
        raw[31] = 0x7f;
        raw[63] = 0x55;

        auto der = keylock::crypto::sign_ecdsa_p256::der::encode_raw_to_der(raw);
        REQUIRE(der.is_ok());
        CHECK(der.value()[0] == 0x30);

        auto back = keylock::crypto::sign_ecdsa_p256::der::decode_der_to_raw(der.value());
        REQUIRE(back.is_ok());
        CHECK(back.value() == raw);
    }

    TEST_CASE("decode rejects malformed DER") {
        dp::Vector<dp::u8> bad = {0x31, 0x00};
        auto r = keylock::crypto::sign_ecdsa_p256::der::decode_der_to_raw(bad);
        CHECK(r.is_err());
    }

    TEST_CASE("context DER helpers work") {
        std::vector<uint8_t> raw(64, 0x00);
        raw[31] = 0x01;
        raw[63] = 0x02;

        auto der = keylock::keylock::encode_ecdsa_p256_signature_der(raw);
        REQUIRE(der.success);

        auto back = keylock::keylock::decode_ecdsa_p256_signature_der(der.data);
        REQUIRE(back.success);
        CHECK(back.data == raw);
    }
}
