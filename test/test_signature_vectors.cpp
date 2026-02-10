#include <doctest/doctest.h>

#include "keylock/crypto/ecdsa_p256/ecdsa_der.hpp"
#include "keylock/crypto/rsa/rsa_pkcs1v15.hpp"

TEST_SUITE("Signature Vectors") {
    using keylock::crypto::sign_common::SignatureHashAlgorithm;

    TEST_CASE("RFC8017 DigestInfo prefixes match known constants") {
        auto p256 = keylock::crypto::sign_rsa::pkcs1v15::digest_info_prefix(SignatureHashAlgorithm::SHA256);
        auto p384 = keylock::crypto::sign_rsa::pkcs1v15::digest_info_prefix(SignatureHashAlgorithm::SHA384);
        auto p512 = keylock::crypto::sign_rsa::pkcs1v15::digest_info_prefix(SignatureHashAlgorithm::SHA512);

        REQUIRE(p256.is_ok());
        REQUIRE(p384.is_ok());
        REQUIRE(p512.is_ok());

        CHECK(p256.value() == dp::Vector<dp::u8>{
                                  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                  0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
                              });
        CHECK(p384.value() == dp::Vector<dp::u8>{
                                  0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                  0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
                              });
        CHECK(p512.value() == dp::Vector<dp::u8>{
                                  0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                  0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
                              });
    }

    TEST_CASE("ECDSA DER KAT for r=1,s=1") {
        dp::Vector<dp::u8> raw(64, 0x00);
        raw[31] = 0x01;
        raw[63] = 0x01;

        auto der = keylock::crypto::sign_ecdsa_p256::der::encode_raw_to_der(raw);
        REQUIRE(der.is_ok());

        CHECK(der.value() == dp::Vector<dp::u8>{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01});

        auto roundtrip = keylock::crypto::sign_ecdsa_p256::der::decode_der_to_raw(der.value());
        REQUIRE(roundtrip.is_ok());
        CHECK(roundtrip.value() == raw);
    }

    TEST_CASE("Wycheproof-style invalid DER vectors are rejected") {
        const dp::Vector<dp::Vector<dp::u8>> bad_vectors = {
            {0x31, 0x00},                                           // wrong top-level tag
            {0x30, 0x03, 0x02, 0x01, 0x01},                         // missing s integer
            {0x30, 0x08, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01}, // non-canonical r
            {0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01},       // negative r
        };

        for (const auto &v : bad_vectors) {
            auto decoded = keylock::crypto::sign_ecdsa_p256::der::decode_der_to_raw(v);
            CHECK(decoded.is_err());
        }
    }
}
