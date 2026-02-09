#include <doctest/doctest.h>

#include "keylock/crypto/sign_rsa/rsa_pkcs1v15.hpp"

TEST_SUITE("RSA PKCS1 v1.5") {
    using keylock::crypto::sign_common::SignatureHashAlgorithm;
    using keylock::crypto::sign_rsa::RsaPublicKey;
    using keylock::crypto::sign_rsa::pkcs1v15::Bytes;

    TEST_CASE("digest info prefixes exist for supported algorithms") {
        auto p256 = keylock::crypto::sign_rsa::pkcs1v15::digest_info_prefix(SignatureHashAlgorithm::SHA256);
        auto p384 = keylock::crypto::sign_rsa::pkcs1v15::digest_info_prefix(SignatureHashAlgorithm::SHA384);
        auto p512 = keylock::crypto::sign_rsa::pkcs1v15::digest_info_prefix(SignatureHashAlgorithm::SHA512);

        REQUIRE(p256.is_ok());
        REQUIRE(p384.is_ok());
        REQUIRE(p512.is_ok());
        CHECK(p256.value().size() == 19);
        CHECK(p384.value().size() == 19);
        CHECK(p512.value().size() == 19);
    }

    TEST_CASE("emsa encode creates 00 01 FF..00 T structure") {
        Bytes message{'k', 'e', 'y', 'l', 'o', 'c', 'k'};
        const dp::usize k = 128; // 1024-bit modulus length

        auto em = keylock::crypto::sign_rsa::pkcs1v15::emsa_encode(message, SignatureHashAlgorithm::SHA256, k);
        REQUIRE(em.is_ok());
        REQUIRE(em.value().size() == k);

        CHECK(em.value()[0] == 0x00);
        CHECK(em.value()[1] == 0x01);

        dp::usize sep = 2;
        while (sep < em.value().size() && em.value()[sep] == 0xff) {
            ++sep;
        }
        CHECK(sep > 10);
        REQUIRE(sep < em.value().size());
        CHECK(em.value()[sep] == 0x00);
    }

    TEST_CASE("public key validation rejects even exponent") {
        RsaPublicKey key;
        key.modulus.resize(128, 0xff);
        key.modulus.back() = 0x03;
        key.public_exponent = Bytes{0x02};

        auto v = keylock::crypto::sign_rsa::validate_public_key(key);
        CHECK(v.is_err());
    }
}
