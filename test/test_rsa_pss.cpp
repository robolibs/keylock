#include <doctest/doctest.h>

#include "keylock/crypto/sign_rsa/rsa_pss.hpp"

TEST_SUITE("RSA PSS") {
    using keylock::crypto::sign_common::SignatureHashAlgorithm;
    using keylock::crypto::sign_rsa::RsaPrivateKey;
    using keylock::crypto::sign_rsa::RsaPublicKey;
    using keylock::crypto::sign_rsa::pss::Bytes;

    TEST_CASE("EMSA-PSS encode and verify with fixed salt") {
        Bytes message{'r', 's', 'a', '-', 'p', 's', 's'};
        Bytes salt(32, 0x42);

        const dp::usize em_bits = 1023;
        auto em =
            keylock::crypto::sign_rsa::pss::emsa_pss_encode(message, SignatureHashAlgorithm::SHA256, em_bits, salt);
        REQUIRE(em.is_ok());

        auto ok = keylock::crypto::sign_rsa::pss::emsa_pss_verify(message, em.value(), SignatureHashAlgorithm::SHA256,
                                                                  em_bits);
        REQUIRE(ok.is_ok());
        CHECK(ok.value());

        em.value()[em.value().size() - 1] = 0x00;
        auto bad = keylock::crypto::sign_rsa::pss::emsa_pss_verify(message, em.value(), SignatureHashAlgorithm::SHA256,
                                                                   em_bits);
        REQUIRE(bad.is_ok());
        CHECK_FALSE(bad.value());
    }

    TEST_CASE("PSS sign and verify round-trip with identity exponent") {
        // Phase-2 plumbing test key: e=d=1 keeps RSASP1/RSAVP1 as identity map.
        // This validates PSS encoding and verify flow before full RSA keygen lands.
        RsaPrivateKey sk;
        sk.modulus.resize(128, 0xff);
        sk.modulus[0] = 0x80;
        sk.modulus.back() = 0x03;
        sk.public_exponent = Bytes{0x01};
        sk.private_exponent = Bytes{0x01};

        RsaPublicKey pk{sk.modulus, sk.public_exponent};

        Bytes message{'k', 'e', 'y', 'l', 'o', 'c', 'k'};
        Bytes salt(32, 0x5a);

        auto sig = keylock::crypto::sign_rsa::pss::sign(message, sk, SignatureHashAlgorithm::SHA256, salt);
        REQUIRE(sig.is_ok());
        CHECK(sig.value().size() == sk.modulus.size());

        auto ok = keylock::crypto::sign_rsa::pss::verify(message, sig.value(), pk, SignatureHashAlgorithm::SHA256);
        REQUIRE(ok.is_ok());
        CHECK(ok.value());

        sig.value()[10] ^= 0x01;
        auto bad = keylock::crypto::sign_rsa::pss::verify(message, sig.value(), pk, SignatureHashAlgorithm::SHA256);
        REQUIRE(bad.is_ok());
        CHECK_FALSE(bad.value());
    }
}
