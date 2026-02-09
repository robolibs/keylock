#include <doctest/doctest.h>

#include "keylock/crypto/sign_rsa/rsa_keygen.hpp"
#include "keylock/crypto/sign_rsa/rsa_pkcs1.hpp"
#include <keylock/keylock.hpp>

TEST_SUITE("RSA PKCS1 Key Formats") {
    TEST_CASE("PKCS1 DER public/private round-trip") {
        auto generated = keylock::crypto::sign_rsa::keygen::generate_keypair(1024, 65537);
        REQUIRE(generated.is_ok());
        auto key = generated.value();

        keylock::crypto::sign_rsa::RsaPublicKey pub{key.modulus, key.public_exponent};

        auto der_pub = keylock::crypto::sign_rsa::pkcs1::encode_public_key_der(pub);
        REQUIRE(der_pub.is_ok());
        auto pub_back = keylock::crypto::sign_rsa::pkcs1::decode_public_key_der(der_pub.value());
        REQUIRE(pub_back.is_ok());
        CHECK(pub_back.value().modulus == pub.modulus);
        CHECK(pub_back.value().public_exponent == pub.public_exponent);

        auto der_priv = keylock::crypto::sign_rsa::pkcs1::encode_private_key_der(key);
        REQUIRE(der_priv.is_ok());
        auto priv_back = keylock::crypto::sign_rsa::pkcs1::decode_private_key_der(der_priv.value());
        REQUIRE(priv_back.is_ok());
        CHECK(priv_back.value().modulus == key.modulus);
        CHECK(priv_back.value().public_exponent == key.public_exponent);
        CHECK(priv_back.value().private_exponent == key.private_exponent);
    }
}
