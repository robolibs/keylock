#include <doctest/doctest.h>

#include "keylock/crypto/sign_rsa/rsa_core.hpp"
#include "keylock/crypto/sign_rsa/rsa_keygen.hpp"

TEST_SUITE("RSA CRT") {
    TEST_CASE("CRT private op matches basic private op") {
        auto generated = keylock::crypto::sign_rsa::keygen::generate_keypair(1024, 65537);
        REQUIRE(generated.is_ok());
        auto key = generated.value();
        REQUIRE(keylock::crypto::sign_rsa::has_crt_parameters(key));

        keylock::crypto::sign_rsa::RsaPublicKey pub{key.modulus, key.public_exponent};
        dp::Vector<dp::u8> msg{0x12, 0x34, 0x56};

        auto c = keylock::crypto::sign_rsa::core::public_op(msg, pub);
        REQUIRE(c.is_ok());

        auto m_basic = keylock::crypto::sign_rsa::core::private_op_basic(c.value(), key);
        auto m_crt = keylock::crypto::sign_rsa::core::private_op_crt(c.value(), key);
        REQUIRE(m_basic.is_ok());
        REQUIRE(m_crt.is_ok());
        CHECK(m_crt.value() == m_basic.value());
    }
}
