#include <doctest/doctest.h>

#include <keylock/crypto/sign_ecdsa_p256/ecdsa_p256.hpp>
#include <keylock/keylock.hpp>

TEST_SUITE("ECDSA Context Integration") {
    TEST_CASE("Context signs and verifies ECDSA P-256 SHA256") {
        keylock::keylock ctx(keylock::Algorithm::ECDSA_P256_SHA256);

        keylock::crypto::sign_ecdsa_p256::PrivateKey sk;
        sk.d = dp::Vector<dp::u8>(32, 0x00);
        sk.d[31] = 0x09;

        auto pk = keylock::crypto::sign_ecdsa_p256::derive_public_key(sk);
        REQUIRE(pk.is_ok());

        auto private_blob =
            keylock::keylock::encode_ecdsa_p256_private_key_blob(std::vector<uint8_t>(sk.d.begin(), sk.d.end()));
        auto public_blob = keylock::keylock::encode_ecdsa_p256_public_key_blob(
            std::vector<uint8_t>(pk.value().q.x.begin(), pk.value().q.x.end()),
            std::vector<uint8_t>(pk.value().q.y.begin(), pk.value().q.y.end()));

        std::vector<uint8_t> message{'a', 'u', 't', 'h', 'b', 'o', 'x'};

        auto sig = ctx.sign(message, private_blob);
        REQUIRE(sig.success);
        CHECK(sig.data.size() == 64);

        auto ok = ctx.verify(message, sig.data, public_blob);
        REQUIRE(ok.success);

        message[0] ^= 0x01;
        auto bad = ctx.verify(message, sig.data, public_blob);
        CHECK_FALSE(bad.success);
    }
}
