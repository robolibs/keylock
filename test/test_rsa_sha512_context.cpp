#include <doctest/doctest.h>

#include <keylock/keylock.hpp>

TEST_SUITE("RSA SHA512 Context") {
    TEST_CASE("RSA PKCS1v1.5 SHA512 round-trip") {
        keylock::keylock ctx(keylock::Algorithm::RSA_PKCS1v15_SHA512);
        auto kp = ctx.generate_keypair();

        std::vector<uint8_t> msg{'s', 'h', 'a', '5', '1', '2'};
        auto sig = ctx.sign(msg, kp.private_key);
        REQUIRE(sig.success);

        auto ok = ctx.verify(msg, sig.data, kp.public_key);
        REQUIRE(ok.success);
    }

    TEST_CASE("RSA PSS SHA512 round-trip") {
        keylock::keylock ctx(keylock::Algorithm::RSA_PSS_SHA512);
        auto kp = ctx.generate_keypair();

        std::vector<uint8_t> msg{'p', 's', 's', '5', '1', '2'};
        auto sig = ctx.sign(msg, kp.private_key);
        REQUIRE(sig.success);

        auto ok = ctx.verify(msg, sig.data, kp.public_key);
        REQUIRE(ok.success);
    }
}
