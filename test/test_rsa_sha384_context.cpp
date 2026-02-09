#include <doctest/doctest.h>

#include <keylock/keylock.hpp>

TEST_SUITE("RSA SHA384 Context") {
    TEST_CASE("RSA PKCS1v1.5 SHA384 round-trip") {
        keylock::keylock ctx(keylock::Algorithm::RSA_PKCS1v15_SHA384);
        auto kp = ctx.generate_keypair();

        std::vector<uint8_t> msg{'s', 'h', 'a', '3', '8', '4'};
        auto sig = ctx.sign(msg, kp.private_key);
        REQUIRE(sig.success);

        auto ok = ctx.verify(msg, sig.data, kp.public_key);
        REQUIRE(ok.success);
    }

    TEST_CASE("RSA PSS SHA384 round-trip") {
        keylock::keylock ctx(keylock::Algorithm::RSA_PSS_SHA384);
        auto kp = ctx.generate_keypair();

        std::vector<uint8_t> msg{'p', 's', 's', '3', '8', '4'};
        auto sig = ctx.sign(msg, kp.private_key);
        REQUIRE(sig.success);

        auto ok = ctx.verify(msg, sig.data, kp.public_key);
        REQUIRE(ok.success);
    }
}
