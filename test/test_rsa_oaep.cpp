#include <doctest/doctest.h>

#include <keylock/keylock.hpp>

TEST_SUITE("RSA OAEP") {
    TEST_CASE("Context RSA OAEP SHA256 round-trip") {
        keylock::keylock ctx(keylock::Algorithm::RSA_OAEP_SHA256);
        auto kp = ctx.generate_keypair();

        std::vector<uint8_t> msg{'o', 'a', 'e', 'p'};
        auto ct = ctx.encrypt_asymmetric(msg, kp.public_key);
        REQUIRE(ct.success);

        auto pt = ctx.decrypt_asymmetric(ct.data, kp.private_key);
        REQUIRE(pt.success);
        CHECK(pt.data == msg);
    }

    TEST_CASE("Context RSA OAEP SHA384 round-trip") {
        keylock::keylock ctx(keylock::Algorithm::RSA_OAEP_SHA384);
        auto kp = ctx.generate_keypair();

        std::vector<uint8_t> msg{'s', 'h', 'a', '3', '8', '4'};
        auto ct = ctx.encrypt_asymmetric(msg, kp.public_key);
        REQUIRE(ct.success);

        auto pt = ctx.decrypt_asymmetric(ct.data, kp.private_key);
        REQUIRE(pt.success);
        CHECK(pt.data == msg);
    }
}
