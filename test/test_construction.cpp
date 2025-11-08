#include "lockey/lockey.hpp"
#include <doctest/doctest.h>

TEST_SUITE("Construction and Configuration") {
    TEST_CASE("Default constructor") {
        REQUIRE_NOTHROW(lockey::Lockey crypto);

        lockey::Lockey crypto;
        CHECK(crypto.get_algorithm() == lockey::Lockey::Algorithm::XChaCha20_Poly1305);
        CHECK(crypto.get_hash_algorithm() == lockey::Lockey::HashAlgorithm::SHA256);
    }

    TEST_CASE("Constructor with parameters") {
        REQUIRE_NOTHROW(lockey::Lockey crypto(lockey::Lockey::Algorithm::SecretBox_XSalsa20,
                                              lockey::Lockey::HashAlgorithm::SHA512));

        lockey::Lockey crypto(lockey::Lockey::Algorithm::SecretBox_XSalsa20,
                              lockey::Lockey::HashAlgorithm::SHA512);
        CHECK(crypto.get_algorithm() == lockey::Lockey::Algorithm::SecretBox_XSalsa20);
        CHECK(crypto.get_hash_algorithm() == lockey::Lockey::HashAlgorithm::SHA512);
    }

    TEST_CASE("Algorithm setting") {
        lockey::Lockey crypto;

        crypto.set_algorithm(lockey::Lockey::Algorithm::SecretBox_XSalsa20);
        CHECK(crypto.get_algorithm() == lockey::Lockey::Algorithm::SecretBox_XSalsa20);

        crypto.set_algorithm(lockey::Lockey::Algorithm::X25519_Box);
        CHECK(crypto.get_algorithm() == lockey::Lockey::Algorithm::X25519_Box);

        crypto.set_algorithm(lockey::Lockey::Algorithm::Ed25519);
        CHECK(crypto.get_algorithm() == lockey::Lockey::Algorithm::Ed25519);
    }

    TEST_CASE("Hash algorithm setting") {
        lockey::Lockey crypto;

        crypto.set_hash_algorithm(lockey::Lockey::HashAlgorithm::SHA512);
        CHECK(crypto.get_hash_algorithm() == lockey::Lockey::HashAlgorithm::SHA512);

        crypto.set_hash_algorithm(lockey::Lockey::HashAlgorithm::BLAKE2b);
        CHECK(crypto.get_hash_algorithm() == lockey::Lockey::HashAlgorithm::BLAKE2b);
    }

    TEST_CASE("Advanced algorithms are available") {
        CHECK_NOTHROW(
            lockey::Lockey crypto(lockey::Lockey::Algorithm::XChaCha20_Poly1305, lockey::Lockey::HashAlgorithm::BLAKE2b));
        CHECK_NOTHROW(lockey::Lockey crypto(lockey::Lockey::Algorithm::Ed25519));
    }
}
