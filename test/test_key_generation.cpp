#include "keylock/keylock.hpp"
#include <doctest/doctest.h>
#include <stdexcept>

namespace {
    bool read_u32_be(const std::vector<uint8_t> &blob, size_t &offset, uint32_t &v) {
        if (offset + 4 > blob.size()) {
            return false;
        }
        v = (static_cast<uint32_t>(blob[offset]) << 24) | (static_cast<uint32_t>(blob[offset + 1]) << 16) |
            (static_cast<uint32_t>(blob[offset + 2]) << 8) | static_cast<uint32_t>(blob[offset + 3]);
        offset += 4;
        return true;
    }
} // namespace

TEST_SUITE("Key Generation") {
    TEST_CASE("Symmetric key generation") {
        keylock::keylock crypto;

        // Test default size (32 bytes)
        auto result = crypto.generate_symmetric_key();
        REQUIRE(result.success);
        CHECK(result.data.size() == 32);
        CHECK(result.error_message.empty());

        // Test different sizes
        auto result16 = crypto.generate_symmetric_key(16);
        REQUIRE(result16.success);
        CHECK(result16.data.size() == 16);

        auto result64 = crypto.generate_symmetric_key(64);
        REQUIRE(result64.success);
        CHECK(result64.data.size() == 64);

        // Keys should be different each time
        auto result2 = crypto.generate_symmetric_key();
        REQUIRE(result2.success);
        CHECK(result.data != result2.data);
    }

    TEST_CASE("X25519 key generation") {
        keylock::keylock crypto(keylock::keylock::Algorithm::X25519_Box);

        auto keypair = crypto.generate_keypair();
        CHECK(keypair.algorithm == keylock::keylock::Algorithm::X25519_Box);
        CHECK(keypair.public_key.size() == crypto_box_PUBLICKEYBYTES);
        CHECK(keypair.private_key.size() == crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES);

        // Keys should be different each time
        auto keypair2 = crypto.generate_keypair();
        CHECK(keypair.public_key != keypair2.public_key);
        CHECK(keypair.private_key != keypair2.private_key);
    }

    TEST_CASE("Ed25519 key generation") {
        keylock::keylock crypto(keylock::keylock::Algorithm::Ed25519);

        auto keypair = crypto.generate_keypair();
        CHECK(keypair.algorithm == keylock::keylock::Algorithm::Ed25519);
        CHECK(keypair.public_key.size() == crypto_sign_ed25519_PUBLICKEYBYTES);
        CHECK(keypair.private_key.size() == crypto_sign_ed25519_SECRETKEYBYTES);
    }

    TEST_CASE("ECDSA P-256 key generation") {
        keylock::keylock crypto(keylock::keylock::Algorithm::ECDSA_P256_SHA256);

        auto keypair = crypto.generate_keypair();
        CHECK(keypair.algorithm == keylock::keylock::Algorithm::ECDSA_P256_SHA256);
        CHECK(keypair.public_key.size() == 64);
        CHECK(keypair.private_key.size() == 32);

        std::vector<uint8_t> msg{'e', 'c', 'd', 's', 'a'};
        auto sig = crypto.sign(msg, keypair.private_key);
        REQUIRE(sig.success);
        auto ok = crypto.verify(msg, sig.data, keypair.public_key);
        REQUIRE(ok.success);
    }

    TEST_CASE("ECDSA secp256k1 key generation") {
        keylock::keylock crypto(keylock::keylock::Algorithm::ECDSA_SECP256K1_COMPACT);

        auto keypair = crypto.generate_keypair();
        CHECK(keypair.algorithm == keylock::keylock::Algorithm::ECDSA_SECP256K1_COMPACT);
        CHECK(keypair.public_key.size() == 65);
        CHECK(keypair.private_key.size() == 32);

        std::vector<uint8_t> msg{'s', 'e', 'c', 'p'};
        auto sig = crypto.sign(msg, keypair.private_key);
        REQUIRE(sig.success);
        CHECK(sig.data.size() == 65);

        auto ok = crypto.verify(msg, sig.data, keypair.public_key);
        REQUIRE(ok.success);
    }

    TEST_CASE("RSA key generation uses 65537 and supports sign/verify") {
        keylock::keylock crypto(keylock::keylock::Algorithm::RSA_PKCS1v15_SHA256);

        auto keypair = crypto.generate_keypair();
        CHECK(keypair.algorithm == keylock::keylock::Algorithm::RSA_PKCS1v15_SHA256);
        CHECK(!keypair.public_key.empty());
        CHECK(!keypair.private_key.empty());

        size_t off = 0;
        uint32_t n_len = 0;
        uint32_t e_len = 0;
        REQUIRE(read_u32_be(keypair.public_key, off, n_len));
        REQUIRE(off + n_len <= keypair.public_key.size());
        off += n_len;
        REQUIRE(read_u32_be(keypair.public_key, off, e_len));
        REQUIRE(off + e_len == keypair.public_key.size());
        std::vector<uint8_t> e(keypair.public_key.begin() + static_cast<std::ptrdiff_t>(off), keypair.public_key.end());
        CHECK(e == std::vector<uint8_t>{0x01, 0x00, 0x01});

        size_t off_priv = 0;
        uint32_t n2 = 0, e2 = 0, d_len = 0;
        REQUIRE(read_u32_be(keypair.private_key, off_priv, n2));
        REQUIRE(off_priv + n2 <= keypair.private_key.size());
        off_priv += n2;
        REQUIRE(read_u32_be(keypair.private_key, off_priv, e2));
        REQUIRE(off_priv + e2 <= keypair.private_key.size());
        std::vector<uint8_t> e_priv(keypair.private_key.begin() + static_cast<std::ptrdiff_t>(off_priv),
                                    keypair.private_key.begin() + static_cast<std::ptrdiff_t>(off_priv + e2));
        off_priv += e2;
        REQUIRE(read_u32_be(keypair.private_key, off_priv, d_len));
        REQUIRE(off_priv + d_len == keypair.private_key.size());
        std::vector<uint8_t> d(keypair.private_key.begin() + static_cast<std::ptrdiff_t>(off_priv),
                               keypair.private_key.end());
        CHECK(e_priv == std::vector<uint8_t>{0x01, 0x00, 0x01});
        CHECK(d != e_priv);

        std::vector<uint8_t> msg{'r', 's', 'a'};
        auto sig = crypto.sign(msg, keypair.private_key);
        REQUIRE(sig.success);
        auto ok = crypto.verify(msg, sig.data, keypair.public_key);
        REQUIRE(ok.success);
    }

    TEST_CASE("Key generation with symmetric algorithm should fail") {
        keylock::keylock crypto(keylock::keylock::Algorithm::XChaCha20_Poly1305);

        CHECK_THROWS_AS(crypto.generate_keypair(), std::runtime_error);
    }
}
