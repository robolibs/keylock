#include <doctest/doctest.h>
#include <lockey/lockey.hpp>
#include <sodium.h>

TEST_SUITE("Libsodium Feature Comparison") {
    TEST_CASE("XChaCha20 vs SecretBox results differ") {
        std::vector<uint8_t> message = {'s', 'o', 'd', 'i', 'u', 'm', '!'};
        std::vector<uint8_t> key = {0x00, 0x01, 0x02};

        lockey::Lockey xchacha(lockey::Lockey::Algorithm::XChaCha20_Poly1305);
        auto chacha_cipher = xchacha.encrypt(message, key);
        REQUIRE(chacha_cipher.success);

        lockey::Lockey secretbox(lockey::Lockey::Algorithm::SecretBox_XSalsa20);
        auto secretbox_cipher = secretbox.encrypt(message, key);
        REQUIRE(secretbox_cipher.success);

        CHECK(chacha_cipher.data != secretbox_cipher.data);

        auto chacha_plain = xchacha.decrypt(chacha_cipher.data, key);
        REQUIRE(chacha_plain.success);
        CHECK(chacha_plain.data == message);

        auto secretbox_plain = secretbox.decrypt(secretbox_cipher.data, key);
        REQUIRE(secretbox_plain.success);
        CHECK(secretbox_plain.data == message);
    }

    TEST_CASE("X25519 box matches libsodium seal semantics") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::X25519_Box);
        auto keypair = crypto.generate_keypair();

        std::vector<uint8_t> payload = {'b', 'o', 'x'};
        auto ciphertext = crypto.encrypt_asymmetric(payload, keypair.public_key);
        REQUIRE(ciphertext.success);
        CHECK(ciphertext.data.size() == payload.size() + crypto_box_SEALBYTES);

        auto plaintext = crypto.decrypt_asymmetric(ciphertext.data, keypair.private_key);
        REQUIRE(plaintext.success);
        CHECK(plaintext.data == payload);
    }

    TEST_CASE("Ed25519 signatures stay deterministic") {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::Ed25519);
        auto keypair = crypto.generate_keypair();

        std::vector<uint8_t> payload = {'t', 'e', 's', 't'};
        auto sig1 = crypto.sign(payload, keypair.private_key);
        auto sig2 = crypto.sign(payload, keypair.private_key);

        REQUIRE(sig1.success);
        REQUIRE(sig2.success);
        CHECK(sig1.data == sig2.data);

        auto verify = crypto.verify(payload, sig1.data, keypair.public_key);
        CHECK(verify.success);
    }

    TEST_CASE("Hash algorithms produce expected sizes") {
        std::vector<uint8_t> message = {0x00, 0x01, 0x02};

        lockey::Lockey sha256(lockey::Lockey::Algorithm::XChaCha20_Poly1305,
                              lockey::Lockey::HashAlgorithm::SHA256);
        lockey::Lockey sha512(lockey::Lockey::Algorithm::XChaCha20_Poly1305,
                              lockey::Lockey::HashAlgorithm::SHA512);
        lockey::Lockey blake(lockey::Lockey::Algorithm::XChaCha20_Poly1305,
                             lockey::Lockey::HashAlgorithm::BLAKE2b);

        auto h256 = sha256.hash(message);
        auto h512 = sha512.hash(message);
        auto hb = blake.hash(message);

        REQUIRE(h256.success);
        REQUIRE(h512.success);
        REQUIRE(hb.success);

        CHECK(h256.data.size() == crypto_hash_sha256_BYTES);
        CHECK(h512.data.size() == crypto_hash_sha512_BYTES);
        CHECK(hb.data.size() == crypto_generichash_BYTES);
    }
}
