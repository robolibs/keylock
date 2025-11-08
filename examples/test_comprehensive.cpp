#include "lockey/lockey.hpp"
#include <cassert>
#include <cstdio>
#include <iostream>

void print_hex(const std::string &label, const std::vector<uint8_t> &data) {
    std::cout << label << ": ";
    for (uint8_t byte : data)
        printf("%02x", byte);
    std::cout << '\n';
}

int main() {
    std::cout << "Comprehensive Lockey (libsodium) demo\n";
    std::cout << "=====================================\n\n";

    const std::string message = "Test message for libsodium-backed Lockey";
    const std::vector<uint8_t> payload(message.begin(), message.end());

    // Symmetric encryption with XChaCha20-Poly1305
    {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::XChaCha20_Poly1305);
        auto key = crypto.generate_symmetric_key(lockey::utils::Common::XCHACHA20_KEY_SIZE);
        assert(key.success);

        auto ciphertext = crypto.encrypt(payload, key.data);
        assert(ciphertext.success);
        auto plaintext = crypto.decrypt(ciphertext.data, key.data);
        assert(plaintext.success && plaintext.data == payload);

        std::cout << "✓ XChaCha20-Poly1305 round-trip succeeded\n";
    }

    // SecretBox XSalsa20-Poly1305
    {
        lockey::Lockey crypto(lockey::Lockey::Algorithm::SecretBox_XSalsa20);
        auto key = crypto.generate_symmetric_key(lockey::utils::Common::SECRETBOX_KEY_SIZE);
        assert(key.success);
        auto ciphertext = crypto.encrypt(payload, key.data);
        assert(ciphertext.success);
        auto plaintext = crypto.decrypt(ciphertext.data, key.data);
        assert(plaintext.success && plaintext.data == payload);
        std::cout << "✓ SecretBox XSalsa20-Poly1305 round-trip succeeded\n";
    }

    // Hashing
    {
        lockey::Lockey sha256(lockey::Lockey::Algorithm::XChaCha20_Poly1305,
                              lockey::Lockey::HashAlgorithm::SHA256);
        auto digest256 = sha256.hash(payload);
        assert(digest256.success && digest256.data.size() == lockey::utils::Common::SHA256_DIGEST_SIZE);

        lockey::Lockey blake(lockey::Lockey::Algorithm::XChaCha20_Poly1305,
                             lockey::Lockey::HashAlgorithm::BLAKE2b);
        auto digestBlake = blake.hash(payload);
        assert(digestBlake.success && digestBlake.data.size() == lockey::utils::Common::BLAKE2B_DIGEST_SIZE);

        std::cout << "✓ Hashing (SHA-256 + BLAKE2b) succeeded\n";
    }

    // X25519 Box encryption
    {
        lockey::Lockey box(lockey::Lockey::Algorithm::X25519_Box);
        auto sender = box.generate_keypair();
        auto ciphertext = box.encrypt_asymmetric(payload, sender.public_key);
        assert(ciphertext.success);
        auto plaintext = box.decrypt_asymmetric(ciphertext.data, sender.private_key);
        assert(plaintext.success && plaintext.data == payload);
        std::cout << "✓ X25519 box seal/open succeeded\n";
    }

    // Ed25519 signatures
    {
        lockey::Lockey signer(lockey::Lockey::Algorithm::Ed25519);
        auto keypair = signer.generate_keypair();

        auto signature = signer.sign(payload, keypair.private_key);
        assert(signature.success && signature.data.size() == crypto_sign_ed25519_BYTES);

        auto verified = signer.verify(payload, signature.data, keypair.public_key);
        assert(verified.success);

        std::cout << "✓ Ed25519 signing/verification succeeded\n";
    }

    // Utility helpers
    {
        auto hex = lockey::Lockey::to_hex(payload);
        auto decoded = lockey::Lockey::from_hex(hex);
        assert(decoded == payload);

        std::cout << "✓ Utility conversions round-trip\n";
        print_hex("Payload hex", payload);
    }

    std::cout << "\nAll libsodium-backed demonstrations passed.\n";
    return 0;
}
