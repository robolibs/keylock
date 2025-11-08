#include "lockey/lockey.hpp"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <stdexcept>

#include <sodium.h>

#include "lockey/utils/sodium_utils.hpp"

namespace {

using lockey::Lockey;
using Algorithm = Lockey::Algorithm;
using CryptoResult = Lockey::CryptoResult;
using HashAlgorithm = Lockey::HashAlgorithm;
using KeyType = Lockey::KeyType;

using lockey::utils::Common;
using lockey::utils::ensure_sodium_init;

std::vector<uint8_t> normalize_key(const std::vector<uint8_t> &key, size_t required) {
    if (key.size() == required) {
        return key;
    }

    std::vector<uint8_t> normalized(required);
    crypto_generichash(normalized.data(), normalized.size(), key.data(), key.size(), nullptr, 0);
    return normalized;
}

CryptoResult aead_xchacha_encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key,
                                  const std::vector<uint8_t> &aad) {
    try {
        auto normalized_key = normalize_key(key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

        std::vector<uint8_t> nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        randombytes_buf(nonce.data(), nonce.size());

        std::vector<uint8_t> ciphertext(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
        unsigned long long ciphertext_len = 0;

        if (crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext.data(), &ciphertext_len, plaintext.data(),
                                                       plaintext.size(), aad.data(), aad.size(), nullptr, nonce.data(),
                                                       normalized_key.data()) != 0) {
            return {false, {}, "AEAD encryption failed"};
        }

        ciphertext.resize(ciphertext_len);
        std::vector<uint8_t> result;
        result.reserve(nonce.size() + ciphertext.size());
        result.insert(result.end(), nonce.begin(), nonce.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());
        return {true, result, ""};
    } catch (const std::exception &e) {
        return {false, {}, e.what()};
    }
}

CryptoResult aead_xchacha_decrypt(const std::vector<uint8_t> &ciphertext_with_nonce, const std::vector<uint8_t> &key,
                                  const std::vector<uint8_t> &aad) {
    try {
        if (ciphertext_with_nonce.size() <
            crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES) {
            return {false, {}, "Ciphertext too short"};
        }

        auto normalized_key = normalize_key(key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
        std::vector<uint8_t> nonce(ciphertext_with_nonce.begin(),
                                   ciphertext_with_nonce.begin() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        std::vector<uint8_t> ciphertext(ciphertext_with_nonce.begin() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
                                        ciphertext_with_nonce.end());

        if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
            return {false, {}, "Ciphertext too short"};
        }

        std::vector<uint8_t> plaintext(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
        unsigned long long plaintext_len = 0;

        if (crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext.data(), &plaintext_len, nullptr, ciphertext.data(),
                                                       ciphertext.size(), aad.data(), aad.size(), nonce.data(),
                                                       normalized_key.data()) != 0) {
            return {false, {}, "Authentication failed"};
        }

        plaintext.resize(plaintext_len);
        return {true, plaintext, ""};
    } catch (const std::exception &e) {
        return {false, {}, e.what()};
    }
}

CryptoResult secretbox_encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key) {
    try {
        auto normalized_key = normalize_key(key, crypto_secretbox_KEYBYTES);
        std::vector<uint8_t> nonce(crypto_secretbox_NONCEBYTES);
        randombytes_buf(nonce.data(), nonce.size());

        std::vector<uint8_t> ciphertext(crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + plaintext.size());
        std::copy(nonce.begin(), nonce.end(), ciphertext.begin());

        if (crypto_secretbox_easy(ciphertext.data() + crypto_secretbox_NONCEBYTES, plaintext.data(), plaintext.size(),
                                  nonce.data(), normalized_key.data()) != 0) {
            return {false, {}, "SecretBox encryption failed"};
        }

        return {true, ciphertext, ""};
    } catch (const std::exception &e) {
        return {false, {}, e.what()};
    }
}

CryptoResult secretbox_decrypt(const std::vector<uint8_t> &ciphertext_with_nonce, const std::vector<uint8_t> &key) {
    try {
        if (ciphertext_with_nonce.size() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
            return {false, {}, "Ciphertext too short"};
        }

        auto normalized_key = normalize_key(key, crypto_secretbox_KEYBYTES);
        std::vector<uint8_t> nonce(ciphertext_with_nonce.begin(),
                                   ciphertext_with_nonce.begin() + crypto_secretbox_NONCEBYTES);
        std::vector<uint8_t> ciphertext(ciphertext_with_nonce.begin() + crypto_secretbox_NONCEBYTES,
                                        ciphertext_with_nonce.end());

        std::vector<uint8_t> plaintext(ciphertext.size() - crypto_secretbox_MACBYTES);
        if (crypto_secretbox_open_easy(plaintext.data(), ciphertext.data(), ciphertext.size(), nonce.data(),
                                       normalized_key.data()) != 0) {
            return {false, {}, "SecretBox decryption failed"};
        }

        return {true, plaintext, ""};
    } catch (const std::exception &e) {
        return {false, {}, e.what()};
    }
}

} // namespace

namespace lockey {

Lockey::Lockey(Algorithm algorithm, HashAlgorithm hash_algo)
    : current_algorithm_(algorithm), current_hash_(hash_algo) {
    ensure_sodium_init();
}

void Lockey::set_algorithm(Algorithm algorithm) { current_algorithm_ = algorithm; }

void Lockey::set_hash_algorithm(HashAlgorithm hash_algo) { current_hash_ = hash_algo; }

Lockey::Algorithm Lockey::get_algorithm() const { return current_algorithm_; }

Lockey::HashAlgorithm Lockey::get_hash_algorithm() const { return current_hash_; }

Lockey::CryptoResult Lockey::encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key,
                                     const std::vector<uint8_t> &associated_data) {
    if (!is_symmetric_algorithm(current_algorithm_)) {
        return {false, {}, "Current algorithm is not suitable for symmetric encryption"};
    }

    ensure_sodium_init();

    if (current_algorithm_ == Algorithm::XChaCha20_Poly1305) {
        return aead_xchacha_encrypt(plaintext, key, associated_data);
    }

    return secretbox_encrypt(plaintext, key);
}

Lockey::CryptoResult Lockey::decrypt(const std::vector<uint8_t> &ciphertext, const std::vector<uint8_t> &key,
                                     const std::vector<uint8_t> &associated_data) {
    if (!is_symmetric_algorithm(current_algorithm_)) {
        return {false, {}, "Current algorithm is not suitable for symmetric decryption"};
    }

    ensure_sodium_init();

    if (current_algorithm_ == Algorithm::XChaCha20_Poly1305) {
        return aead_xchacha_decrypt(ciphertext, key, associated_data);
    }

    return secretbox_decrypt(ciphertext, key);
}

Lockey::CryptoResult Lockey::encrypt_asymmetric(const std::vector<uint8_t> &plaintext,
                                                const std::vector<uint8_t> &public_key) {
    if (!is_asymmetric_algorithm(current_algorithm_)) {
        return {false, {}, "Current algorithm does not support asymmetric encryption"};
    }

    ensure_sodium_init();

    if (public_key.size() != crypto_box_PUBLICKEYBYTES) {
        return {false, {}, "Invalid public key size"};
    }

    std::vector<uint8_t> ciphertext(plaintext.size() + crypto_box_SEALBYTES);
    if (crypto_box_seal(ciphertext.data(), plaintext.data(), plaintext.size(), public_key.data()) != 0) {
        return {false, {}, "crypto_box_seal failed"};
    }

    return {true, ciphertext, ""};
}

Lockey::CryptoResult Lockey::decrypt_asymmetric(const std::vector<uint8_t> &ciphertext,
                                                const std::vector<uint8_t> &private_key) {
    if (!is_asymmetric_algorithm(current_algorithm_)) {
        return {false, {}, "Current algorithm does not support asymmetric decryption"};
    }

    ensure_sodium_init();

    if (private_key.size() != crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES) {
        return {false, {}, "Invalid private key material"};
    }

    if (ciphertext.size() < crypto_box_SEALBYTES) {
        return {false, {}, "Ciphertext too short"};
    }

    std::vector<uint8_t> plaintext(ciphertext.size() - crypto_box_SEALBYTES);
    const uint8_t *pub = private_key.data();
    const uint8_t *sec = private_key.data() + crypto_box_PUBLICKEYBYTES;
    if (crypto_box_seal_open(plaintext.data(), ciphertext.data(), ciphertext.size(), pub, sec) != 0) {
        return {false, {}, "Decryption failed"};
    }

    return {true, plaintext, ""};
}

Lockey::KeyPair Lockey::generate_keypair() {
    ensure_sodium_init();

    switch (current_algorithm_) {
    case Algorithm::X25519_Box: {
        std::vector<uint8_t> pub(crypto_box_PUBLICKEYBYTES);
        std::vector<uint8_t> sec(crypto_box_SECRETKEYBYTES);
        if (crypto_box_keypair(pub.data(), sec.data()) != 0) {
            throw std::runtime_error("Failed to generate X25519 keypair");
        }
        KeyPair pair;
        pair.algorithm = current_algorithm_;
        pair.public_key = pub;
        pair.private_key = pub;
        pair.private_key.insert(pair.private_key.end(), sec.begin(), sec.end());
        return pair;
    }
    case Algorithm::Ed25519: {
        std::vector<uint8_t> pub(crypto_sign_ed25519_PUBLICKEYBYTES);
        std::vector<uint8_t> sec(crypto_sign_ed25519_SECRETKEYBYTES);
        if (crypto_sign_ed25519_keypair(pub.data(), sec.data()) != 0) {
            throw std::runtime_error("Failed to generate Ed25519 keypair");
        }
        KeyPair pair;
        pair.algorithm = current_algorithm_;
        pair.public_key = std::move(pub);
        pair.private_key = std::move(sec);
        return pair;
    }
    default:
        throw std::runtime_error("Key generation not supported for this algorithm");
    }
}

Lockey::CryptoResult Lockey::generate_symmetric_key(size_t key_size) {
    try {
        ensure_sodium_init();
        std::vector<uint8_t> key(key_size);
        randombytes_buf(key.data(), key.size());
        return {true, key, ""};
    } catch (const std::exception &e) {
        return {false, {}, e.what()};
    }
}

Lockey::CryptoResult Lockey::sign(const std::vector<uint8_t> &data, const std::vector<uint8_t> &private_key) {
    if (!is_signature_algorithm(current_algorithm_)) {
        return {false, {}, "Current algorithm does not support signing"};
    }

    ensure_sodium_init();

    if (private_key.size() != crypto_sign_ed25519_SECRETKEYBYTES) {
        return {false, {}, "Invalid private key size"};
    }

    std::vector<uint8_t> signature(crypto_sign_ed25519_BYTES);
    unsigned long long sig_len = 0;
    if (crypto_sign_ed25519_detached(signature.data(), &sig_len, data.data(), data.size(), private_key.data()) != 0) {
        return {false, {}, "Ed25519 signing failed"};
    }

    signature.resize(sig_len);
    return {true, signature, ""};
}

Lockey::CryptoResult Lockey::verify(const std::vector<uint8_t> &data, const std::vector<uint8_t> &signature,
                                    const std::vector<uint8_t> &public_key) {
    if (!is_signature_algorithm(current_algorithm_)) {
        return {false, {}, "Current algorithm does not support verification"};
    }

    ensure_sodium_init();

    if (public_key.size() != crypto_sign_ed25519_PUBLICKEYBYTES) {
        return {false, {}, "Invalid public key size"};
    }

    int rc = crypto_sign_ed25519_verify_detached(signature.data(), data.data(), data.size(), public_key.data());
    return {rc == 0, {}, rc == 0 ? "" : "Ed25519 signature verification failed"};
}

Lockey::CryptoResult Lockey::hash(const std::vector<uint8_t> &data) {
    ensure_sodium_init();

    switch (current_hash_) {
    case HashAlgorithm::SHA256: {
        std::vector<uint8_t> digest(crypto_hash_sha256_BYTES);
        crypto_hash_sha256(digest.data(), data.data(), data.size());
        return {true, digest, ""};
    }
    case HashAlgorithm::SHA512: {
        std::vector<uint8_t> digest(crypto_hash_sha512_BYTES);
        crypto_hash_sha512(digest.data(), data.data(), data.size());
        return {true, digest, ""};
    }
    case HashAlgorithm::BLAKE2b: {
        std::vector<uint8_t> digest(crypto_generichash_BYTES);
        crypto_generichash(digest.data(), digest.size(), data.data(), data.size(), nullptr, 0);
        return {true, digest, ""};
    }
    }
    return {false, {}, "Unsupported hash algorithm"};
}

Lockey::CryptoResult Lockey::hmac(const std::vector<uint8_t> &data, const std::vector<uint8_t> &key) {
    ensure_sodium_init();

    switch (current_hash_) {
    case HashAlgorithm::SHA256: {
        std::vector<uint8_t> mac(crypto_auth_hmacsha256_BYTES);
        crypto_auth_hmacsha256_state state;
        crypto_auth_hmacsha256_init(&state, key.data(), key.size());
        crypto_auth_hmacsha256_update(&state, data.data(), data.size());
        crypto_auth_hmacsha256_final(&state, mac.data());
        return {true, mac, ""};
    }
    case HashAlgorithm::SHA512: {
        std::vector<uint8_t> mac(crypto_auth_hmacsha512_BYTES);
        crypto_auth_hmacsha512_state state;
        crypto_auth_hmacsha512_init(&state, key.data(), key.size());
        crypto_auth_hmacsha512_update(&state, data.data(), data.size());
        crypto_auth_hmacsha512_final(&state, mac.data());
        return {true, mac, ""};
    }
    case HashAlgorithm::BLAKE2b: {
        if (key.empty()) {
            return {false, {}, "BLAKE2b HMAC requires non-empty key"};
        }
        std::vector<uint8_t> mac(crypto_generichash_BYTES);
        crypto_generichash(mac.data(), mac.size(), data.data(), data.size(), key.data(), key.size());
        return {true, mac, ""};
    }
    }

    return {false, {}, "Unsupported hash algorithm"};
}

bool Lockey::save_key_to_file(const std::vector<uint8_t> &key, const std::string &filename, KeyType, utils::KeyFormat) {
    try {
        std::ofstream file(filename, std::ios::binary);
        if (!file)
            return false;
        file.write(reinterpret_cast<const char *>(key.data()), key.size());
        return file.good();
    } catch (...) {
        return false;
    }
}

Lockey::CryptoResult Lockey::load_key_from_file(const std::string &filename, KeyType key_type) {
    try {
        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            return {false, {}, "Cannot open file"};
        }
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        if (data.empty()) {
            return {false, {}, "File empty"};
        }

        if (auto expected = expected_key_size(key_type)) {
            if (data.size() != *expected) {
                return {false, {}, "Unexpected key size"};
            }
        }
        return {true, data, ""};
    } catch (const std::exception &e) {
        return {false, {}, e.what()};
    }
}

bool Lockey::save_keypair_to_files(const KeyPair &keypair, const std::string &public_filename,
                                   const std::string &private_filename, utils::KeyFormat format) {
    return save_key_to_file(keypair.public_key, public_filename, KeyType::PUBLIC, format) &&
           save_key_to_file(keypair.private_key, private_filename, KeyType::PRIVATE, format);
}

Lockey::CryptoResult Lockey::load_keypair_from_files(const std::string &public_filename,
                                                     const std::string &private_filename) {
    auto pub = load_key_from_file(public_filename, KeyType::PUBLIC);
    if (!pub.success)
        return pub;

    auto priv = load_key_from_file(private_filename, KeyType::PRIVATE);
    if (!priv.success)
        return priv;

    return {true, priv.data, ""};
}

std::string Lockey::to_hex(const std::vector<uint8_t> &data) { return Common::bytes_to_hex(data); }

std::vector<uint8_t> Lockey::from_hex(const std::string &hex) { return Common::hex_to_bytes(hex); }

std::string Lockey::algorithm_to_string(Algorithm algorithm) {
    switch (algorithm) {
    case Algorithm::XChaCha20_Poly1305:
        return "XChaCha20-Poly1305";
    case Algorithm::SecretBox_XSalsa20:
        return "SecretBox-XSalsa20-Poly1305";
    case Algorithm::X25519_Box:
        return "X25519-Box";
    case Algorithm::Ed25519:
        return "Ed25519";
    }
    return "Unknown";
}

std::string Lockey::hash_algorithm_to_string(HashAlgorithm hash_algo) {
    switch (hash_algo) {
    case HashAlgorithm::SHA256:
        return "SHA-256";
    case HashAlgorithm::SHA512:
        return "SHA-512";
    case HashAlgorithm::BLAKE2b:
        return "BLAKE2b";
    }
    return "Unknown";
}

std::optional<size_t> Lockey::expected_key_size(KeyType key_type) const {
    switch (current_algorithm_) {
    case Algorithm::X25519_Box:
        if (key_type == KeyType::PUBLIC)
            return crypto_box_PUBLICKEYBYTES;
        return crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;
    case Algorithm::Ed25519:
        if (key_type == KeyType::PUBLIC)
            return crypto_sign_ed25519_PUBLICKEYBYTES;
        return crypto_sign_ed25519_SECRETKEYBYTES;
    case Algorithm::XChaCha20_Poly1305:
    case Algorithm::SecretBox_XSalsa20:
        break;
    }
    return std::nullopt;
}

bool Lockey::is_symmetric_algorithm(Algorithm algo) const {
    return algo == Algorithm::XChaCha20_Poly1305 || algo == Algorithm::SecretBox_XSalsa20;
}

bool Lockey::is_asymmetric_algorithm(Algorithm algo) const { return algo == Algorithm::X25519_Box; }

bool Lockey::is_signature_algorithm(Algorithm algo) const { return algo == Algorithm::Ed25519; }

} // namespace lockey
