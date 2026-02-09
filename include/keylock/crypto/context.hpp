#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "keylock/crypto/common.hpp"
#include "keylock/hash/blake2b/blake2b.hpp"
#include "keylock/hash/context.hpp"

// Our crypto implementations
#include "keylock/crypto/aead_aes256gcm/aead.hpp"
#include "keylock/crypto/aead_chacha20poly1305_ietf/aead.hpp"
#include "keylock/crypto/aead_xchacha20poly1305_ietf/aead.hpp"
#include "keylock/crypto/box_seal_x25519/seal.hpp"
#include "keylock/crypto/rng/randombytes.hpp"
#include "keylock/crypto/secretbox_xsalsa20poly1305/secretbox.hpp"
#include "keylock/crypto/sign_ecdsa_p256/ecdsa_der.hpp"
#include "keylock/crypto/sign_ecdsa_p256/ecdsa_p256.hpp"
#include "keylock/crypto/sign_ed25519/ed25519.hpp"
#include "keylock/crypto/sign_rsa/rsa_keygen.hpp"
#include "keylock/crypto/sign_rsa/rsa_keys.hpp"
#include "keylock/crypto/sign_rsa/rsa_oaep.hpp"
#include "keylock/crypto/sign_rsa/rsa_pkcs1.hpp"
#include "keylock/crypto/sign_rsa/rsa_pkcs1v15.hpp"
#include "keylock/crypto/sign_rsa/rsa_pss.hpp"

namespace keylock::crypto {

    namespace detail {

        struct FileLoadResult {
            bool success;
            std::vector<uint8_t> data;
            std::string error_message;
        };

        inline bool write_binary(const std::vector<uint8_t> &data, const std::string &path) {
            try {
                std::ofstream file(path, std::ios::binary);
                if (!file) {
                    return false;
                }
                file.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
                return file.good();
            } catch (...) {
                return false;
            }
        }

        inline FileLoadResult read_binary(const std::string &path) {
            try {
                std::ifstream file(path, std::ios::binary);
                if (!file) {
                    return {false, {}, "Cannot open file"};
                }
                std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                if (data.empty()) {
                    return {false, {}, "File empty"};
                }
                return {true, std::move(data), ""};
            } catch (const std::exception &e) {
                return {false, {}, e.what()};
            }
        }

        inline std::vector<uint8_t> normalize_key(const std::vector<uint8_t> &key, size_t required) {
            if (key.size() == required) {
                return key;
            }
            std::vector<uint8_t> normalized(required);
            hash::blake2b::hash(normalized.data(), normalized.size(), key.data(), key.size());
            return normalized;
        }

        inline void append_u32_be(std::vector<uint8_t> &out, uint32_t value) {
            out.push_back(static_cast<uint8_t>((value >> 24) & 0xff));
            out.push_back(static_cast<uint8_t>((value >> 16) & 0xff));
            out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
            out.push_back(static_cast<uint8_t>(value & 0xff));
        }

        inline bool read_u32_be(const std::vector<uint8_t> &in, size_t &offset, uint32_t &value) {
            if (offset + 4 > in.size()) {
                return false;
            }
            value = (static_cast<uint32_t>(in[offset]) << 24) | (static_cast<uint32_t>(in[offset + 1]) << 16) |
                    (static_cast<uint32_t>(in[offset + 2]) << 8) | static_cast<uint32_t>(in[offset + 3]);
            offset += 4;
            return true;
        }

        inline std::string dp_error_message(const dp::Error &error) { return std::string(error.message.c_str()); }

        inline int compare_be_bytes(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b) {
            if (a.size() != b.size()) {
                return a.size() < b.size() ? -1 : 1;
            }
            for (size_t i = 0; i < a.size(); ++i) {
                if (a[i] < b[i]) {
                    return -1;
                }
                if (a[i] > b[i]) {
                    return 1;
                }
            }
            return 0;
        }

        inline bool is_zero_bytes(const std::vector<uint8_t> &x) {
            for (uint8_t b : x) {
                if (b != 0) {
                    return false;
                }
            }
            return true;
        }

        inline std::vector<uint8_t> encode_rsa_public_key_blob_raw(const std::vector<uint8_t> &modulus,
                                                                   const std::vector<uint8_t> &public_exponent) {
            std::vector<uint8_t> out;
            out.reserve(8 + modulus.size() + public_exponent.size());
            append_u32_be(out, static_cast<uint32_t>(modulus.size()));
            out.insert(out.end(), modulus.begin(), modulus.end());
            append_u32_be(out, static_cast<uint32_t>(public_exponent.size()));
            out.insert(out.end(), public_exponent.begin(), public_exponent.end());
            return out;
        }

        inline std::vector<uint8_t> encode_rsa_private_key_blob_raw(const std::vector<uint8_t> &modulus,
                                                                    const std::vector<uint8_t> &public_exponent,
                                                                    const std::vector<uint8_t> &private_exponent) {
            auto out = encode_rsa_public_key_blob_raw(modulus, public_exponent);
            append_u32_be(out, static_cast<uint32_t>(private_exponent.size()));
            out.insert(out.end(), private_exponent.begin(), private_exponent.end());
            return out;
        }

        inline bool decode_rsa_public_key_blob_raw(const std::vector<uint8_t> &blob, sign_rsa::RsaPublicKey &out_key,
                                                   std::string &error) {
            size_t offset = 0;
            uint32_t n_len = 0;
            uint32_t e_len = 0;

            if (!read_u32_be(blob, offset, n_len)) {
                error = "RSA key blob missing modulus length";
                return false;
            }
            if (n_len == 0) {
                error = "RSA key blob has empty modulus";
                return false;
            }
            if (offset + n_len > blob.size()) {
                error = "RSA key blob modulus truncated";
                return false;
            }
            out_key.modulus.assign(blob.begin() + static_cast<std::ptrdiff_t>(offset),
                                   blob.begin() + static_cast<std::ptrdiff_t>(offset + n_len));
            offset += n_len;

            if (!read_u32_be(blob, offset, e_len)) {
                error = "RSA key blob missing exponent length";
                return false;
            }
            if (e_len == 0) {
                error = "RSA key blob has empty exponent";
                return false;
            }
            if (offset + e_len > blob.size()) {
                error = "RSA key blob exponent truncated";
                return false;
            }
            out_key.public_exponent.assign(blob.begin() + static_cast<std::ptrdiff_t>(offset),
                                           blob.begin() + static_cast<std::ptrdiff_t>(offset + e_len));
            offset += e_len;

            if (offset != blob.size()) {
                error = "RSA key blob has trailing bytes";
                return false;
            }
            return true;
        }

        inline bool decode_rsa_private_key_blob_raw(const std::vector<uint8_t> &blob, sign_rsa::RsaPrivateKey &out_key,
                                                    std::string &error) {
            size_t offset = 0;
            uint32_t n_len = 0;
            uint32_t e_len = 0;
            uint32_t d_len = 0;

            if (!read_u32_be(blob, offset, n_len)) {
                error = "RSA private key blob missing modulus length";
                return false;
            }
            if (n_len == 0) {
                error = "RSA private key blob has empty modulus";
                return false;
            }
            if (offset + n_len > blob.size()) {
                error = "RSA private key blob modulus truncated";
                return false;
            }
            out_key.modulus.assign(blob.begin() + static_cast<std::ptrdiff_t>(offset),
                                   blob.begin() + static_cast<std::ptrdiff_t>(offset + n_len));
            offset += n_len;

            if (!read_u32_be(blob, offset, e_len)) {
                error = "RSA private key blob missing exponent length";
                return false;
            }
            if (e_len == 0) {
                error = "RSA private key blob has empty exponent";
                return false;
            }
            if (offset + e_len > blob.size()) {
                error = "RSA private key blob exponent truncated";
                return false;
            }
            out_key.public_exponent.assign(blob.begin() + static_cast<std::ptrdiff_t>(offset),
                                           blob.begin() + static_cast<std::ptrdiff_t>(offset + e_len));
            offset += e_len;

            if (!read_u32_be(blob, offset, d_len)) {
                error = "RSA private key blob missing private exponent length";
                return false;
            }
            if (d_len == 0) {
                error = "RSA private key blob has empty private exponent";
                return false;
            }
            if (offset + d_len > blob.size()) {
                error = "RSA private key blob private exponent truncated";
                return false;
            }
            out_key.private_exponent.assign(blob.begin() + static_cast<std::ptrdiff_t>(offset),
                                            blob.begin() + static_cast<std::ptrdiff_t>(offset + d_len));
            offset += d_len;

            if (offset != blob.size()) {
                error = "RSA private key blob has trailing bytes";
                return false;
            }
            return true;
        }

    } // namespace detail

    class Context {
      public:
        using HashAlgorithm = hash::Algorithm;

        enum class Algorithm {
            XChaCha20_Poly1305,
            ChaCha20_Poly1305,
            AES256_GCM,
            SecretBox_XSalsa20,
            X25519_Box,
            Ed25519,
            RSA_PKCS1v15_SHA256,
            RSA_PSS_SHA256,
            RSA_PKCS1v15_SHA384,
            RSA_PSS_SHA384,
            RSA_PKCS1v15_SHA512,
            RSA_PSS_SHA512,
            RSA_OAEP_SHA256,
            RSA_OAEP_SHA384,
            RSA_OAEP_SHA512,
            ECDSA_P256_SHA256
        };

        enum class KeyType { PUBLIC, PRIVATE };

        struct CryptoResult {
            bool success;
            std::vector<uint8_t> data;
            std::string error_message;
        };

        struct KeyPair {
            std::vector<uint8_t> public_key;
            std::vector<uint8_t> private_key;
            Algorithm algorithm;
        };

        explicit Context(Algorithm algorithm = Algorithm::XChaCha20_Poly1305,
                         HashAlgorithm hash_algo = HashAlgorithm::SHA256)
            : current_algorithm_(algorithm), current_hash_(hash_algo) {}

        void set_algorithm(Algorithm algorithm) { current_algorithm_ = algorithm; }
        void set_hash_algorithm(HashAlgorithm hash_algo) { current_hash_ = hash_algo; }
        [[nodiscard]] Algorithm get_algorithm() const { return current_algorithm_; }
        [[nodiscard]] HashAlgorithm get_hash_algorithm() const { return current_hash_; }

        CryptoResult encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key,
                             const std::vector<uint8_t> &associated_data = {}) {
            if (!is_symmetric_algorithm(current_algorithm_)) {
                return {false, {}, "Current algorithm is not suitable for symmetric encryption"};
            }

            switch (current_algorithm_) {
            case Algorithm::XChaCha20_Poly1305:
                return aead_xchacha_encrypt(plaintext, key, associated_data);
            case Algorithm::ChaCha20_Poly1305:
                return aead_chacha_ietf_encrypt(plaintext, key, associated_data);
            case Algorithm::AES256_GCM:
                return aead_aes256gcm_encrypt(plaintext, key, associated_data);
            case Algorithm::SecretBox_XSalsa20:
                return secretbox_encrypt(plaintext, key);
            default:
                return {false, {}, "Unsupported symmetric algorithm"};
            }
        }

        CryptoResult decrypt(const std::vector<uint8_t> &ciphertext, const std::vector<uint8_t> &key,
                             const std::vector<uint8_t> &associated_data = {}) {
            if (!is_symmetric_algorithm(current_algorithm_)) {
                return {false, {}, "Current algorithm is not suitable for symmetric decryption"};
            }

            switch (current_algorithm_) {
            case Algorithm::XChaCha20_Poly1305:
                return aead_xchacha_decrypt(ciphertext, key, associated_data);
            case Algorithm::ChaCha20_Poly1305:
                return aead_chacha_ietf_decrypt(ciphertext, key, associated_data);
            case Algorithm::AES256_GCM:
                return aead_aes256gcm_decrypt(ciphertext, key, associated_data);
            case Algorithm::SecretBox_XSalsa20:
                return secretbox_decrypt(ciphertext, key);
            default:
                return {false, {}, "Unsupported symmetric algorithm"};
            }
        }

        CryptoResult encrypt_asymmetric(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &public_key) {
            if (!is_asymmetric_algorithm(current_algorithm_)) {
                return {false, {}, "Current algorithm does not support asymmetric encryption"};
            }

            if (current_algorithm_ == Algorithm::X25519_Box) {
                if (public_key.size() != box_seal::PUBLICKEYBYTES) {
                    return {false, {}, "Invalid public key size"};
                }

                std::vector<uint8_t> ciphertext(plaintext.size() + box_seal::SEALBYTES);
                if (box_seal::seal(ciphertext.data(), plaintext.data(), plaintext.size(), public_key.data()) != 0) {
                    return {false, {}, "seal failed"};
                }

                return {true, ciphertext, ""};
            }

            sign_rsa::RsaPublicKey rsa_key;
            std::string decode_error;
            if (!detail::decode_rsa_public_key_blob_raw(public_key, rsa_key, decode_error)) {
                return {false, {}, decode_error};
            }

            sign_common::SignatureHashAlgorithm hash_alg = sign_common::SignatureHashAlgorithm::SHA256;
            if (current_algorithm_ == Algorithm::RSA_OAEP_SHA384) {
                hash_alg = sign_common::SignatureHashAlgorithm::SHA384;
            } else if (current_algorithm_ == Algorithm::RSA_OAEP_SHA512) {
                hash_alg = sign_common::SignatureHashAlgorithm::SHA512;
            }

            auto ct =
                sign_rsa::oaep::encrypt(dp::Vector<dp::u8>(plaintext.begin(), plaintext.end()), rsa_key, hash_alg);
            if (ct.is_err()) {
                return {false, {}, detail::dp_error_message(ct.error())};
            }
            return {true, std::vector<uint8_t>(ct.value().begin(), ct.value().end()), ""};
        }

        CryptoResult decrypt_asymmetric(const std::vector<uint8_t> &ciphertext,
                                        const std::vector<uint8_t> &private_key) {
            if (!is_asymmetric_algorithm(current_algorithm_)) {
                return {false, {}, "Current algorithm does not support asymmetric decryption"};
            }

            if (current_algorithm_ == Algorithm::X25519_Box) {
                if (private_key.size() != box_seal::PUBLICKEYBYTES + box_seal::SECRETKEYBYTES) {
                    return {false, {}, "Invalid private key material"};
                }

                if (ciphertext.size() < box_seal::SEALBYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                std::vector<uint8_t> plaintext(ciphertext.size() - box_seal::SEALBYTES);
                const uint8_t *pub = private_key.data();
                const uint8_t *sec = private_key.data() + box_seal::PUBLICKEYBYTES;
                if (box_seal::seal_open(plaintext.data(), ciphertext.data(), ciphertext.size(), pub, sec) != 0) {
                    return {false, {}, "Decryption failed"};
                }

                return {true, plaintext, ""};
            }

            sign_rsa::RsaPrivateKey rsa_key;
            std::string decode_error;
            if (!detail::decode_rsa_private_key_blob_raw(private_key, rsa_key, decode_error)) {
                return {false, {}, decode_error};
            }

            sign_common::SignatureHashAlgorithm hash_alg = sign_common::SignatureHashAlgorithm::SHA256;
            if (current_algorithm_ == Algorithm::RSA_OAEP_SHA384) {
                hash_alg = sign_common::SignatureHashAlgorithm::SHA384;
            } else if (current_algorithm_ == Algorithm::RSA_OAEP_SHA512) {
                hash_alg = sign_common::SignatureHashAlgorithm::SHA512;
            }

            auto pt =
                sign_rsa::oaep::decrypt(dp::Vector<dp::u8>(ciphertext.begin(), ciphertext.end()), rsa_key, hash_alg);
            if (pt.is_err()) {
                return {false, {}, detail::dp_error_message(pt.error())};
            }
            return {true, std::vector<uint8_t>(pt.value().begin(), pt.value().end()), ""};
        }

        CryptoResult sign(const std::vector<uint8_t> &data, const std::vector<uint8_t> &private_key) {
            if (!is_signature_algorithm(current_algorithm_)) {
                return {false, {}, "Current algorithm does not support signing"};
            }

            switch (current_algorithm_) {
            case Algorithm::Ed25519: {
                if (private_key.size() != ed25519::SECRETKEYBYTES) {
                    return {false, {}, "Invalid private key size"};
                }

                std::vector<uint8_t> signature(ed25519::BYTES);
                unsigned long long sig_len = 0;
                if (ed25519::sign_detached(signature.data(), &sig_len, data.data(), data.size(), private_key.data()) !=
                    0) {
                    return {false, {}, "Ed25519 signing failed"};
                }

                signature.resize(sig_len);
                return {true, signature, ""};
            }
            case Algorithm::RSA_PKCS1v15_SHA256:
            case Algorithm::RSA_PSS_SHA256:
            case Algorithm::RSA_PKCS1v15_SHA384:
            case Algorithm::RSA_PSS_SHA384:
            case Algorithm::RSA_PKCS1v15_SHA512:
            case Algorithm::RSA_PSS_SHA512:
            case Algorithm::RSA_OAEP_SHA256:
            case Algorithm::RSA_OAEP_SHA384:
            case Algorithm::RSA_OAEP_SHA512: {
                sign_rsa::RsaPrivateKey rsa_key;
                std::string decode_error;
                if (!detail::decode_rsa_private_key_blob_raw(private_key, rsa_key, decode_error)) {
                    return {false, {}, decode_error};
                }

                const dp::Vector<dp::u8> msg(data.begin(), data.end());
                if (current_algorithm_ == Algorithm::RSA_PKCS1v15_SHA256 ||
                    current_algorithm_ == Algorithm::RSA_PKCS1v15_SHA384 ||
                    current_algorithm_ == Algorithm::RSA_PKCS1v15_SHA512) {
                    const auto hash_alg = current_algorithm_ == Algorithm::RSA_PKCS1v15_SHA256
                                              ? sign_common::SignatureHashAlgorithm::SHA256
                                              : (current_algorithm_ == Algorithm::RSA_PKCS1v15_SHA384
                                                     ? sign_common::SignatureHashAlgorithm::SHA384
                                                     : sign_common::SignatureHashAlgorithm::SHA512);
                    auto sig = sign_rsa::pkcs1v15::sign(msg, rsa_key, hash_alg);
                    if (sig.is_err()) {
                        return {false, {}, detail::dp_error_message(sig.error())};
                    }
                    return {true, std::vector<uint8_t>(sig.value().begin(), sig.value().end()), ""};
                }

                const auto hash_alg = current_algorithm_ == Algorithm::RSA_PSS_SHA256
                                          ? sign_common::SignatureHashAlgorithm::SHA256
                                          : (current_algorithm_ == Algorithm::RSA_PSS_SHA384
                                                 ? sign_common::SignatureHashAlgorithm::SHA384
                                                 : sign_common::SignatureHashAlgorithm::SHA512);
                auto sig = sign_rsa::pss::sign(msg, rsa_key, hash_alg);
                if (sig.is_err()) {
                    return {false, {}, detail::dp_error_message(sig.error())};
                }
                return {true, std::vector<uint8_t>(sig.value().begin(), sig.value().end()), ""};
            }
            case Algorithm::ECDSA_P256_SHA256: {
                if (private_key.size() != 32) {
                    return {false, {}, "Invalid ECDSA P-256 private key size"};
                }
                sign_ecdsa_p256::PrivateKey sk{dp::Vector<dp::u8>(private_key.begin(), private_key.end())};
                const dp::Vector<dp::u8> msg(data.begin(), data.end());
                auto sig = sign_ecdsa_p256::sign_detached(msg, sk);
                if (sig.is_err()) {
                    return {false, {}, detail::dp_error_message(sig.error())};
                }
                return {true, std::vector<uint8_t>(sig.value().begin(), sig.value().end()), ""};
            }
            default:
                return {false, {}, "Unsupported signature algorithm"};
            }
        }

        CryptoResult verify(const std::vector<uint8_t> &data, const std::vector<uint8_t> &signature,
                            const std::vector<uint8_t> &public_key) {
            if (!is_signature_algorithm(current_algorithm_)) {
                return {false, {}, "Current algorithm does not support verification"};
            }

            switch (current_algorithm_) {
            case Algorithm::Ed25519: {
                if (public_key.size() != ed25519::PUBLICKEYBYTES) {
                    return {false, {}, "Invalid public key size"};
                }

                int rc = ed25519::verify_detached(signature.data(), data.data(), data.size(), public_key.data());
                return {rc == 0, {}, rc == 0 ? "" : "Ed25519 signature verification failed"};
            }
            case Algorithm::RSA_PKCS1v15_SHA256:
            case Algorithm::RSA_PSS_SHA256:
            case Algorithm::RSA_PKCS1v15_SHA384:
            case Algorithm::RSA_PSS_SHA384:
            case Algorithm::RSA_PKCS1v15_SHA512:
            case Algorithm::RSA_PSS_SHA512:
            case Algorithm::RSA_OAEP_SHA256:
            case Algorithm::RSA_OAEP_SHA384:
            case Algorithm::RSA_OAEP_SHA512: {
                sign_rsa::RsaPublicKey rsa_key;
                std::string decode_error;
                if (!detail::decode_rsa_public_key_blob_raw(public_key, rsa_key, decode_error)) {
                    return {false, {}, decode_error};
                }

                const dp::Vector<dp::u8> msg(data.begin(), data.end());
                const dp::Vector<dp::u8> sig(signature.begin(), signature.end());

                if (current_algorithm_ == Algorithm::RSA_PKCS1v15_SHA256 ||
                    current_algorithm_ == Algorithm::RSA_PKCS1v15_SHA384 ||
                    current_algorithm_ == Algorithm::RSA_PKCS1v15_SHA512) {
                    const auto hash_alg = current_algorithm_ == Algorithm::RSA_PKCS1v15_SHA256
                                              ? sign_common::SignatureHashAlgorithm::SHA256
                                              : (current_algorithm_ == Algorithm::RSA_PKCS1v15_SHA384
                                                     ? sign_common::SignatureHashAlgorithm::SHA384
                                                     : sign_common::SignatureHashAlgorithm::SHA512);
                    auto ok = sign_rsa::pkcs1v15::verify(msg, sig, rsa_key, hash_alg);
                    if (ok.is_err()) {
                        return {false, {}, detail::dp_error_message(ok.error())};
                    }
                    return {ok.value(), {}, ok.value() ? "" : "RSA PKCS1v15 signature verification failed"};
                }

                const auto hash_alg = current_algorithm_ == Algorithm::RSA_PSS_SHA256
                                          ? sign_common::SignatureHashAlgorithm::SHA256
                                          : (current_algorithm_ == Algorithm::RSA_PSS_SHA384
                                                 ? sign_common::SignatureHashAlgorithm::SHA384
                                                 : sign_common::SignatureHashAlgorithm::SHA512);
                auto ok = sign_rsa::pss::verify(msg, sig, rsa_key, hash_alg);
                if (ok.is_err()) {
                    return {false, {}, detail::dp_error_message(ok.error())};
                }
                return {ok.value(), {}, ok.value() ? "" : "RSA PSS signature verification failed"};
            }
            case Algorithm::ECDSA_P256_SHA256: {
                if (public_key.size() != 64) {
                    return {false, {}, "Invalid ECDSA P-256 public key size"};
                }

                sign_ecdsa_p256::PublicKey pk;
                pk.q.infinity = false;
                pk.q.x.assign(public_key.begin(), public_key.begin() + 32);
                pk.q.y.assign(public_key.begin() + 32, public_key.end());

                const dp::Vector<dp::u8> msg(data.begin(), data.end());
                const dp::Vector<dp::u8> sig(signature.begin(), signature.end());
                auto ok = sign_ecdsa_p256::verify_detached(msg, sig, pk);
                if (ok.is_err()) {
                    return {false, {}, detail::dp_error_message(ok.error())};
                }
                return {ok.value(), {}, ok.value() ? "" : "ECDSA P-256 signature verification failed"};
            }
            default:
                return {false, {}, "Unsupported signature algorithm"};
            }
        }

        KeyPair generate_keypair() {
            switch (current_algorithm_) {
            case Algorithm::X25519_Box: {
                std::vector<uint8_t> pub(box_seal::PUBLICKEYBYTES);
                std::vector<uint8_t> sec(box_seal::SECRETKEYBYTES);
                box_seal::keypair(pub.data(), sec.data());
                KeyPair pair;
                pair.algorithm = current_algorithm_;
                pair.public_key = pub;
                pair.private_key = pub;
                pair.private_key.insert(pair.private_key.end(), sec.begin(), sec.end());
                return pair;
            }
            case Algorithm::Ed25519: {
                std::vector<uint8_t> pub(ed25519::PUBLICKEYBYTES);
                std::vector<uint8_t> sec(ed25519::SECRETKEYBYTES);
                ed25519::keypair(pub.data(), sec.data());
                KeyPair pair;
                pair.algorithm = current_algorithm_;
                pair.public_key = std::move(pub);
                pair.private_key = std::move(sec);
                return pair;
            }
            case Algorithm::ECDSA_P256_SHA256: {
                std::vector<uint8_t> d(32);
                const std::vector<uint8_t> n(sign_ecdsa_p256::field::order_n().begin(),
                                             sign_ecdsa_p256::field::order_n().end());

                do {
                    rng::randombytes_buf(d.data(), d.size());
                } while (detail::is_zero_bytes(d) || detail::compare_be_bytes(d, n) >= 0);

                sign_ecdsa_p256::PrivateKey sk{dp::Vector<dp::u8>(d.begin(), d.end())};
                auto pk = sign_ecdsa_p256::derive_public_key(sk);
                if (pk.is_err()) {
                    throw std::runtime_error("ECDSA P-256 key generation failed");
                }

                KeyPair pair;
                pair.algorithm = current_algorithm_;
                pair.private_key = encode_ecdsa_p256_private_key_blob(d);
                pair.public_key = encode_ecdsa_p256_public_key_blob(
                    std::vector<uint8_t>(pk.value().q.x.begin(), pk.value().q.x.end()),
                    std::vector<uint8_t>(pk.value().q.y.begin(), pk.value().q.y.end()));
                return pair;
            }
            case Algorithm::RSA_PKCS1v15_SHA256:
            case Algorithm::RSA_PSS_SHA256:
            case Algorithm::RSA_PKCS1v15_SHA384:
            case Algorithm::RSA_PSS_SHA384:
            case Algorithm::RSA_PKCS1v15_SHA512:
            case Algorithm::RSA_PSS_SHA512:
            case Algorithm::RSA_OAEP_SHA256:
            case Algorithm::RSA_OAEP_SHA384:
            case Algorithm::RSA_OAEP_SHA512: {
                for (int attempt = 0; attempt < 8; ++attempt) {
                    auto generated = sign_rsa::keygen::generate_keypair(1536, 65537);
                    if (generated.is_err()) {
                        continue;
                    }

                    const auto &rsa_key = generated.value();
                    if (rsa_key.public_exponent != dp::Vector<dp::u8>{0x01, 0x00, 0x01}) {
                        continue;
                    }
                    if (rsa_key.private_exponent == rsa_key.public_exponent) {
                        continue;
                    }

                    const dp::Vector<dp::u8> self_test_msg{'k', 'e', 'y', 'g', 'e', 'n'};
                    auto sig =
                        sign_rsa::pkcs1v15::sign(self_test_msg, rsa_key, sign_common::SignatureHashAlgorithm::SHA256);
                    if (sig.is_err()) {
                        continue;
                    }
                    sign_rsa::RsaPublicKey pub_key{rsa_key.modulus, rsa_key.public_exponent};
                    auto ok = sign_rsa::pkcs1v15::verify(self_test_msg, sig.value(), pub_key,
                                                         sign_common::SignatureHashAlgorithm::SHA256);
                    if (ok.is_err() || !ok.value()) {
                        continue;
                    }

                    const std::vector<uint8_t> n_vec(rsa_key.modulus.begin(), rsa_key.modulus.end());
                    const std::vector<uint8_t> e_vec(rsa_key.public_exponent.begin(), rsa_key.public_exponent.end());
                    const std::vector<uint8_t> d_vec(rsa_key.private_exponent.begin(), rsa_key.private_exponent.end());

                    KeyPair pair;
                    pair.algorithm = current_algorithm_;
                    pair.public_key = encode_rsa_public_key_blob(n_vec, e_vec);
                    pair.private_key = encode_rsa_private_key_blob(n_vec, e_vec, d_vec);
                    return pair;
                }
                throw std::runtime_error("RSA key generation failed");
            }
            default:
                throw std::runtime_error("Key generation not supported for this algorithm");
            }
        }

        CryptoResult generate_symmetric_key(size_t key_size = 32) {
            try {
                std::vector<uint8_t> key(key_size);
                rng::randombytes_buf(key.data(), key.size());
                return {true, key, ""};
            } catch (const std::exception &e) {
                return {false, {}, e.what()};
            }
        }

        CryptoResult hash(const std::vector<uint8_t> &data) {
            auto result = ::keylock::hash::digest(current_hash_, data);
            return {result.success, std::move(result.data), std::move(result.error_message)};
        }

        CryptoResult hmac(const std::vector<uint8_t> &data, const std::vector<uint8_t> &key) {
            auto result = ::keylock::hash::hmac(current_hash_, data, key);
            return {result.success, std::move(result.data), std::move(result.error_message)};
        }

        bool save_key_to_file(const std::vector<uint8_t> &key, const std::string &filename, KeyType key_type,
                              KeyFormat format = KeyFormat::RAW);

        CryptoResult load_key_from_file(const std::string &filename, KeyType key_type);

        bool save_keypair_to_files(const KeyPair &keypair, const std::string &public_filename,
                                   const std::string &private_filename, KeyFormat format = KeyFormat::RAW) {
            return save_key_to_file(keypair.public_key, public_filename, KeyType::PUBLIC, format) &&
                   save_key_to_file(keypair.private_key, private_filename, KeyType::PRIVATE, format);
        }

        CryptoResult load_keypair_from_files(const std::string &public_filename, const std::string &private_filename) {
            auto pub = load_key_from_file(public_filename, KeyType::PUBLIC);
            if (!pub.success)
                return pub;

            auto priv = load_key_from_file(private_filename, KeyType::PRIVATE);
            if (!priv.success)
                return priv;

            return {true, priv.data, ""};
        }

        static std::string to_hex(const std::vector<uint8_t> &data) { return Common::bytes_to_hex(data); }
        static std::vector<uint8_t> from_hex(const std::string &hex) { return Common::hex_to_bytes(hex); }

        static std::string algorithm_to_string(Algorithm algorithm) {
            switch (algorithm) {
            case Algorithm::XChaCha20_Poly1305:
                return "XChaCha20-Poly1305";
            case Algorithm::ChaCha20_Poly1305:
                return "ChaCha20-Poly1305-IETF";
            case Algorithm::AES256_GCM:
                return "AES-256-GCM";
            case Algorithm::SecretBox_XSalsa20:
                return "SecretBox-XSalsa20-Poly1305";
            case Algorithm::X25519_Box:
                return "X25519-Box";
            case Algorithm::Ed25519:
                return "Ed25519";
            case Algorithm::RSA_PKCS1v15_SHA256:
                return "RSA-PKCS1v1.5-SHA256";
            case Algorithm::RSA_PSS_SHA256:
                return "RSA-PSS-SHA256";
            case Algorithm::RSA_PKCS1v15_SHA384:
                return "RSA-PKCS1v1.5-SHA384";
            case Algorithm::RSA_PSS_SHA384:
                return "RSA-PSS-SHA384";
            case Algorithm::RSA_PKCS1v15_SHA512:
                return "RSA-PKCS1v1.5-SHA512";
            case Algorithm::RSA_PSS_SHA512:
                return "RSA-PSS-SHA512";
            case Algorithm::RSA_OAEP_SHA256:
                return "RSA-OAEP-SHA256";
            case Algorithm::RSA_OAEP_SHA384:
                return "RSA-OAEP-SHA384";
            case Algorithm::RSA_OAEP_SHA512:
                return "RSA-OAEP-SHA512";
            case Algorithm::ECDSA_P256_SHA256:
                return "ECDSA-P256-SHA256";
            }
            return "Unknown";
        }

        static std::vector<uint8_t> encode_rsa_public_key_blob(const std::vector<uint8_t> &modulus,
                                                               const std::vector<uint8_t> &public_exponent) {
            return detail::encode_rsa_public_key_blob_raw(modulus, public_exponent);
        }

        static std::vector<uint8_t> encode_rsa_private_key_blob(const std::vector<uint8_t> &modulus,
                                                                const std::vector<uint8_t> &public_exponent,
                                                                const std::vector<uint8_t> &private_exponent) {
            return detail::encode_rsa_private_key_blob_raw(modulus, public_exponent, private_exponent);
        }

        static CryptoResult encode_rsa_public_key_pkcs1_der(const std::vector<uint8_t> &modulus,
                                                            const std::vector<uint8_t> &public_exponent) {
            sign_rsa::RsaPublicKey key{dp::Vector<dp::u8>(modulus.begin(), modulus.end()),
                                       dp::Vector<dp::u8>(public_exponent.begin(), public_exponent.end())};
            auto der = sign_rsa::pkcs1::encode_public_key_der(key);
            if (der.is_err()) {
                return {false, {}, detail::dp_error_message(der.error())};
            }
            return {true, std::vector<uint8_t>(der.value().begin(), der.value().end()), ""};
        }

        static CryptoResult encode_rsa_private_key_pkcs1_der(
            const std::vector<uint8_t> &modulus, const std::vector<uint8_t> &public_exponent,
            const std::vector<uint8_t> &private_exponent, const std::vector<uint8_t> &p = {},
            const std::vector<uint8_t> &q = {}, const std::vector<uint8_t> &dp = {},
            const std::vector<uint8_t> &dq = {}, const std::vector<uint8_t> &qinv = {}) {
            sign_rsa::RsaPrivateKey key;
            key.modulus = dp::Vector<dp::u8>(modulus.begin(), modulus.end());
            key.public_exponent = dp::Vector<dp::u8>(public_exponent.begin(), public_exponent.end());
            key.private_exponent = dp::Vector<dp::u8>(private_exponent.begin(), private_exponent.end());
            key.prime_p = dp::Vector<dp::u8>(p.begin(), p.end());
            key.prime_q = dp::Vector<dp::u8>(q.begin(), q.end());
            key.crt_dp = dp::Vector<dp::u8>(dp.begin(), dp.end());
            key.crt_dq = dp::Vector<dp::u8>(dq.begin(), dq.end());
            key.crt_qinv = dp::Vector<dp::u8>(qinv.begin(), qinv.end());

            auto der = sign_rsa::pkcs1::encode_private_key_der(key);
            if (der.is_err()) {
                return {false, {}, detail::dp_error_message(der.error())};
            }
            return {true, std::vector<uint8_t>(der.value().begin(), der.value().end()), ""};
        }

        static CryptoResult decode_rsa_public_key_pkcs1_der(const std::vector<uint8_t> &der_bytes) {
            auto key = sign_rsa::pkcs1::decode_public_key_der(dp::Vector<dp::u8>(der_bytes.begin(), der_bytes.end()));
            if (key.is_err()) {
                return {false, {}, detail::dp_error_message(key.error())};
            }
            auto blob = encode_rsa_public_key_blob(
                std::vector<uint8_t>(key.value().modulus.begin(), key.value().modulus.end()),
                std::vector<uint8_t>(key.value().public_exponent.begin(), key.value().public_exponent.end()));
            return {true, std::move(blob), ""};
        }

        static CryptoResult decode_rsa_private_key_pkcs1_der(const std::vector<uint8_t> &der_bytes) {
            auto key = sign_rsa::pkcs1::decode_private_key_der(dp::Vector<dp::u8>(der_bytes.begin(), der_bytes.end()));
            if (key.is_err()) {
                return {false, {}, detail::dp_error_message(key.error())};
            }
            auto blob = encode_rsa_private_key_blob(
                std::vector<uint8_t>(key.value().modulus.begin(), key.value().modulus.end()),
                std::vector<uint8_t>(key.value().public_exponent.begin(), key.value().public_exponent.end()),
                std::vector<uint8_t>(key.value().private_exponent.begin(), key.value().private_exponent.end()));
            return {true, std::move(blob), ""};
        }

        static std::vector<uint8_t> encode_ecdsa_p256_public_key_blob(const std::vector<uint8_t> &x,
                                                                      const std::vector<uint8_t> &y) {
            std::vector<uint8_t> out;
            out.reserve(64);
            if (x.size() < 32) {
                out.insert(out.end(), 32 - x.size(), 0x00);
            }
            out.insert(out.end(), x.size() > 32 ? x.end() - 32 : x.begin(), x.end());
            if (y.size() < 32) {
                out.insert(out.end(), 32 - y.size(), 0x00);
            }
            out.insert(out.end(), y.size() > 32 ? y.end() - 32 : y.begin(), y.end());
            return out;
        }

        static std::vector<uint8_t> encode_ecdsa_p256_private_key_blob(const std::vector<uint8_t> &d) {
            std::vector<uint8_t> out;
            out.reserve(32);
            if (d.size() < 32) {
                out.insert(out.end(), 32 - d.size(), 0x00);
            }
            out.insert(out.end(), d.size() > 32 ? d.end() - 32 : d.begin(), d.end());
            return out;
        }

        static CryptoResult encode_ecdsa_p256_signature_der(const std::vector<uint8_t> &raw_signature_64) {
            auto der = sign_ecdsa_p256::der::encode_raw_to_der(
                dp::Vector<dp::u8>(raw_signature_64.begin(), raw_signature_64.end()));
            if (der.is_err()) {
                return {false, {}, detail::dp_error_message(der.error())};
            }
            return {true, std::vector<uint8_t>(der.value().begin(), der.value().end()), ""};
        }

        static CryptoResult decode_ecdsa_p256_signature_der(const std::vector<uint8_t> &der_signature) {
            auto raw =
                sign_ecdsa_p256::der::decode_der_to_raw(dp::Vector<dp::u8>(der_signature.begin(), der_signature.end()));
            if (raw.is_err()) {
                return {false, {}, detail::dp_error_message(raw.error())};
            }
            return {true, std::vector<uint8_t>(raw.value().begin(), raw.value().end()), ""};
        }

        static bool is_aes_gcm_available() { return aead_aes256gcm::is_available() != 0; }

        static std::string hash_algorithm_to_string(HashAlgorithm hash_algo) {
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

      private:
        Algorithm current_algorithm_;
        HashAlgorithm current_hash_;

        std::optional<size_t> expected_key_size(KeyType key_type) const {
            switch (current_algorithm_) {
            case Algorithm::X25519_Box:
                if (key_type == KeyType::PUBLIC)
                    return box_seal::PUBLICKEYBYTES;
                return box_seal::PUBLICKEYBYTES + box_seal::SECRETKEYBYTES;
            case Algorithm::Ed25519:
                if (key_type == KeyType::PUBLIC)
                    return ed25519::PUBLICKEYBYTES;
                return ed25519::SECRETKEYBYTES;
            case Algorithm::RSA_PKCS1v15_SHA256:
            case Algorithm::RSA_PSS_SHA256:
            case Algorithm::RSA_PKCS1v15_SHA384:
            case Algorithm::RSA_PSS_SHA384:
            case Algorithm::RSA_PKCS1v15_SHA512:
            case Algorithm::RSA_PSS_SHA512:
            case Algorithm::RSA_OAEP_SHA256:
            case Algorithm::RSA_OAEP_SHA384:
            case Algorithm::RSA_OAEP_SHA512:
                break;
            case Algorithm::ECDSA_P256_SHA256:
                if (key_type == KeyType::PUBLIC)
                    return 64;
                return 32;
            case Algorithm::XChaCha20_Poly1305:
            case Algorithm::ChaCha20_Poly1305:
            case Algorithm::AES256_GCM:
            case Algorithm::SecretBox_XSalsa20:
                break;
            }
            return std::nullopt;
        }

        bool is_symmetric_algorithm(Algorithm algo) const {
            return algo == Algorithm::XChaCha20_Poly1305 || algo == Algorithm::ChaCha20_Poly1305 ||
                   algo == Algorithm::AES256_GCM || algo == Algorithm::SecretBox_XSalsa20;
        }

        bool is_asymmetric_algorithm(Algorithm algo) const {
            return algo == Algorithm::X25519_Box || algo == Algorithm::RSA_OAEP_SHA256 ||
                   algo == Algorithm::RSA_OAEP_SHA384 || algo == Algorithm::RSA_OAEP_SHA512;
        }
        bool is_signature_algorithm(Algorithm algo) const {
            return algo == Algorithm::Ed25519 || algo == Algorithm::RSA_PKCS1v15_SHA256 ||
                   algo == Algorithm::RSA_PSS_SHA256 || algo == Algorithm::RSA_PKCS1v15_SHA384 ||
                   algo == Algorithm::RSA_PSS_SHA384 || algo == Algorithm::RSA_PKCS1v15_SHA512 ||
                   algo == Algorithm::RSA_PSS_SHA512 || algo == Algorithm::ECDSA_P256_SHA256;
        }

        CryptoResult aead_xchacha_encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key,
                                          const std::vector<uint8_t> &aad) {
            try {
                auto normalized_key = detail::normalize_key(key, aead_xchacha20poly1305::KEYBYTES);
                std::vector<uint8_t> nonce(aead_xchacha20poly1305::NPUBBYTES);
                rng::randombytes_buf(nonce.data(), nonce.size());

                std::vector<uint8_t> ciphertext(plaintext.size() + aead_xchacha20poly1305::ABYTES);
                unsigned long long ciphertext_len = 0;

                if (aead_xchacha20poly1305::encrypt(ciphertext.data(), &ciphertext_len, plaintext.data(),
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

        CryptoResult aead_xchacha_decrypt(const std::vector<uint8_t> &ciphertext_with_nonce,
                                          const std::vector<uint8_t> &key, const std::vector<uint8_t> &aad) {
            try {
                if (ciphertext_with_nonce.size() < aead_xchacha20poly1305::NPUBBYTES + aead_xchacha20poly1305::ABYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                auto normalized_key = detail::normalize_key(key, aead_xchacha20poly1305::KEYBYTES);
                std::vector<uint8_t> nonce(ciphertext_with_nonce.begin(),
                                           ciphertext_with_nonce.begin() + aead_xchacha20poly1305::NPUBBYTES);
                std::vector<uint8_t> ciphertext(ciphertext_with_nonce.begin() + aead_xchacha20poly1305::NPUBBYTES,
                                                ciphertext_with_nonce.end());

                if (ciphertext.size() < aead_xchacha20poly1305::ABYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                std::vector<uint8_t> plaintext(ciphertext.size() - aead_xchacha20poly1305::ABYTES);
                unsigned long long plaintext_len = 0;

                if (aead_xchacha20poly1305::decrypt(plaintext.data(), &plaintext_len, nullptr, ciphertext.data(),
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

        CryptoResult aead_chacha_ietf_encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key,
                                              const std::vector<uint8_t> &aad) {
            try {
                auto normalized_key = detail::normalize_key(key, aead_chacha20poly1305_ietf::KEYBYTES);
                std::vector<uint8_t> nonce(aead_chacha20poly1305_ietf::NPUBBYTES);
                rng::randombytes_buf(nonce.data(), nonce.size());

                std::vector<uint8_t> ciphertext(plaintext.size() + aead_chacha20poly1305_ietf::ABYTES);
                unsigned long long ciphertext_len = 0;

                if (aead_chacha20poly1305_ietf::encrypt(ciphertext.data(), &ciphertext_len, plaintext.data(),
                                                        plaintext.size(), aad.data(), aad.size(), nullptr, nonce.data(),
                                                        normalized_key.data()) != 0) {
                    return {false, {}, "ChaCha20-Poly1305 IETF encryption failed"};
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

        CryptoResult aead_chacha_ietf_decrypt(const std::vector<uint8_t> &ciphertext_with_nonce,
                                              const std::vector<uint8_t> &key, const std::vector<uint8_t> &aad) {
            try {
                if (ciphertext_with_nonce.size() <
                    aead_chacha20poly1305_ietf::NPUBBYTES + aead_chacha20poly1305_ietf::ABYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                auto normalized_key = detail::normalize_key(key, aead_chacha20poly1305_ietf::KEYBYTES);
                std::vector<uint8_t> nonce(ciphertext_with_nonce.begin(),
                                           ciphertext_with_nonce.begin() + aead_chacha20poly1305_ietf::NPUBBYTES);
                std::vector<uint8_t> ciphertext(ciphertext_with_nonce.begin() + aead_chacha20poly1305_ietf::NPUBBYTES,
                                                ciphertext_with_nonce.end());

                if (ciphertext.size() < aead_chacha20poly1305_ietf::ABYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                std::vector<uint8_t> plaintext(ciphertext.size() - aead_chacha20poly1305_ietf::ABYTES);
                unsigned long long plaintext_len = 0;

                if (aead_chacha20poly1305_ietf::decrypt(plaintext.data(), &plaintext_len, nullptr, ciphertext.data(),
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

        CryptoResult aead_aes256gcm_encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key,
                                            const std::vector<uint8_t> &aad) {
            try {
                if (aead_aes256gcm::is_available() == 0) {
                    return {false, {}, "AES-GCM not available (requires AES-NI hardware support)"};
                }

                auto normalized_key = detail::normalize_key(key, aead_aes256gcm::KEYBYTES);
                std::vector<uint8_t> nonce(aead_aes256gcm::NPUBBYTES);
                rng::randombytes_buf(nonce.data(), nonce.size());

                std::vector<uint8_t> ciphertext(plaintext.size() + aead_aes256gcm::ABYTES);
                unsigned long long ciphertext_len = 0;

                if (aead_aes256gcm::encrypt(ciphertext.data(), &ciphertext_len, plaintext.data(), plaintext.size(),
                                            aad.data(), aad.size(), nullptr, nonce.data(),
                                            normalized_key.data()) != 0) {
                    return {false, {}, "AES-256-GCM encryption failed"};
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

        CryptoResult aead_aes256gcm_decrypt(const std::vector<uint8_t> &ciphertext_with_nonce,
                                            const std::vector<uint8_t> &key, const std::vector<uint8_t> &aad) {
            try {
                if (aead_aes256gcm::is_available() == 0) {
                    return {false, {}, "AES-GCM not available (requires AES-NI hardware support)"};
                }

                if (ciphertext_with_nonce.size() < aead_aes256gcm::NPUBBYTES + aead_aes256gcm::ABYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                auto normalized_key = detail::normalize_key(key, aead_aes256gcm::KEYBYTES);
                std::vector<uint8_t> nonce(ciphertext_with_nonce.begin(),
                                           ciphertext_with_nonce.begin() + aead_aes256gcm::NPUBBYTES);
                std::vector<uint8_t> ciphertext(ciphertext_with_nonce.begin() + aead_aes256gcm::NPUBBYTES,
                                                ciphertext_with_nonce.end());

                if (ciphertext.size() < aead_aes256gcm::ABYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                std::vector<uint8_t> plaintext(ciphertext.size() - aead_aes256gcm::ABYTES);
                unsigned long long plaintext_len = 0;

                if (aead_aes256gcm::decrypt(plaintext.data(), &plaintext_len, nullptr, ciphertext.data(),
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
                auto normalized_key = detail::normalize_key(key, secretbox::KEYBYTES);
                std::vector<uint8_t> nonce(secretbox::NONCEBYTES);
                rng::randombytes_buf(nonce.data(), nonce.size());

                std::vector<uint8_t> ciphertext(secretbox::NONCEBYTES + secretbox::MACBYTES + plaintext.size());
                std::copy(nonce.begin(), nonce.end(), ciphertext.begin());

                if (secretbox::easy(ciphertext.data() + secretbox::NONCEBYTES, plaintext.data(), plaintext.size(),
                                    nonce.data(), normalized_key.data()) != 0) {
                    return {false, {}, "SecretBox encryption failed"};
                }

                return {true, ciphertext, ""};
            } catch (const std::exception &e) {
                return {false, {}, e.what()};
            }
        }

        CryptoResult secretbox_decrypt(const std::vector<uint8_t> &ciphertext_with_nonce,
                                       const std::vector<uint8_t> &key) {
            try {
                if (ciphertext_with_nonce.size() < secretbox::NONCEBYTES + secretbox::MACBYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                auto normalized_key = detail::normalize_key(key, secretbox::KEYBYTES);
                std::vector<uint8_t> nonce(ciphertext_with_nonce.begin(),
                                           ciphertext_with_nonce.begin() + secretbox::NONCEBYTES);
                std::vector<uint8_t> ciphertext(ciphertext_with_nonce.begin() + secretbox::NONCEBYTES,
                                                ciphertext_with_nonce.end());

                std::vector<uint8_t> plaintext(ciphertext.size() - secretbox::MACBYTES);
                if (secretbox::open_easy(plaintext.data(), ciphertext.data(), ciphertext.size(), nonce.data(),
                                         normalized_key.data()) != 0) {
                    return {false, {}, "SecretBox decryption failed"};
                }

                return {true, plaintext, ""};
            } catch (const std::exception &e) {
                return {false, {}, e.what()};
            }
        }
    };

} // namespace keylock::crypto

namespace keylock::crypto {

    inline bool Context::save_key_to_file(const std::vector<uint8_t> &key, const std::string &filename,
                                          KeyType key_type, KeyFormat format) {
        (void)key_type;
        (void)format;

        return detail::write_binary(key, filename);
    }

    inline Context::CryptoResult Context::load_key_from_file(const std::string &filename, KeyType key_type) {
        auto load = detail::read_binary(filename);
        if (!load.success) {
            return {false, {}, load.error_message};
        }

        if (auto expected = expected_key_size(key_type)) {
            if (load.data.size() != *expected) {
                return {false, {}, "Unexpected key size"};
            }
        }
        return {true, load.data, ""};
    }

} // namespace keylock::crypto
