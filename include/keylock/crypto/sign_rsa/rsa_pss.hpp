#pragma once

#include <utility>

#include "keylock/crypto/rng/randombytes.hpp"
#include "keylock/crypto/sign_common/hash_route.hpp"
#include "keylock/crypto/sign_rsa/rsa_keys.hpp"
#include "keylock/crypto/sign_rsa/rsa_math.hpp"

namespace keylock::crypto::sign_rsa::pss {

    using Bytes = dp::Vector<dp::u8>;
    using SignResult = dp::Result<Bytes>;

    namespace detail {

        inline dp::usize bit_length(const Bytes &x) {
            if (x.empty()) {
                return 0;
            }
            dp::usize first = 0;
            while (first < x.size() && x[first] == 0) {
                ++first;
            }
            if (first == x.size()) {
                return 0;
            }

            dp::u8 top = x[first];
            dp::usize bits = 0;
            while (top > 0) {
                top >>= 1;
                ++bits;
            }
            return (x.size() - first - 1) * 8 + bits;
        }

        inline dp::Result<Bytes> mgf1(const Bytes &seed, dp::usize out_len,
                                      sign_common::SignatureHashAlgorithm hash_alg) {
            Bytes out;
            out.reserve(out_len);

            dp::u32 counter = 0;
            while (out.size() < out_len) {
                Bytes block_input = seed;
                block_input.push_back(static_cast<dp::u8>((counter >> 24) & 0xff));
                block_input.push_back(static_cast<dp::u8>((counter >> 16) & 0xff));
                block_input.push_back(static_cast<dp::u8>((counter >> 8) & 0xff));
                block_input.push_back(static_cast<dp::u8>(counter & 0xff));

                auto h = sign_common::hash_message(hash_alg, block_input);
                if (h.is_err()) {
                    return dp::Result<Bytes>::err(h.error());
                }

                for (dp::u8 b : h.value()) {
                    if (out.size() == out_len) {
                        break;
                    }
                    out.push_back(b);
                }
                ++counter;
            }
            return dp::Result<Bytes>::ok(std::move(out));
        }

    } // namespace detail

    inline dp::Result<Bytes> emsa_pss_encode(const Bytes &message, sign_common::SignatureHashAlgorithm hash_alg,
                                             dp::usize em_bits, const Bytes &salt_input = {}) {
        const dp::usize em_len = (em_bits + 7) / 8;
        const dp::usize h_len = sign_common::digest_size(hash_alg);
        if (h_len == 0) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("invalid hash algorithm"));
        }

        Bytes salt = salt_input;
        if (salt.empty()) {
            salt.resize(h_len);
            rng::randombytes_buf(salt.data(), salt.size());
        }

        if (em_len < h_len + salt.size() + 2) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("encoding error: intended length too short"));
        }

        auto m_hash_res = sign_common::hash_message(hash_alg, message);
        if (m_hash_res.is_err()) {
            return dp::Result<Bytes>::err(m_hash_res.error());
        }
        const Bytes &m_hash = m_hash_res.value();

        Bytes m_prime;
        m_prime.resize(8, 0x00);
        for (dp::u8 b : m_hash) {
            m_prime.push_back(b);
        }
        for (dp::u8 b : salt) {
            m_prime.push_back(b);
        }

        auto h_res = sign_common::hash_message(hash_alg, m_prime);
        if (h_res.is_err()) {
            return dp::Result<Bytes>::err(h_res.error());
        }
        const Bytes &h = h_res.value();

        Bytes db;
        db.resize(em_len - h_len - 1, 0x00);
        db[db.size() - salt.size() - 1] = 0x01;
        for (dp::usize i = 0; i < salt.size(); ++i) {
            db[db.size() - salt.size() + i] = salt[i];
        }

        auto mask_res = detail::mgf1(h, db.size(), hash_alg);
        if (mask_res.is_err()) {
            return dp::Result<Bytes>::err(mask_res.error());
        }

        Bytes masked_db = db;
        for (dp::usize i = 0; i < masked_db.size(); ++i) {
            masked_db[i] ^= mask_res.value()[i];
        }

        const dp::usize leftmost_unused_bits = 8 * em_len - em_bits;
        if (leftmost_unused_bits > 0) {
            const dp::u8 mask = static_cast<dp::u8>(0xffU >> leftmost_unused_bits);
            masked_db[0] &= mask;
        }

        Bytes em = masked_db;
        for (dp::u8 b : h) {
            em.push_back(b);
        }
        em.push_back(0xbc);

        return dp::Result<Bytes>::ok(std::move(em));
    }

    inline dp::Result<bool> emsa_pss_verify(const Bytes &message, const Bytes &em,
                                            sign_common::SignatureHashAlgorithm hash_alg, dp::usize em_bits) {
        const dp::usize em_len = (em_bits + 7) / 8;
        const dp::usize h_len = sign_common::digest_size(hash_alg);
        if (h_len == 0) {
            return dp::Result<bool>::err(dp::Error::invalid_argument("invalid hash algorithm"));
        }

        if (em.size() != em_len || em_len < h_len + 2) {
            return dp::Result<bool>::ok(false);
        }
        if (em.back() != 0xbc) {
            return dp::Result<bool>::ok(false);
        }

        Bytes masked_db;
        masked_db.resize(em_len - h_len - 1);
        for (dp::usize i = 0; i < masked_db.size(); ++i) {
            masked_db[i] = em[i];
        }

        Bytes h;
        h.resize(h_len);
        for (dp::usize i = 0; i < h_len; ++i) {
            h[i] = em[masked_db.size() + i];
        }

        const dp::usize leftmost_unused_bits = 8 * em_len - em_bits;
        if (leftmost_unused_bits > 0) {
            const dp::u8 leading_bits = static_cast<dp::u8>(0xffU << (8 - leftmost_unused_bits));
            if ((masked_db[0] & leading_bits) != 0) {
                return dp::Result<bool>::ok(false);
            }
        }

        auto db_mask_res = detail::mgf1(h, masked_db.size(), hash_alg);
        if (db_mask_res.is_err()) {
            return dp::Result<bool>::err(db_mask_res.error());
        }

        Bytes db = masked_db;
        for (dp::usize i = 0; i < db.size(); ++i) {
            db[i] ^= db_mask_res.value()[i];
        }

        if (leftmost_unused_bits > 0) {
            const dp::u8 mask = static_cast<dp::u8>(0xffU >> leftmost_unused_bits);
            db[0] &= mask;
        }

        dp::usize idx = 0;
        while (idx < db.size() && db[idx] == 0x00) {
            ++idx;
        }
        if (idx >= db.size() || db[idx] != 0x01) {
            return dp::Result<bool>::ok(false);
        }
        ++idx;

        Bytes salt;
        salt.reserve(db.size() - idx);
        while (idx < db.size()) {
            salt.push_back(db[idx++]);
        }

        auto m_hash_res = sign_common::hash_message(hash_alg, message);
        if (m_hash_res.is_err()) {
            return dp::Result<bool>::err(m_hash_res.error());
        }

        Bytes m_prime;
        m_prime.resize(8, 0x00);
        for (dp::u8 b : m_hash_res.value()) {
            m_prime.push_back(b);
        }
        for (dp::u8 b : salt) {
            m_prime.push_back(b);
        }

        auto hp_res = sign_common::hash_message(hash_alg, m_prime);
        if (hp_res.is_err()) {
            return dp::Result<bool>::err(hp_res.error());
        }

        return dp::Result<bool>::ok(hp_res.value() == h);
    }

    inline SignResult sign(const Bytes &message, const RsaPrivateKey &key, sign_common::SignatureHashAlgorithm hash_alg,
                           const Bytes &salt = {}) {
        auto key_ok = validate_private_key(key);
        if (key_ok.is_err()) {
            return SignResult::err(key_ok.error());
        }

        const dp::usize mod_bits = detail::bit_length(key.modulus);
        if (mod_bits < 2) {
            return SignResult::err(dp::Error::invalid_argument("invalid rsa modulus"));
        }

        const dp::usize em_bits = mod_bits - 1;
        const dp::usize em_len = (em_bits + 7) / 8;
        auto em_res = emsa_pss_encode(message, hash_alg, em_bits, salt);
        if (em_res.is_err()) {
            return SignResult::err(em_res.error());
        }

        auto sig_res = math::mod_exp_be(em_res.value(), key.private_exponent, key.modulus);
        if (sig_res.is_err()) {
            return SignResult::err(sig_res.error());
        }

        Bytes signature = std::move(sig_res.value());
        const dp::usize k = key.modulus.size();
        if (signature.size() < k) {
            Bytes padded;
            padded.resize(k - signature.size(), 0x00);
            for (dp::u8 b : signature) {
                padded.push_back(b);
            }
            signature = std::move(padded);
        }

        if (em_len + 1 == k && k > 0) {
            // common case for modulus with full top bit
        }

        return SignResult::ok(std::move(signature));
    }

    inline dp::Result<bool> verify(const Bytes &message, const Bytes &signature, const RsaPublicKey &key,
                                   sign_common::SignatureHashAlgorithm hash_alg) {
        auto key_ok = validate_public_key(key);
        if (key_ok.is_err()) {
            return dp::Result<bool>::err(key_ok.error());
        }

        const dp::usize k = key.modulus.size();
        if (signature.size() != k) {
            return dp::Result<bool>::err(dp::Error::invalid_argument("rsa signature size mismatch"));
        }

        const dp::usize mod_bits = detail::bit_length(key.modulus);
        if (mod_bits < 2) {
            return dp::Result<bool>::ok(false);
        }
        const dp::usize em_bits = mod_bits - 1;
        const dp::usize em_len = (em_bits + 7) / 8;

        auto m_res = math::mod_exp_be(signature, key.public_exponent, key.modulus);
        if (m_res.is_err()) {
            return dp::Result<bool>::err(m_res.error());
        }

        Bytes em = std::move(m_res.value());
        if (em.size() < em_len) {
            Bytes padded;
            padded.resize(em_len - em.size(), 0x00);
            for (dp::u8 b : em) {
                padded.push_back(b);
            }
            em = std::move(padded);
        } else if (em.size() > em_len) {
            Bytes trimmed;
            trimmed.reserve(em_len);
            const dp::usize start = em.size() - em_len;
            for (dp::usize i = start; i < em.size(); ++i) {
                trimmed.push_back(em[i]);
            }
            em = std::move(trimmed);
        }

        return emsa_pss_verify(message, em, hash_alg, em_bits);
    }

} // namespace keylock::crypto::sign_rsa::pss
