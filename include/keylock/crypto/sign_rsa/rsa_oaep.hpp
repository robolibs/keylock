#pragma once

#include "keylock/crypto/rng/randombytes.hpp"
#include "keylock/crypto/sign_common/hash_route.hpp"
#include "keylock/crypto/sign_rsa/rsa_core.hpp"

namespace keylock::crypto::sign_rsa::oaep {

    using Bytes = dp::Vector<dp::u8>;

    namespace detail {

        inline Bytes left_pad(const Bytes &x, dp::usize len) {
            if (x.size() >= len) {
                Bytes out;
                out.reserve(len);
                for (dp::usize i = x.size() - len; i < x.size(); ++i) {
                    out.push_back(x[i]);
                }
                return out;
            }
            Bytes out(len - x.size(), 0x00);
            for (dp::u8 b : x) {
                out.push_back(b);
            }
            return out;
        }

        inline dp::Result<Bytes> mgf1(const Bytes &seed, dp::usize out_len,
                                      sign_common::SignatureHashAlgorithm hash_alg) {
            Bytes out;
            out.reserve(out_len);
            dp::u32 c = 0;
            while (out.size() < out_len) {
                Bytes in = seed;
                in.push_back(static_cast<dp::u8>((c >> 24) & 0xff));
                in.push_back(static_cast<dp::u8>((c >> 16) & 0xff));
                in.push_back(static_cast<dp::u8>((c >> 8) & 0xff));
                in.push_back(static_cast<dp::u8>(c & 0xff));
                auto h = sign_common::hash_message(hash_alg, in);
                if (h.is_err()) {
                    return dp::Result<Bytes>::err(h.error());
                }
                for (dp::u8 b : h.value()) {
                    if (out.size() == out_len) {
                        break;
                    }
                    out.push_back(b);
                }
                ++c;
            }
            return dp::Result<Bytes>::ok(std::move(out));
        }

    } // namespace detail

    inline dp::Result<Bytes> encode(const Bytes &message, dp::usize k, sign_common::SignatureHashAlgorithm hash_alg,
                                    const Bytes &label = {}, const Bytes &seed_override = {}) {
        const dp::usize h_len = sign_common::digest_size(hash_alg);
        if (h_len == 0) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("invalid OAEP hash algorithm"));
        }
        if (k < 2 * h_len + 2) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("rsa modulus too short for OAEP"));
        }
        if (message.size() > k - 2 * h_len - 2) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("oaep message too long"));
        }

        auto l_hash = sign_common::hash_message(hash_alg, label);
        if (l_hash.is_err()) {
            return dp::Result<Bytes>::err(l_hash.error());
        }

        Bytes db;
        db.reserve(k - h_len - 1);
        for (dp::u8 b : l_hash.value()) {
            db.push_back(b);
        }

        const dp::usize ps_len = k - message.size() - 2 * h_len - 2;
        db.resize(db.size() + ps_len, 0x00);
        db.push_back(0x01);
        for (dp::u8 b : message) {
            db.push_back(b);
        }

        Bytes seed = seed_override;
        if (seed.empty()) {
            seed.resize(h_len);
            rng::randombytes_buf(seed.data(), seed.size());
        }
        if (seed.size() != h_len) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("invalid OAEP seed size"));
        }

        auto db_mask = detail::mgf1(seed, k - h_len - 1, hash_alg);
        if (db_mask.is_err()) {
            return dp::Result<Bytes>::err(db_mask.error());
        }
        Bytes masked_db = db;
        for (dp::usize i = 0; i < masked_db.size(); ++i) {
            masked_db[i] ^= db_mask.value()[i];
        }

        auto seed_mask = detail::mgf1(masked_db, h_len, hash_alg);
        if (seed_mask.is_err()) {
            return dp::Result<Bytes>::err(seed_mask.error());
        }
        Bytes masked_seed = seed;
        for (dp::usize i = 0; i < masked_seed.size(); ++i) {
            masked_seed[i] ^= seed_mask.value()[i];
        }

        Bytes em;
        em.reserve(k);
        em.push_back(0x00);
        for (dp::u8 b : masked_seed) {
            em.push_back(b);
        }
        for (dp::u8 b : masked_db) {
            em.push_back(b);
        }
        return dp::Result<Bytes>::ok(std::move(em));
    }

    inline dp::Result<Bytes> decode(const Bytes &encoded_message, sign_common::SignatureHashAlgorithm hash_alg,
                                    const Bytes &label = {}) {
        const dp::usize h_len = sign_common::digest_size(hash_alg);
        if (h_len == 0) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("invalid OAEP hash algorithm"));
        }
        if (encoded_message.size() < 2 * h_len + 2) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("oaep encoded message too short"));
        }
        if (encoded_message[0] != 0x00) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("oaep leading byte invalid"));
        }

        const dp::usize k = encoded_message.size();
        Bytes masked_seed(encoded_message.begin() + 1,
                          encoded_message.begin() + 1 + static_cast<std::ptrdiff_t>(h_len));
        Bytes masked_db(encoded_message.begin() + 1 + static_cast<std::ptrdiff_t>(h_len), encoded_message.end());

        auto seed_mask = detail::mgf1(masked_db, h_len, hash_alg);
        if (seed_mask.is_err()) {
            return dp::Result<Bytes>::err(seed_mask.error());
        }
        Bytes seed = masked_seed;
        for (dp::usize i = 0; i < h_len; ++i) {
            seed[i] ^= seed_mask.value()[i];
        }

        auto db_mask = detail::mgf1(seed, k - h_len - 1, hash_alg);
        if (db_mask.is_err()) {
            return dp::Result<Bytes>::err(db_mask.error());
        }
        Bytes db = masked_db;
        for (dp::usize i = 0; i < db.size(); ++i) {
            db[i] ^= db_mask.value()[i];
        }

        auto l_hash = sign_common::hash_message(hash_alg, label);
        if (l_hash.is_err()) {
            return dp::Result<Bytes>::err(l_hash.error());
        }
        for (dp::usize i = 0; i < h_len; ++i) {
            if (db[i] != l_hash.value()[i]) {
                return dp::Result<Bytes>::err(dp::Error::invalid_argument("oaep label hash mismatch"));
            }
        }

        dp::usize idx = h_len;
        while (idx < db.size() && db[idx] == 0x00) {
            ++idx;
        }
        if (idx >= db.size() || db[idx] != 0x01) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("oaep delimiter not found"));
        }
        ++idx;

        Bytes msg;
        msg.reserve(db.size() - idx);
        for (; idx < db.size(); ++idx) {
            msg.push_back(db[idx]);
        }
        return dp::Result<Bytes>::ok(std::move(msg));
    }

    inline dp::Result<Bytes> encrypt(const Bytes &message, const RsaPublicKey &key,
                                     sign_common::SignatureHashAlgorithm hash_alg, const Bytes &label = {}) {
        const dp::usize k = key.modulus.size();
        auto em = encode(message, k, hash_alg, label);
        if (em.is_err()) {
            return dp::Result<Bytes>::err(em.error());
        }

        auto c = core::public_op(em.value(), key);
        if (c.is_err()) {
            return dp::Result<Bytes>::err(c.error());
        }
        return dp::Result<Bytes>::ok(detail::left_pad(c.value(), k));
    }

    inline dp::Result<Bytes> decrypt(const Bytes &ciphertext, const RsaPrivateKey &key,
                                     sign_common::SignatureHashAlgorithm hash_alg, const Bytes &label = {}) {
        const dp::usize k = key.modulus.size();
        if (ciphertext.size() != k) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("oaep ciphertext size mismatch"));
        }

        auto m = core::private_op_crt(ciphertext, key);
        if (m.is_err()) {
            return dp::Result<Bytes>::err(m.error());
        }
        auto em = detail::left_pad(m.value(), k);
        return decode(em, hash_alg, label);
    }

} // namespace keylock::crypto::sign_rsa::oaep
