#pragma once

#include <utility>

#include "keylock/crypto/sign_common/hash_route.hpp"
#include "keylock/crypto/sign_rsa/rsa_keys.hpp"
#include "keylock/crypto/sign_rsa/rsa_math.hpp"

namespace keylock::crypto::sign_rsa::pkcs1v15 {

    using Bytes = dp::Vector<dp::u8>;
    using SignResult = dp::Result<Bytes>;

    inline dp::Result<Bytes> digest_info_prefix(sign_common::SignatureHashAlgorithm hash_alg) {
        // DER prefix for DigestInfo ::= SEQUENCE {digestAlgorithm, digest}
        // RFC 8017, Appendix B.1
        switch (hash_alg) {
        case sign_common::SignatureHashAlgorithm::SHA256:
            return dp::Result<Bytes>::ok(Bytes{
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
            });
        case sign_common::SignatureHashAlgorithm::SHA384:
            return dp::Result<Bytes>::ok(Bytes{
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
            });
        case sign_common::SignatureHashAlgorithm::SHA512:
            return dp::Result<Bytes>::ok(Bytes{
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
            });
        }
        return dp::Result<Bytes>::err(dp::Error::invalid_argument("unsupported hash algorithm"));
    }

    inline dp::Result<Bytes> emsa_encode(const Bytes &message, sign_common::SignatureHashAlgorithm hash_alg,
                                         dp::usize modulus_len_bytes) {
        auto digest_res = sign_common::hash_message(hash_alg, message);
        if (digest_res.is_err()) {
            return dp::Result<Bytes>::err(digest_res.error());
        }

        auto prefix_res = digest_info_prefix(hash_alg);
        if (prefix_res.is_err()) {
            return dp::Result<Bytes>::err(prefix_res.error());
        }

        Bytes t = std::move(prefix_res.value());
        const Bytes &digest = digest_res.value();
        for (dp::u8 b : digest) {
            t.push_back(b);
        }

        if (modulus_len_bytes < t.size() + 11) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("rsa modulus too short for pkcs1 v1.5"));
        }

        Bytes em;
        em.resize(modulus_len_bytes, 0);
        em[0] = 0x00;
        em[1] = 0x01;

        const dp::usize ps_len = modulus_len_bytes - t.size() - 3;
        for (dp::usize i = 0; i < ps_len; ++i) {
            em[2 + i] = 0xff;
        }
        em[2 + ps_len] = 0x00;
        for (dp::usize i = 0; i < t.size(); ++i) {
            em[3 + ps_len + i] = t[i];
        }

        return dp::Result<Bytes>::ok(std::move(em));
    }

    inline SignResult sign(const Bytes &message, const RsaPrivateKey &key,
                           sign_common::SignatureHashAlgorithm hash_alg) {
        auto key_ok = validate_private_key(key);
        if (key_ok.is_err()) {
            return SignResult::err(key_ok.error());
        }

        const dp::usize k = key.modulus.size();
        auto em_res = emsa_encode(message, hash_alg, k);
        if (em_res.is_err()) {
            return SignResult::err(em_res.error());
        }

        auto sig_res = math::mod_exp_be(em_res.value(), key.private_exponent, key.modulus);
        if (sig_res.is_err()) {
            return SignResult::err(sig_res.error());
        }

        Bytes sig = std::move(sig_res.value());
        if (sig.size() < k) {
            Bytes padded;
            padded.resize(k - sig.size(), 0);
            for (dp::u8 b : sig) {
                padded.push_back(b);
            }
            sig = std::move(padded);
        }
        return SignResult::ok(std::move(sig));
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

        auto em_res = emsa_encode(message, hash_alg, k);
        if (em_res.is_err()) {
            return dp::Result<bool>::err(em_res.error());
        }

        auto m_res = math::mod_exp_be(signature, key.public_exponent, key.modulus);
        if (m_res.is_err()) {
            return dp::Result<bool>::err(m_res.error());
        }

        Bytes recovered = std::move(m_res.value());
        if (recovered.size() < k) {
            Bytes padded;
            padded.resize(k - recovered.size(), 0);
            for (dp::u8 b : recovered) {
                padded.push_back(b);
            }
            recovered = std::move(padded);
        }

        return dp::Result<bool>::ok(recovered == em_res.value());
    }

} // namespace keylock::crypto::sign_rsa::pkcs1v15
