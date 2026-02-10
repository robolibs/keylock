#pragma once

#include "keylock/crypto/rsa/rsa_keys.hpp"
#include "keylock/crypto/rsa/rsa_math.hpp"

namespace keylock::crypto::sign_rsa::core {

    using Bytes = dp::Vector<dp::u8>;

    inline dp::Result<Bytes> public_op(const Bytes &message_repr, const RsaPublicKey &key) {
        auto valid = validate_public_key(key);
        if (valid.is_err()) {
            return dp::Result<Bytes>::err(valid.error());
        }

        auto m_cmp = math::sub_be(message_repr, key.modulus);
        if (m_cmp.is_ok()) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("rsa message representative out of range"));
        }

        auto out = math::mod_exp_be(message_repr, key.public_exponent, key.modulus);
        if (out.is_err()) {
            return dp::Result<Bytes>::err(out.error());
        }
        return dp::Result<Bytes>::ok(out.value());
    }

    inline dp::Result<Bytes> private_op_basic(const Bytes &cipher_repr, const RsaPrivateKey &key) {
        auto valid = validate_private_key(key);
        if (valid.is_err()) {
            return dp::Result<Bytes>::err(valid.error());
        }

        auto c_cmp = math::sub_be(cipher_repr, key.modulus);
        if (c_cmp.is_ok()) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("rsa ciphertext representative out of range"));
        }

        auto out = math::mod_exp_be(cipher_repr, key.private_exponent, key.modulus);
        if (out.is_err()) {
            return dp::Result<Bytes>::err(out.error());
        }
        return dp::Result<Bytes>::ok(out.value());
    }

    inline dp::Result<Bytes> private_op_crt(const Bytes &cipher_repr, const RsaPrivateKey &key) {
        if (!has_crt_parameters(key)) {
            return private_op_basic(cipher_repr, key);
        }

        auto m1 = math::mod_exp_be(cipher_repr, key.crt_dp, key.prime_p);
        auto m2 = math::mod_exp_be(cipher_repr, key.crt_dq, key.prime_q);
        if (m1.is_err() || m2.is_err()) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("rsa crt exponentiation failed"));
        }

        auto diff = math::sub_be(m1.value(), m2.value());
        Bytes diff_mod;
        if (diff.is_ok()) {
            diff_mod = diff.value();
        } else {
            auto lifted = math::add_be(m1.value(), key.prime_p);
            if (lifted.is_err()) {
                return dp::Result<Bytes>::err(lifted.error());
            }
            auto diff2 = math::sub_be(lifted.value(), m2.value());
            if (diff2.is_err()) {
                return dp::Result<Bytes>::err(diff2.error());
            }
            diff_mod = diff2.value();
        }

        auto h_mul = math::mul_be(key.crt_qinv, diff_mod);
        if (h_mul.is_err()) {
            return dp::Result<Bytes>::err(h_mul.error());
        }
        auto h = math::mod_be(h_mul.value(), key.prime_p);
        if (h.is_err()) {
            return dp::Result<Bytes>::err(h.error());
        }

        auto hq = math::mul_be(h.value(), key.prime_q);
        if (hq.is_err()) {
            return dp::Result<Bytes>::err(hq.error());
        }
        auto recombined = math::add_be(m2.value(), hq.value());
        if (recombined.is_err()) {
            return dp::Result<Bytes>::err(recombined.error());
        }

        auto mod_n = math::mod_be(recombined.value(), key.modulus);
        if (mod_n.is_err()) {
            return dp::Result<Bytes>::err(mod_n.error());
        }
        return dp::Result<Bytes>::ok(mod_n.value());
    }

} // namespace keylock::crypto::sign_rsa::core
