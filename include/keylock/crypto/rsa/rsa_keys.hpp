#pragma once

#include "keylock/crypto/signature/common/dp_echo_compat.hpp"

namespace keylock::crypto::sign_rsa {

    using Bytes = dp::Vector<dp::u8>;
    using ValidationResult = dp::Result<void>;

    struct RsaPublicKey {
        Bytes modulus;         // n
        Bytes public_exponent; // e
    };

    struct RsaPrivateKey {
        Bytes modulus;          // n
        Bytes public_exponent;  // e
        Bytes private_exponent; // d
        Bytes prime_p;          // p (optional)
        Bytes prime_q;          // q (optional)
        Bytes crt_dp;           // d mod (p-1) (optional)
        Bytes crt_dq;           // d mod (q-1) (optional)
        Bytes crt_qinv;         // q^{-1} mod p (optional)
    };

    inline bool has_crt_parameters(const RsaPrivateKey &key) {
        return !key.prime_p.empty() && !key.prime_q.empty() && !key.crt_dp.empty() && !key.crt_dq.empty() &&
               !key.crt_qinv.empty();
    }

    inline ValidationResult validate_public_key(const RsaPublicKey &key) {
        if (key.modulus.empty() || (key.modulus.size() == 1 && key.modulus[0] == 0)) {
            return ValidationResult::err(dp::Error::invalid_argument("rsa modulus must be non-zero"));
        }
        if (key.modulus.size() > 1 && key.modulus[0] == 0x00) {
            return ValidationResult::err(dp::Error::invalid_argument("rsa modulus must be canonical big-endian"));
        }
        if (key.public_exponent.empty()) {
            return ValidationResult::err(dp::Error::invalid_argument("rsa public exponent must be non-empty"));
        }
        if (key.public_exponent.size() > 1 && key.public_exponent[0] == 0x00) {
            return ValidationResult::err(
                dp::Error::invalid_argument("rsa public exponent must be canonical big-endian"));
        }

        if (key.modulus.size() < 64) {
            return ValidationResult::err(dp::Error::invalid_argument("rsa modulus must be at least 512 bits"));
        }

        const dp::u8 lsb_e = key.public_exponent.back() & 1U;
        if (lsb_e == 0) {
            return ValidationResult::err(dp::Error::invalid_argument("rsa public exponent must be odd"));
        }

        if (key.public_exponent.size() == 1 && key.public_exponent[0] < 3) {
            return ValidationResult::err(dp::Error::invalid_argument("rsa public exponent must be >= 3"));
        }

        if (key.modulus.back() % 2U == 0) {
            return ValidationResult::err(dp::Error::invalid_argument("rsa modulus must be odd"));
        }

        return ValidationResult::ok();
    }

    inline ValidationResult validate_private_key(const RsaPrivateKey &key) {
        auto pub_result = validate_public_key(RsaPublicKey{key.modulus, key.public_exponent});
        if (pub_result.is_err()) {
            return pub_result;
        }
        if (key.private_exponent.empty()) {
            return ValidationResult::err(dp::Error::invalid_argument("rsa private exponent must be non-empty"));
        }
        if (key.private_exponent.size() > 1 && key.private_exponent[0] == 0x00) {
            return ValidationResult::err(
                dp::Error::invalid_argument("rsa private exponent must be canonical big-endian"));
        }

        const bool any_crt = !key.prime_p.empty() || !key.prime_q.empty() || !key.crt_dp.empty() ||
                             !key.crt_dq.empty() || !key.crt_qinv.empty();
        if (any_crt && !has_crt_parameters(key)) {
            return ValidationResult::err(dp::Error::invalid_argument("rsa crt parameters are incomplete"));
        }
        return ValidationResult::ok();
    }

} // namespace keylock::crypto::sign_rsa
