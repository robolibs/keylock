#pragma once

#include "keylock/crypto/sign_common/dp_echo_compat.hpp"

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
    };

    inline ValidationResult validate_public_key(const RsaPublicKey &key) {
        if (key.modulus.empty() || (key.modulus.size() == 1 && key.modulus[0] == 0)) {
            return ValidationResult::err(dp::Error::invalid_argument("rsa modulus must be non-zero"));
        }
        if (key.public_exponent.empty()) {
            return ValidationResult::err(dp::Error::invalid_argument("rsa public exponent must be non-empty"));
        }

        const dp::u8 lsb_e = key.public_exponent.back() & 1U;
        if (lsb_e == 0) {
            return ValidationResult::err(dp::Error::invalid_argument("rsa public exponent must be odd"));
        }

        if (key.modulus.back() % 2U == 0) {
            return ValidationResult::err(dp::Error::invalid_argument("rsa modulus must be odd"));
        }

        if (key.modulus.size() < 64) {
            echo::warn("validate_public_key: rsa modulus smaller than 512 bits");
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
        return ValidationResult::ok();
    }

} // namespace keylock::crypto::sign_rsa
