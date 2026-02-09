#pragma once

#include <vector>

#include "keylock/crypto/sign_common/dp_echo_compat.hpp"
#include "keylock/crypto/sign_ecdsa_p256/p256_field.hpp"
#include "keylock/hash/context.hpp"

namespace keylock::crypto::sign_ecdsa_p256::rfc6979 {

    using Bytes = dp::Vector<dp::u8>;

    namespace detail {

        inline dp::Result<Bytes> hmac_sha256(const Bytes &key, const Bytes &message) {
            const std::vector<uint8_t> k(key.begin(), key.end());
            const std::vector<uint8_t> m(message.begin(), message.end());
            auto h = hash::hmac(hash::Algorithm::SHA256, m, k);
            if (!h.success) {
                return dp::Result<Bytes>::err(dp::Error::invalid_argument(h.error_message.c_str()));
            }
            return dp::Result<Bytes>::ok(Bytes(h.data.begin(), h.data.end()));
        }

        inline bool is_zero(const Bytes &x) {
            for (dp::u8 b : x) {
                if (b != 0) {
                    return false;
                }
            }
            return true;
        }

        inline int compare_bytes(const Bytes &a, const Bytes &b) {
            if (a.size() != b.size()) {
                return a.size() < b.size() ? -1 : 1;
            }
            for (dp::usize i = 0; i < a.size(); ++i) {
                if (a[i] < b[i]) {
                    return -1;
                }
                if (a[i] > b[i]) {
                    return 1;
                }
            }
            return 0;
        }

    } // namespace detail

    inline dp::Result<Bytes> generate_nonce_k(const Bytes &private_scalar_32, const Bytes &msg_hash_32) {
        if (private_scalar_32.size() != 32 || msg_hash_32.size() != 32) {
            return dp::Result<Bytes>::err(
                dp::Error::invalid_argument("RFC6979 expects 32-byte private scalar and hash"));
        }

        Bytes v(32, 0x01);
        Bytes k(32, 0x00);

        Bytes bx = private_scalar_32;
        Bytes bh = msg_hash_32;

        Bytes kv = v;
        kv.push_back(0x00);
        for (dp::u8 b : bx) {
            kv.push_back(b);
        }
        for (dp::u8 b : bh) {
            kv.push_back(b);
        }
        auto k1 = detail::hmac_sha256(k, kv);
        if (k1.is_err()) {
            return k1;
        }
        k = k1.value();

        auto v1 = detail::hmac_sha256(k, v);
        if (v1.is_err()) {
            return v1;
        }
        v = v1.value();

        Bytes kv2 = v;
        kv2.push_back(0x01);
        for (dp::u8 b : bx) {
            kv2.push_back(b);
        }
        for (dp::u8 b : bh) {
            kv2.push_back(b);
        }
        auto k2 = detail::hmac_sha256(k, kv2);
        if (k2.is_err()) {
            return k2;
        }
        k = k2.value();

        auto v2 = detail::hmac_sha256(k, v);
        if (v2.is_err()) {
            return v2;
        }
        v = v2.value();

        const Bytes n = field::order_n();

        for (;;) {
            auto vv = detail::hmac_sha256(k, v);
            if (vv.is_err()) {
                return vv;
            }
            v = vv.value();

            Bytes candidate = field::to_fixed32(v);
            auto cmod = sign_rsa::math::mod_be(candidate, n);
            if (cmod.is_err()) {
                return dp::Result<Bytes>::err(cmod.error());
            }
            candidate = field::to_fixed32(cmod.value());

            if (!detail::is_zero(candidate) && detail::compare_bytes(candidate, n) < 0) {
                return dp::Result<Bytes>::ok(std::move(candidate));
            }

            Bytes kk = v;
            kk.push_back(0x00);
            auto k3 = detail::hmac_sha256(k, kk);
            if (k3.is_err()) {
                return k3;
            }
            k = k3.value();

            auto v3 = detail::hmac_sha256(k, v);
            if (v3.is_err()) {
                return v3;
            }
            v = v3.value();
        }
    }

} // namespace keylock::crypto::sign_ecdsa_p256::rfc6979
