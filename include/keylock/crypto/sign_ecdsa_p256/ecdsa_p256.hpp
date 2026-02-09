#pragma once

#include <vector>

#include "keylock/crypto/sign_common/hash_route.hpp"
#include "keylock/crypto/sign_ecdsa_p256/p256_point.hpp"
#include "keylock/crypto/sign_ecdsa_p256/rfc6979.hpp"

namespace keylock::crypto::sign_ecdsa_p256 {

    using Bytes = dp::Vector<dp::u8>;

    struct PrivateKey {
        Bytes d; // 32-byte scalar
    };

    struct PublicKey {
        point::Point q;
    };

    namespace detail {

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

        inline dp::Result<Bytes> mod_n(const Bytes &x) {
            auto r = sign_rsa::math::mod_be(x, field::order_n());
            if (r.is_err()) {
                return dp::Result<Bytes>::err(r.error());
            }
            return dp::Result<Bytes>::ok(field::to_fixed32(r.value()));
        }

        inline dp::Result<Bytes> add_n(const Bytes &a, const Bytes &b) {
            auto s = sign_rsa::math::add_be(a, b);
            if (s.is_err()) {
                return dp::Result<Bytes>::err(s.error());
            }
            return mod_n(s.value());
        }

        inline dp::Result<Bytes> mul_n(const Bytes &a, const Bytes &b) {
            auto p = sign_rsa::math::mul_be(a, b);
            if (p.is_err()) {
                return dp::Result<Bytes>::err(p.error());
            }
            return mod_n(p.value());
        }

        inline dp::Result<Bytes> inv_n(const Bytes &x) {
            auto n_minus_2 = sign_rsa::math::sub_be(field::order_n(), Bytes{0x02});
            if (n_minus_2.is_err()) {
                return dp::Result<Bytes>::err(n_minus_2.error());
            }
            auto inv = sign_rsa::math::mod_exp_be(x, n_minus_2.value(), field::order_n());
            if (inv.is_err()) {
                return dp::Result<Bytes>::err(inv.error());
            }
            return dp::Result<Bytes>::ok(field::to_fixed32(inv.value()));
        }

        inline dp::Result<Bytes> hash_to_z(const Bytes &message) {
            auto h = sign_common::hash_message(sign_common::SignatureHashAlgorithm::SHA256, message);
            if (h.is_err()) {
                return dp::Result<Bytes>::err(h.error());
            }
            return mod_n(h.value());
        }

    } // namespace detail

    inline dp::Result<void> validate_private_key(const PrivateKey &sk) {
        Bytes d = field::to_fixed32(sk.d);
        if (detail::is_zero(d)) {
            return dp::Result<void>::err(dp::Error::invalid_argument("ecdsa private scalar must be non-zero"));
        }
        if (detail::compare_bytes(d, field::order_n()) >= 0) {
            return dp::Result<void>::err(dp::Error::invalid_argument("ecdsa private scalar out of range"));
        }
        return dp::Result<void>::ok();
    }

    inline dp::Result<void> validate_public_key(const PublicKey &pk) {
        if (pk.q.infinity) {
            return dp::Result<void>::err(dp::Error::invalid_argument("ecdsa public key cannot be point at infinity"));
        }
        auto on_curve = point::is_on_curve(pk.q);
        if (on_curve.is_err()) {
            return dp::Result<void>::err(on_curve.error());
        }
        if (!on_curve.value()) {
            return dp::Result<void>::err(dp::Error::invalid_argument("ecdsa public key not on curve"));
        }
        return dp::Result<void>::ok();
    }

    inline dp::Result<PublicKey> derive_public_key(const PrivateKey &sk) {
        auto sk_ok = validate_private_key(sk);
        if (sk_ok.is_err()) {
            return dp::Result<PublicKey>::err(sk_ok.error());
        }

        auto q = point::scalar_mul(point::generator(), field::to_fixed32(sk.d));
        if (q.is_err()) {
            return dp::Result<PublicKey>::err(q.error());
        }
        return dp::Result<PublicKey>::ok(PublicKey{q.value()});
    }

    inline dp::Result<Bytes> sign_detached(const Bytes &message, const PrivateKey &sk) {
        auto sk_ok = validate_private_key(sk);
        if (sk_ok.is_err()) {
            return dp::Result<Bytes>::err(sk_ok.error());
        }

        const Bytes d = field::to_fixed32(sk.d);
        auto z = detail::hash_to_z(message);
        if (z.is_err()) {
            return dp::Result<Bytes>::err(z.error());
        }

        auto k_res = rfc6979::generate_nonce_k(d, z.value());
        if (k_res.is_err()) {
            return dp::Result<Bytes>::err(k_res.error());
        }
        const Bytes k = k_res.value();

        auto r_point = point::scalar_mul(point::generator(), k);
        if (r_point.is_err() || r_point.value().infinity) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("ecdsa nonce produced invalid point"));
        }

        auto r = detail::mod_n(r_point.value().x);
        if (r.is_err() || detail::is_zero(r.value())) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("ecdsa r is zero"));
        }

        auto rd = detail::mul_n(r.value(), d);
        if (rd.is_err()) {
            return dp::Result<Bytes>::err(rd.error());
        }
        auto z_plus_rd = detail::add_n(z.value(), rd.value());
        if (z_plus_rd.is_err()) {
            return dp::Result<Bytes>::err(z_plus_rd.error());
        }

        auto k_inv = detail::inv_n(k);
        if (k_inv.is_err()) {
            return dp::Result<Bytes>::err(k_inv.error());
        }

        auto s = detail::mul_n(k_inv.value(), z_plus_rd.value());
        if (s.is_err() || detail::is_zero(s.value())) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("ecdsa s is zero"));
        }

        Bytes sig;
        sig.reserve(64);
        for (dp::u8 b : field::to_fixed32(r.value())) {
            sig.push_back(b);
        }
        for (dp::u8 b : field::to_fixed32(s.value())) {
            sig.push_back(b);
        }
        return dp::Result<Bytes>::ok(std::move(sig));
    }

    inline dp::Result<bool> verify_detached(const Bytes &message, const Bytes &signature, const PublicKey &pk) {
        auto pk_ok = validate_public_key(pk);
        if (pk_ok.is_err()) {
            return dp::Result<bool>::err(pk_ok.error());
        }

        if (signature.size() != 64) {
            return dp::Result<bool>::ok(false);
        }

        Bytes r(signature.begin(), signature.begin() + 32);
        Bytes s(signature.begin() + 32, signature.end());

        r = field::to_fixed32(r);
        s = field::to_fixed32(s);
        if (detail::is_zero(r) || detail::is_zero(s)) {
            return dp::Result<bool>::ok(false);
        }
        if (detail::compare_bytes(r, field::order_n()) >= 0 || detail::compare_bytes(s, field::order_n()) >= 0) {
            return dp::Result<bool>::ok(false);
        }

        auto z = detail::hash_to_z(message);
        if (z.is_err()) {
            return dp::Result<bool>::err(z.error());
        }

        auto w = detail::inv_n(s);
        if (w.is_err()) {
            return dp::Result<bool>::err(w.error());
        }

        auto u1 = detail::mul_n(z.value(), w.value());
        auto u2 = detail::mul_n(r, w.value());
        if (u1.is_err() || u2.is_err()) {
            return dp::Result<bool>::err(dp::Error::invalid_argument("ecdsa scalar multiplication prep failed"));
        }

        auto p1 = point::scalar_mul(point::generator(), u1.value());
        auto p2 = point::scalar_mul(pk.q, u2.value());
        if (p1.is_err() || p2.is_err()) {
            return dp::Result<bool>::err(dp::Error::invalid_argument("ecdsa point multiplication failed"));
        }

        auto p = point::add(p1.value(), p2.value());
        if (p.is_err()) {
            return dp::Result<bool>::err(p.error());
        }
        if (p.value().infinity) {
            return dp::Result<bool>::ok(false);
        }

        auto v = detail::mod_n(p.value().x);
        if (v.is_err()) {
            return dp::Result<bool>::err(v.error());
        }
        return dp::Result<bool>::ok(v.value() == r);
    }

} // namespace keylock::crypto::sign_ecdsa_p256
