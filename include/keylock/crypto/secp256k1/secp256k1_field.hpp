#pragma once

#include "keylock/crypto/rsa/rsa_math.hpp"
#include "keylock/crypto/signature/common/dp_echo_compat.hpp"

namespace keylock::crypto::sign_secp256k1::field {

    using Bytes = dp::Vector<dp::u8>;
    using FieldResult = dp::Result<Bytes>;

    inline const Bytes &prime_p() {
        static const Bytes P = {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
        };
        return P;
    }

    inline const Bytes &order_n() {
        static const Bytes N = {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
        };
        return N;
    }

    inline const Bytes &half_order_n() {
        static const Bytes H = {
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
        };
        return H;
    }

    inline const Bytes &sqrt_exponent_p_plus_1_div_4() {
        static const Bytes E = {
            0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbf, 0xff, 0xff, 0x0c,
        };
        return E;
    }

    inline Bytes to_fixed32(const Bytes &x) {
        if (x.size() == 32) {
            return x;
        }
        if (x.size() > 32) {
            Bytes out;
            out.reserve(32);
            for (dp::usize i = x.size() - 32; i < x.size(); ++i) {
                out.push_back(x[i]);
            }
            return out;
        }
        Bytes out;
        out.resize(32 - x.size(), 0x00);
        for (dp::u8 b : x) {
            out.push_back(b);
        }
        return out;
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

    inline bool is_zero(const Bytes &x) {
        for (dp::u8 b : x) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    inline FieldResult mod_p(const Bytes &x) {
        auto r = sign_rsa::math::mod_be(x, prime_p());
        if (r.is_err()) {
            return FieldResult::err(r.error());
        }
        return FieldResult::ok(to_fixed32(r.value()));
    }

    inline FieldResult mod_n(const Bytes &x) {
        auto r = sign_rsa::math::mod_be(x, order_n());
        if (r.is_err()) {
            return FieldResult::err(r.error());
        }
        return FieldResult::ok(to_fixed32(r.value()));
    }

    inline FieldResult add_p(const Bytes &a, const Bytes &b) {
        auto sum = sign_rsa::math::add_be(a, b);
        if (sum.is_err()) {
            return FieldResult::err(sum.error());
        }
        return mod_p(sum.value());
    }

    inline FieldResult sub_p(const Bytes &a, const Bytes &b) {
        auto aa = mod_p(a);
        auto bb = mod_p(b);
        if (aa.is_err()) {
            return aa;
        }
        if (bb.is_err()) {
            return bb;
        }

        auto diff = sign_rsa::math::sub_be(aa.value(), bb.value());
        if (diff.is_ok()) {
            return FieldResult::ok(to_fixed32(diff.value()));
        }

        auto lifted = sign_rsa::math::add_be(aa.value(), prime_p());
        if (lifted.is_err()) {
            return FieldResult::err(lifted.error());
        }
        auto diff2 = sign_rsa::math::sub_be(lifted.value(), bb.value());
        if (diff2.is_err()) {
            return FieldResult::err(diff2.error());
        }
        return FieldResult::ok(to_fixed32(diff2.value()));
    }

    inline FieldResult sub_n(const Bytes &a, const Bytes &b) {
        auto aa = mod_n(a);
        auto bb = mod_n(b);
        if (aa.is_err()) {
            return aa;
        }
        if (bb.is_err()) {
            return bb;
        }

        auto diff = sign_rsa::math::sub_be(aa.value(), bb.value());
        if (diff.is_ok()) {
            return FieldResult::ok(to_fixed32(diff.value()));
        }

        auto lifted = sign_rsa::math::add_be(aa.value(), order_n());
        if (lifted.is_err()) {
            return FieldResult::err(lifted.error());
        }
        auto diff2 = sign_rsa::math::sub_be(lifted.value(), bb.value());
        if (diff2.is_err()) {
            return FieldResult::err(diff2.error());
        }
        return FieldResult::ok(to_fixed32(diff2.value()));
    }

    inline FieldResult add_n(const Bytes &a, const Bytes &b) {
        auto sum = sign_rsa::math::add_be(a, b);
        if (sum.is_err()) {
            return FieldResult::err(sum.error());
        }
        return mod_n(sum.value());
    }

    inline FieldResult mul_p(const Bytes &a, const Bytes &b) {
        auto prod = sign_rsa::math::mul_be(a, b);
        if (prod.is_err()) {
            return FieldResult::err(prod.error());
        }
        return mod_p(prod.value());
    }

    inline FieldResult mul_n(const Bytes &a, const Bytes &b) {
        auto prod = sign_rsa::math::mul_be(a, b);
        if (prod.is_err()) {
            return FieldResult::err(prod.error());
        }
        return mod_n(prod.value());
    }

    inline FieldResult inv_p(const Bytes &a) {
        auto p_minus_2 = sign_rsa::math::sub_be(prime_p(), Bytes{0x02});
        if (p_minus_2.is_err()) {
            return FieldResult::err(p_minus_2.error());
        }
        auto inv = sign_rsa::math::mod_exp_be(a, p_minus_2.value(), prime_p());
        if (inv.is_err()) {
            return FieldResult::err(inv.error());
        }
        return FieldResult::ok(to_fixed32(inv.value()));
    }

    inline FieldResult inv_n(const Bytes &a) {
        auto n_minus_2 = sign_rsa::math::sub_be(order_n(), Bytes{0x02});
        if (n_minus_2.is_err()) {
            return FieldResult::err(n_minus_2.error());
        }
        auto inv = sign_rsa::math::mod_exp_be(a, n_minus_2.value(), order_n());
        if (inv.is_err()) {
            return FieldResult::err(inv.error());
        }
        return FieldResult::ok(to_fixed32(inv.value()));
    }

    inline FieldResult sqrt_p(const Bytes &a) {
        auto root = sign_rsa::math::mod_exp_be(a, sqrt_exponent_p_plus_1_div_4(), prime_p());
        if (root.is_err()) {
            return FieldResult::err(root.error());
        }
        auto root_fixed = to_fixed32(root.value());
        auto check = mul_p(root_fixed, root_fixed);
        if (check.is_err()) {
            return FieldResult::err(check.error());
        }
        auto a_mod = mod_p(a);
        if (a_mod.is_err()) {
            return FieldResult::err(a_mod.error());
        }
        if (check.value() != a_mod.value()) {
            return FieldResult::err(dp::Error::invalid_argument("value is not a quadratic residue"));
        }
        return FieldResult::ok(std::move(root_fixed));
    }

} // namespace keylock::crypto::sign_secp256k1::field
