#pragma once

#include "keylock/crypto/sign_common/dp_echo_compat.hpp"
#include "keylock/crypto/sign_rsa/rsa_math.hpp"

namespace keylock::crypto::sign_ecdsa_p256::field {

    using Bytes = dp::Vector<dp::u8>;
    using FieldResult = dp::Result<Bytes>;

    inline const Bytes &prime_p() {
        static const Bytes P = {
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        };
        return P;
    }

    inline const Bytes &order_n() {
        static const Bytes N = {
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
        };
        return N;
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

    inline FieldResult mod_p(const Bytes &x) {
        auto r = sign_rsa::math::mod_be(x, prime_p());
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

    inline FieldResult mul_p(const Bytes &a, const Bytes &b) {
        auto prod = sign_rsa::math::mul_be(a, b);
        if (prod.is_err()) {
            return FieldResult::err(prod.error());
        }
        return mod_p(prod.value());
    }

    inline FieldResult inv_p(const Bytes &a) {
        // Fermat inverse: a^(p-2) mod p
        Bytes exponent = prime_p();
        auto two = Bytes{0x02};
        auto exp_sub = sign_rsa::math::sub_be(exponent, two);
        if (exp_sub.is_err()) {
            return FieldResult::err(exp_sub.error());
        }

        auto inv = sign_rsa::math::mod_exp_be(a, exp_sub.value(), prime_p());
        if (inv.is_err()) {
            return FieldResult::err(inv.error());
        }
        return FieldResult::ok(to_fixed32(inv.value()));
    }

} // namespace keylock::crypto::sign_ecdsa_p256::field
