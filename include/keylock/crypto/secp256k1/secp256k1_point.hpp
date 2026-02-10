#pragma once

#include "keylock/crypto/secp256k1/secp256k1_field.hpp"

namespace keylock::crypto::sign_secp256k1::point {

    using Bytes = dp::Vector<dp::u8>;

    struct Point {
        Bytes x;
        Bytes y;
        bool infinity = false;
    };

    inline Bytes zero32() { return Bytes(32, 0x00); }

    inline Point infinity() {
        Point p;
        p.infinity = true;
        p.x = zero32();
        p.y = zero32();
        return p;
    }

    inline Point generator() {
        Point g;
        g.infinity = false;
        g.x = {
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
            0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        };
        g.y = {
            0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
            0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
        };
        return g;
    }

    inline bool equal(const Point &a, const Point &b) {
        if (a.infinity != b.infinity) {
            return false;
        }
        if (a.infinity) {
            return true;
        }
        return a.x == b.x && a.y == b.y;
    }

    inline dp::Result<bool> is_on_curve(const Point &p) {
        if (p.infinity) {
            return dp::Result<bool>::ok(true);
        }

        auto x = field::mod_p(p.x);
        auto y = field::mod_p(p.y);
        if (x.is_err()) {
            return dp::Result<bool>::err(x.error());
        }
        if (y.is_err()) {
            return dp::Result<bool>::err(y.error());
        }

        auto y2 = field::mul_p(y.value(), y.value());
        auto x2 = field::mul_p(x.value(), x.value());
        if (y2.is_err()) {
            return dp::Result<bool>::err(y2.error());
        }
        if (x2.is_err()) {
            return dp::Result<bool>::err(x2.error());
        }

        auto x3 = field::mul_p(x2.value(), x.value());
        if (x3.is_err()) {
            return dp::Result<bool>::err(x3.error());
        }

        auto rhs = field::add_p(x3.value(), Bytes{0x07});
        if (rhs.is_err()) {
            return dp::Result<bool>::err(rhs.error());
        }

        return dp::Result<bool>::ok(y2.value() == rhs.value());
    }

    inline dp::Result<Point> double_point(const Point &p) {
        if (p.infinity) {
            return dp::Result<Point>::ok(p);
        }

        if (field::is_zero(p.y)) {
            return dp::Result<Point>::ok(infinity());
        }

        auto two = field::to_fixed32(Bytes{0x02});
        auto three = field::to_fixed32(Bytes{0x03});

        auto x2 = field::mul_p(p.x, p.x);
        if (x2.is_err()) {
            return dp::Result<Point>::err(dp::Error::invalid_argument("point doubling failed"));
        }

        auto num = field::mul_p(three, x2.value());
        auto den = field::mul_p(two, p.y);
        if (num.is_err() || den.is_err() || field::is_zero(den.value())) {
            return dp::Result<Point>::err(dp::Error::invalid_argument("point doubling failed"));
        }

        auto den_inv = field::inv_p(den.value());
        if (den_inv.is_err()) {
            return dp::Result<Point>::err(den_inv.error());
        }

        auto lambda = field::mul_p(num.value(), den_inv.value());
        auto lambda2 = field::mul_p(lambda.value(), lambda.value());
        auto two_x = field::mul_p(two, p.x);
        auto x3 = field::sub_p(lambda2.value(), two_x.value());
        auto x1_minus_x3 = field::sub_p(p.x, x3.value());
        auto y3a = field::mul_p(lambda.value(), x1_minus_x3.value());
        auto y3 = field::sub_p(y3a.value(), p.y);

        if (lambda.is_err() || lambda2.is_err() || two_x.is_err() || x3.is_err() || x1_minus_x3.is_err() ||
            y3a.is_err() || y3.is_err()) {
            return dp::Result<Point>::err(dp::Error::invalid_argument("point doubling failed"));
        }

        Point out;
        out.infinity = false;
        out.x = x3.value();
        out.y = y3.value();
        return dp::Result<Point>::ok(std::move(out));
    }

    inline dp::Result<Point> add(const Point &p, const Point &q) {
        if (p.infinity) {
            return dp::Result<Point>::ok(q);
        }
        if (q.infinity) {
            return dp::Result<Point>::ok(p);
        }

        if (p.x == q.x) {
            auto y_sum = field::add_p(p.y, q.y);
            if (y_sum.is_err()) {
                return dp::Result<Point>::err(y_sum.error());
            }
            if (field::is_zero(y_sum.value())) {
                return dp::Result<Point>::ok(infinity());
            }
            return double_point(p);
        }

        auto y_diff = field::sub_p(q.y, p.y);
        auto x_diff = field::sub_p(q.x, p.x);
        if (y_diff.is_err() || x_diff.is_err()) {
            return dp::Result<Point>::err(dp::Error::invalid_argument("point add difference failed"));
        }
        if (field::is_zero(x_diff.value())) {
            return dp::Result<Point>::err(dp::Error::invalid_argument("point add difference failed"));
        }

        auto x_inv = field::inv_p(x_diff.value());
        if (x_inv.is_err()) {
            return dp::Result<Point>::err(x_inv.error());
        }

        auto lambda = field::mul_p(y_diff.value(), x_inv.value());
        auto lambda2 = field::mul_p(lambda.value(), lambda.value());
        auto sum_x = field::add_p(p.x, q.x);
        auto x3 = field::sub_p(lambda2.value(), sum_x.value());
        auto x1_minus_x3 = field::sub_p(p.x, x3.value());
        auto y3a = field::mul_p(lambda.value(), x1_minus_x3.value());
        auto y3 = field::sub_p(y3a.value(), p.y);

        if (lambda.is_err() || lambda2.is_err() || sum_x.is_err() || x3.is_err() || x1_minus_x3.is_err() ||
            y3a.is_err() || y3.is_err()) {
            return dp::Result<Point>::err(dp::Error::invalid_argument("point add failed"));
        }

        Point out;
        out.infinity = false;
        out.x = x3.value();
        out.y = y3.value();
        return dp::Result<Point>::ok(std::move(out));
    }

    inline dp::Result<Point> scalar_mul(const Point &p, const Bytes &scalar) {
        Point result = infinity();
        Point addend = p;

        for (dp::u8 byte : scalar) {
            for (int bit = 7; bit >= 0; --bit) {
                auto doubled = double_point(result);
                if (doubled.is_err()) {
                    return dp::Result<Point>::err(doubled.error());
                }
                result = doubled.value();

                if (((byte >> bit) & 1U) != 0) {
                    auto added = add(result, addend);
                    if (added.is_err()) {
                        return dp::Result<Point>::err(added.error());
                    }
                    result = added.value();
                }
            }
        }

        return dp::Result<Point>::ok(std::move(result));
    }

} // namespace keylock::crypto::sign_secp256k1::point
