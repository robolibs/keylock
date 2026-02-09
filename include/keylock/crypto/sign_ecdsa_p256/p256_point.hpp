#pragma once

#include "keylock/crypto/sign_ecdsa_p256/p256_field.hpp"

namespace keylock::crypto::sign_ecdsa_p256::point {

    using Bytes = dp::Vector<dp::u8>;
    using PointResult = dp::Result<bool>;

    struct Point {
        Bytes x;
        Bytes y;
        bool infinity = false;
    };

    inline Bytes zero32() { return Bytes(32, 0x00); }

    inline Bytes curve_a() {
        // a = -3 mod p
        Bytes a = field::prime_p();
        auto three = Bytes{0x03};
        auto out = sign_rsa::math::sub_be(a, three);
        if (out.is_ok()) {
            return field::to_fixed32(out.value());
        }
        return zero32();
    }

    inline const Bytes &curve_b() {
        static const Bytes b = {
            0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
            0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
        };
        return b;
    }

    inline Point generator() {
        Point g;
        g.infinity = false;
        g.x = {
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
            0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
        };
        g.y = {
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
            0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
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

    inline Point infinity() {
        Point p;
        p.infinity = true;
        p.x = zero32();
        p.y = zero32();
        return p;
    }

    inline PointResult is_on_curve(const Point &p) {
        if (p.infinity) {
            return PointResult::ok(true);
        }

        auto x = field::mod_p(p.x);
        auto y = field::mod_p(p.y);
        if (x.is_err()) {
            return PointResult::err(x.error());
        }
        if (y.is_err()) {
            return PointResult::err(y.error());
        }

        auto y2 = field::mul_p(y.value(), y.value());
        auto x2 = field::mul_p(x.value(), x.value());
        if (y2.is_err()) {
            return PointResult::err(y2.error());
        }
        if (x2.is_err()) {
            return PointResult::err(x2.error());
        }

        auto x3 = field::mul_p(x2.value(), x.value());
        if (x3.is_err()) {
            return PointResult::err(x3.error());
        }

        auto ax = field::mul_p(curve_a(), x.value());
        if (ax.is_err()) {
            return PointResult::err(ax.error());
        }

        auto rhs1 = field::add_p(x3.value(), ax.value());
        if (rhs1.is_err()) {
            return PointResult::err(rhs1.error());
        }
        auto rhs = field::add_p(rhs1.value(), curve_b());
        if (rhs.is_err()) {
            return PointResult::err(rhs.error());
        }

        return PointResult::ok(y2.value() == rhs.value());
    }

    inline dp::Result<Point> double_point(const Point &p) {
        if (p.infinity) {
            return dp::Result<Point>::ok(p);
        }

        auto two = field::to_fixed32(Bytes{0x02});
        auto three = field::to_fixed32(Bytes{0x03});

        auto x2 = field::mul_p(p.x, p.x);
        auto three_x2 = field::mul_p(x2.value(), three);
        auto num = field::add_p(three_x2.value(), curve_a());
        auto two_y = field::mul_p(two, p.y);
        auto den_inv = field::inv_p(two_y.value());
        auto lambda = field::mul_p(num.value(), den_inv.value());

        auto lambda2 = field::mul_p(lambda.value(), lambda.value());
        auto two_x = field::mul_p(two, p.x);
        auto x3 = field::sub_p(lambda2.value(), two_x.value());
        auto x1_minus_x3 = field::sub_p(p.x, x3.value());
        auto y3a = field::mul_p(lambda.value(), x1_minus_x3.value());
        auto y3 = field::sub_p(y3a.value(), p.y);

        if (x2.is_err() || three_x2.is_err() || num.is_err() || two_y.is_err() || den_inv.is_err() || lambda.is_err() ||
            lambda2.is_err() || two_x.is_err() || x3.is_err() || x1_minus_x3.is_err() || y3a.is_err() || y3.is_err()) {
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
            bool is_zero = true;
            for (dp::u8 b : y_sum.value()) {
                if (b != 0) {
                    is_zero = false;
                    break;
                }
            }
            if (is_zero) {
                return dp::Result<Point>::ok(infinity());
            }
            return double_point(p);
        }

        auto y_diff = field::sub_p(q.y, p.y);
        auto x_diff = field::sub_p(q.x, p.x);
        if (y_diff.is_err() || x_diff.is_err()) {
            return dp::Result<Point>::err(dp::Error::invalid_argument("point add difference failed"));
        }

        auto x_inv = field::inv_p(x_diff.value());
        if (x_inv.is_err()) {
            return dp::Result<Point>::err(x_inv.error());
        }

        auto lambda = field::mul_p(y_diff.value(), x_inv.value());
        if (lambda.is_err()) {
            return dp::Result<Point>::err(lambda.error());
        }

        auto lambda2 = field::mul_p(lambda.value(), lambda.value());
        auto sum_x = field::add_p(p.x, q.x);
        auto x3 = field::sub_p(lambda2.value(), sum_x.value());
        auto x1_minus_x3 = field::sub_p(p.x, x3.value());
        auto y3a = field::mul_p(lambda.value(), x1_minus_x3.value());
        auto y3 = field::sub_p(y3a.value(), p.y);

        if (lambda2.is_err() || sum_x.is_err() || x3.is_err() || x1_minus_x3.is_err() || y3a.is_err() || y3.is_err()) {
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

} // namespace keylock::crypto::sign_ecdsa_p256::point
