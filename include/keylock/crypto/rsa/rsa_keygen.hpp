#pragma once

#include <algorithm>
#include <utility>

#include "keylock/crypto/rng/randombytes.hpp"
#include "keylock/crypto/rsa/rsa_keys.hpp"
#include "keylock/crypto/rsa/rsa_math.hpp"

namespace keylock::crypto::sign_rsa::keygen {

    using Bytes = dp::Vector<dp::u8>;
    using KeygenResult = dp::Result<RsaPrivateKey>;

    namespace detail {

        inline Bytes from_u32(dp::u32 value) {
            if (value == 0) {
                return Bytes{0};
            }
            Bytes out;
            while (value > 0) {
                out.push_back(static_cast<dp::u8>(value & 0xffU));
                value >>= 8;
            }
            std::reverse(out.begin(), out.end());
            return out;
        }

        inline int compare_be(const Bytes &a, const Bytes &b) {
            dp::usize ia = 0;
            while (ia + 1 < a.size() && a[ia] == 0) {
                ++ia;
            }
            dp::usize ib = 0;
            while (ib + 1 < b.size() && b[ib] == 0) {
                ++ib;
            }

            const dp::usize sa = a.size() - ia;
            const dp::usize sb = b.size() - ib;
            if (sa < sb) {
                return -1;
            }
            if (sa > sb) {
                return 1;
            }
            for (dp::usize i = 0; i < sa; ++i) {
                if (a[ia + i] < b[ib + i]) {
                    return -1;
                }
                if (a[ia + i] > b[ib + i]) {
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

        inline dp::u32 mod_small(const Bytes &x, dp::u32 m) {
            if (m == 0) {
                return 0;
            }
            dp::u64 rem = 0;
            for (dp::u8 b : x) {
                rem = ((rem << 8) + b) % m;
            }
            return static_cast<dp::u32>(rem);
        }

        inline dp::Result<Bytes> mul_small(const Bytes &x, dp::u32 m) {
            if (m == 0 || is_zero(x)) {
                return dp::Result<Bytes>::ok(Bytes{0});
            }

            Bytes out;
            out.resize(x.size(), 0);
            dp::u64 carry = 0;
            for (dp::usize i = x.size(); i > 0; --i) {
                const dp::u64 cur = static_cast<dp::u64>(x[i - 1]) * m + carry;
                out[i - 1] = static_cast<dp::u8>(cur & 0xffU);
                carry = cur >> 8;
            }

            while (carry > 0) {
                out.insert(out.begin(), static_cast<dp::u8>(carry & 0xffU));
                carry >>= 8;
            }
            return dp::Result<Bytes>::ok(std::move(out));
        }

        inline dp::Result<Bytes> add_small(const Bytes &x, dp::u32 v) {
            Bytes out = x;
            dp::u64 carry = v;
            for (dp::usize i = out.size(); i > 0 && carry > 0; --i) {
                const dp::u64 sum = static_cast<dp::u64>(out[i - 1]) + (carry & 0xffU);
                out[i - 1] = static_cast<dp::u8>(sum & 0xffU);
                carry = (carry >> 8) + (sum >> 8);
            }
            while (carry > 0) {
                out.insert(out.begin(), static_cast<dp::u8>(carry & 0xffU));
                carry >>= 8;
            }
            return dp::Result<Bytes>::ok(std::move(out));
        }

        inline dp::Result<Bytes> div_small_exact(const Bytes &x, dp::u32 d) {
            if (d == 0) {
                return dp::Result<Bytes>::err(dp::Error::invalid_argument("division by zero"));
            }

            Bytes q;
            q.resize(x.size(), 0);
            dp::u64 rem = 0;
            for (dp::usize i = 0; i < x.size(); ++i) {
                rem = (rem << 8) + x[i];
                q[i] = static_cast<dp::u8>(rem / d);
                rem %= d;
            }
            if (rem != 0) {
                return dp::Result<Bytes>::err(dp::Error::invalid_argument("non-exact division"));
            }

            dp::usize first = 0;
            while (first + 1 < q.size() && q[first] == 0) {
                ++first;
            }
            if (first > 0) {
                Bytes trimmed;
                trimmed.reserve(q.size() - first);
                for (dp::usize i = first; i < q.size(); ++i) {
                    trimmed.push_back(q[i]);
                }
                q = std::move(trimmed);
            }
            return dp::Result<Bytes>::ok(std::move(q));
        }

        inline Bytes random_odd_candidate(dp::usize bits) {
            const dp::usize bytes = (bits + 7) / 8;
            Bytes x(bytes);
            rng::randombytes_buf(x.data(), x.size());
            x[0] |= 0x80U;
            x.back() |= 0x01U;
            return x;
        }

        inline Bytes shift_right_one(const Bytes &x) {
            Bytes out = x;
            dp::u8 carry = 0;
            for (dp::usize i = 0; i < out.size(); ++i) {
                const dp::u8 next_carry = static_cast<dp::u8>(out[i] & 1U);
                out[i] = static_cast<dp::u8>((out[i] >> 1) | (carry << 7));
                carry = next_carry;
            }
            dp::usize first = 0;
            while (first + 1 < out.size() && out[first] == 0) {
                ++first;
            }
            if (first > 0) {
                Bytes trimmed;
                trimmed.reserve(out.size() - first);
                for (dp::usize i = first; i < out.size(); ++i) {
                    trimmed.push_back(out[i]);
                }
                return trimmed;
            }
            return out;
        }

        inline bool is_probable_prime(const Bytes &n) {
            if (n.empty() || (n.size() == 1 && n[0] < 2)) {
                return false;
            }
            if ((n.back() & 1U) == 0) {
                return n.size() == 1 && n[0] == 2;
            }

            static const dp::u32 SMALL_PRIMES[] = {3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
            for (dp::u32 p : SMALL_PRIMES) {
                const dp::u32 r = mod_small(n, p);
                if (r == 0) {
                    return n.size() == 1 && n[0] == p;
                }
            }

            auto n_minus_1 = math::sub_be(n, Bytes{1});
            if (n_minus_1.is_err()) {
                return false;
            }

            Bytes d = n_minus_1.value();
            dp::usize s = 0;
            while (!d.empty() && (d.back() & 1U) == 0) {
                d = shift_right_one(d);
                ++s;
            }

            static const dp::u32 BASES[] = {2, 3, 5, 17, 257, 65537};
            for (dp::u32 a32 : BASES) {
                if (mod_small(n, a32) == 0) {
                    continue;
                }
                Bytes a = from_u32(a32);
                auto x = math::mod_exp_be(a, d, n);
                if (x.is_err()) {
                    return false;
                }

                if (x.value() == Bytes{1} || x.value() == n_minus_1.value()) {
                    continue;
                }

                bool witness = true;
                Bytes xi = x.value();
                for (dp::usize i = 1; i < s; ++i) {
                    auto sq = math::mul_be(xi, xi);
                    if (sq.is_err()) {
                        return false;
                    }
                    auto mod = math::mod_be(sq.value(), n);
                    if (mod.is_err()) {
                        return false;
                    }
                    xi = mod.value();
                    if (xi == n_minus_1.value()) {
                        witness = false;
                        break;
                    }
                }
                if (witness) {
                    return false;
                }
            }

            return true;
        }

        inline dp::Result<Bytes> generate_prime(dp::usize bits, dp::u32 e) {
            for (int tries = 0; tries < 10000; ++tries) {
                Bytes p = random_odd_candidate(bits);
                if (mod_small(p, e) <= 1) {
                    continue;
                }
                auto p_minus_1 = math::sub_be(p, Bytes{1});
                if (p_minus_1.is_err()) {
                    continue;
                }
                if (mod_small(p_minus_1.value(), e) == 0) {
                    continue;
                }
                if (is_probable_prime(p)) {
                    return dp::Result<Bytes>::ok(std::move(p));
                }
            }
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("unable to generate probable prime"));
        }

    } // namespace detail

    inline KeygenResult generate_keypair(dp::usize modulus_bits = 2048, dp::u32 public_exponent = 65537) {
        if (modulus_bits < 1024 || (modulus_bits % 2) != 0) {
            return KeygenResult::err(dp::Error::invalid_argument("rsa modulus bits must be even and >= 1024"));
        }
        if (public_exponent < 3 || (public_exponent % 2) == 0) {
            return KeygenResult::err(dp::Error::invalid_argument("rsa public exponent must be odd and >=3"));
        }

        const dp::usize prime_bits = modulus_bits / 2;

        for (int attempts = 0; attempts < 64; ++attempts) {
            auto p_res = detail::generate_prime(prime_bits, public_exponent);
            auto q_res = detail::generate_prime(prime_bits, public_exponent);
            if (p_res.is_err() || q_res.is_err()) {
                continue;
            }

            Bytes p = p_res.value();
            Bytes q = q_res.value();
            if (detail::compare_be(p, q) == 0) {
                continue;
            }

            auto n_res = math::mul_be(p, q);
            if (n_res.is_err()) {
                continue;
            }
            Bytes n = n_res.value();

            auto p1 = math::sub_be(p, Bytes{1});
            auto q1 = math::sub_be(q, Bytes{1});
            if (p1.is_err() || q1.is_err()) {
                continue;
            }
            auto phi_res = math::mul_be(p1.value(), q1.value());
            if (phi_res.is_err()) {
                continue;
            }
            Bytes phi = phi_res.value();

            const dp::u32 phi_mod_e = detail::mod_small(phi, public_exponent);
            if (phi_mod_e == 0) {
                continue;
            }

            dp::u32 k = 0;
            for (dp::u32 candidate_k = 1; candidate_k < public_exponent; ++candidate_k) {
                if (((static_cast<dp::u64>(candidate_k) * phi_mod_e + 1ULL) % public_exponent) == 0ULL) {
                    k = candidate_k;
                    break;
                }
            }
            if (k == 0) {
                continue;
            }

            auto kphi = detail::mul_small(phi, k);
            if (kphi.is_err()) {
                continue;
            }
            auto num = detail::add_small(kphi.value(), 1);
            if (num.is_err()) {
                continue;
            }
            auto d_res = detail::div_small_exact(num.value(), public_exponent);
            if (d_res.is_err()) {
                continue;
            }

            RsaPrivateKey key;
            key.modulus = std::move(n);
            key.public_exponent = detail::from_u32(public_exponent);
            key.private_exponent = std::move(d_res.value());

            key.prime_p = p;
            key.prime_q = q;

            auto dp_res = math::mod_be(key.private_exponent, p1.value());
            auto dq_res = math::mod_be(key.private_exponent, q1.value());
            auto p_minus_2 = math::sub_be(p, Bytes{2});
            if (dp_res.is_err() || dq_res.is_err() || p_minus_2.is_err()) {
                continue;
            }
            auto qinv_res = math::mod_exp_be(q, p_minus_2.value(), p);
            if (qinv_res.is_err()) {
                continue;
            }

            key.crt_dp = dp_res.value();
            key.crt_dq = dq_res.value();
            key.crt_qinv = qinv_res.value();

            auto ok = validate_private_key(key);
            if (ok.is_ok()) {
                return KeygenResult::ok(std::move(key));
            }
        }

        return KeygenResult::err(dp::Error::invalid_argument("rsa key generation failed"));
    }

} // namespace keylock::crypto::sign_rsa::keygen
