#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <utility>

#include "keylock/crypto/sign_common/dp_echo_compat.hpp"

namespace keylock::crypto::sign_rsa::math {

    using Bytes = dp::Vector<dp::u8>;
    using MathResult = dp::Result<Bytes>;

    namespace detail {

        inline void trim_leading_zero_words(dp::Vector<dp::u32> &words) {
            while (!words.empty() && words.back() == 0) {
                words.pop_back();
            }
        }

        inline dp::Vector<dp::u32> bytes_to_words_le(const Bytes &be) {
            dp::Vector<dp::u32> words;
            if (be.empty()) {
                return words;
            }
            const dp::usize n_words = (be.size() + 3) / 4;
            words.resize(n_words, 0);

            dp::usize byte_index = be.size();
            for (dp::usize w = 0; w < n_words; ++w) {
                dp::u32 acc = 0;
                for (dp::usize b = 0; b < 4 && byte_index > 0; ++b) {
                    --byte_index;
                    acc |= static_cast<dp::u32>(be[byte_index]) << (8 * b);
                }
                words[w] = acc;
            }
            trim_leading_zero_words(words);
            return words;
        }

        inline Bytes words_le_to_bytes(const dp::Vector<dp::u32> &words_in) {
            dp::Vector<dp::u32> words = words_in;
            trim_leading_zero_words(words);
            if (words.empty()) {
                return Bytes{0};
            }

            Bytes out;
            out.resize(words.size() * 4);
            for (dp::usize i = 0; i < words.size(); ++i) {
                const dp::u32 w = words[i];
                const dp::usize o = out.size() - (i + 1) * 4;
                out[o + 0] = static_cast<dp::u8>((w >> 24) & 0xff);
                out[o + 1] = static_cast<dp::u8>((w >> 16) & 0xff);
                out[o + 2] = static_cast<dp::u8>((w >> 8) & 0xff);
                out[o + 3] = static_cast<dp::u8>(w & 0xff);
            }

            dp::usize first_non_zero = 0;
            while (first_non_zero + 1 < out.size() && out[first_non_zero] == 0) {
                ++first_non_zero;
            }
            if (first_non_zero == 0) {
                return out;
            }

            Bytes compact;
            compact.reserve(out.size() - first_non_zero);
            for (dp::usize i = first_non_zero; i < out.size(); ++i) {
                compact.push_back(out[i]);
            }
            return compact;
        }

        inline int compare_words(const dp::Vector<dp::u32> &a_in, const dp::Vector<dp::u32> &b_in) {
            dp::Vector<dp::u32> a = a_in;
            dp::Vector<dp::u32> b = b_in;
            trim_leading_zero_words(a);
            trim_leading_zero_words(b);

            if (a.size() < b.size()) {
                return -1;
            }
            if (a.size() > b.size()) {
                return 1;
            }
            for (dp::usize i = a.size(); i > 0; --i) {
                if (a[i - 1] < b[i - 1]) {
                    return -1;
                }
                if (a[i - 1] > b[i - 1]) {
                    return 1;
                }
            }
            return 0;
        }

        inline dp::Vector<dp::u32> add_words(const dp::Vector<dp::u32> &a, const dp::Vector<dp::u32> &b) {
            const dp::usize n = a.size() > b.size() ? a.size() : b.size();
            dp::Vector<dp::u32> out;
            out.resize(n + 1, 0);

            dp::u64 carry = 0;
            for (dp::usize i = 0; i < n; ++i) {
                const dp::u64 ai = i < a.size() ? a[i] : 0;
                const dp::u64 bi = i < b.size() ? b[i] : 0;
                const dp::u64 sum = ai + bi + carry;
                out[i] = static_cast<dp::u32>(sum & 0xffffffffULL);
                carry = sum >> 32;
            }
            out[n] = static_cast<dp::u32>(carry);
            trim_leading_zero_words(out);
            return out;
        }

        inline dp::Result<dp::Vector<dp::u32>> sub_words(const dp::Vector<dp::u32> &a, const dp::Vector<dp::u32> &b) {
            if (compare_words(a, b) < 0) {
                return dp::Result<dp::Vector<dp::u32>>::err(dp::Error::invalid_argument("subtraction underflow"));
            }

            dp::Vector<dp::u32> out;
            out.resize(a.size(), 0);
            dp::i64 borrow = 0;
            for (dp::usize i = 0; i < a.size(); ++i) {
                const dp::i64 ai = a[i];
                const dp::i64 bi = i < b.size() ? b[i] : 0;
                dp::i64 v = ai - bi - borrow;
                if (v < 0) {
                    v += (1LL << 32);
                    borrow = 1;
                } else {
                    borrow = 0;
                }
                out[i] = static_cast<dp::u32>(v);
            }

            trim_leading_zero_words(out);
            return dp::Result<dp::Vector<dp::u32>>::ok(std::move(out));
        }

        inline dp::Vector<dp::u32> mul_words(const dp::Vector<dp::u32> &a, const dp::Vector<dp::u32> &b) {
            if (a.empty() || b.empty()) {
                return {};
            }

            dp::Vector<dp::u32> out;
            out.resize(a.size() + b.size(), 0);

            for (dp::usize i = 0; i < a.size(); ++i) {
                dp::u64 carry = 0;
                for (dp::usize j = 0; j < b.size(); ++j) {
                    const dp::usize k = i + j;
                    const dp::u64 cur =
                        static_cast<dp::u64>(out[k]) + static_cast<dp::u64>(a[i]) * static_cast<dp::u64>(b[j]) + carry;
                    out[k] = static_cast<dp::u32>(cur & 0xffffffffULL);
                    carry = cur >> 32;
                }
                out[i + b.size()] = static_cast<dp::u32>(static_cast<dp::u64>(out[i + b.size()]) + carry);
            }

            trim_leading_zero_words(out);
            return out;
        }

        inline dp::usize bit_length_words(const dp::Vector<dp::u32> &words_in) {
            dp::Vector<dp::u32> words = words_in;
            trim_leading_zero_words(words);
            if (words.empty()) {
                return 0;
            }

            dp::u32 top = words.back();
            dp::usize bits = 0;
            while (top > 0) {
                top >>= 1;
                ++bits;
            }
            return (words.size() - 1) * 32 + bits;
        }

        inline bool get_bit_words(const dp::Vector<dp::u32> &words, dp::usize bit_index) {
            const dp::usize word_index = bit_index / 32;
            if (word_index >= words.size()) {
                return false;
            }
            const dp::usize offset = bit_index % 32;
            return ((words[word_index] >> offset) & 1U) != 0;
        }

        inline void shift_left_one_in_place(dp::Vector<dp::u32> &words) {
            dp::u64 carry = 0;
            for (dp::usize i = 0; i < words.size(); ++i) {
                const dp::u64 v = (static_cast<dp::u64>(words[i]) << 1) | carry;
                words[i] = static_cast<dp::u32>(v & 0xffffffffULL);
                carry = (v >> 32) & 1ULL;
            }
            if (carry != 0) {
                words.push_back(static_cast<dp::u32>(carry));
            }
        }

        inline dp::Vector<dp::u32> modulo_words(const dp::Vector<dp::u32> &a, const dp::Vector<dp::u32> &m) {
            dp::Vector<dp::u32> mod = m;
            trim_leading_zero_words(mod);
            if (mod.empty()) {
                return {};
            }

            dp::Vector<dp::u32> rem;
            rem.push_back(0);
            const dp::usize bits = bit_length_words(a);

            for (dp::usize i = bits; i > 0; --i) {
                shift_left_one_in_place(rem);
                if (get_bit_words(a, i - 1)) {
                    if (rem.empty()) {
                        rem.push_back(1);
                    } else {
                        rem[0] |= 1U;
                    }
                }
                trim_leading_zero_words(rem);
                if (compare_words(rem, mod) >= 0) {
                    const auto sub = sub_words(rem, mod);
                    if (!sub.is_ok()) {
                        return {};
                    }
                    rem = sub.value();
                }
            }

            trim_leading_zero_words(rem);
            if (rem.empty()) {
                rem.push_back(0);
            }
            return rem;
        }

        inline dp::Result<dp::u64> to_u64(const Bytes &value_be) {
            if (value_be.size() > 8) {
                return dp::Result<dp::u64>::err(dp::Error::invalid_argument("value exceeds u64"));
            }
            dp::u64 v = 0;
            for (dp::u8 b : value_be) {
                v = (v << 8) | static_cast<dp::u64>(b);
            }
            return dp::Result<dp::u64>::ok(v);
        }

        inline Bytes from_u64(dp::u64 value) {
            if (value == 0) {
                return Bytes{0};
            }
            Bytes out;
            while (value > 0) {
                out.push_back(static_cast<dp::u8>(value & 0xff));
                value >>= 8;
            }
            std::reverse(out.begin(), out.end());
            return out;
        }

    } // namespace detail

    inline MathResult add_be(const Bytes &a, const Bytes &b) {
        const auto aw = detail::bytes_to_words_le(a);
        const auto bw = detail::bytes_to_words_le(b);
        const auto out = detail::add_words(aw, bw);
        return MathResult::ok(detail::words_le_to_bytes(out));
    }

    inline MathResult sub_be(const Bytes &a, const Bytes &b) {
        const auto aw = detail::bytes_to_words_le(a);
        const auto bw = detail::bytes_to_words_le(b);
        const auto out = detail::sub_words(aw, bw);
        if (!out.is_ok()) {
            return MathResult::err(out.error());
        }
        return MathResult::ok(detail::words_le_to_bytes(out.value()));
    }

    inline MathResult mul_be(const Bytes &a, const Bytes &b) {
        const auto aw = detail::bytes_to_words_le(a);
        const auto bw = detail::bytes_to_words_le(b);
        const auto out = detail::mul_words(aw, bw);
        return MathResult::ok(detail::words_le_to_bytes(out));
    }

    inline MathResult mod_be(const Bytes &a, const Bytes &modulus) {
        const auto mw = detail::bytes_to_words_le(modulus);
        if (mw.empty()) {
            return MathResult::err(dp::Error::invalid_argument("modulus must be non-zero"));
        }
        const auto aw = detail::bytes_to_words_le(a);
        const auto out = detail::modulo_words(aw, mw);
        return MathResult::ok(detail::words_le_to_bytes(out));
    }

    inline MathResult mod_exp_be(const Bytes &base, const Bytes &exponent, const Bytes &modulus) {
        auto mod_base_res = mod_be(base, modulus);
        if (!mod_base_res.is_ok()) {
            return mod_base_res;
        }

        Bytes result{1};
        Bytes cur = std::move(mod_base_res.value());

        for (dp::u8 byte : exponent) {
            for (int bit = 7; bit >= 0; --bit) {
                auto sq = mul_be(result, result);
                if (!sq.is_ok()) {
                    return sq;
                }
                auto sq_mod = mod_be(sq.value(), modulus);
                if (!sq_mod.is_ok()) {
                    return sq_mod;
                }
                result = std::move(sq_mod.value());

                if (((byte >> bit) & 1U) != 0) {
                    auto mul = mul_be(result, cur);
                    if (!mul.is_ok()) {
                        return mul;
                    }
                    auto mul_mod = mod_be(mul.value(), modulus);
                    if (!mul_mod.is_ok()) {
                        return mul_mod;
                    }
                    result = std::move(mul_mod.value());
                }
            }
        }

        return MathResult::ok(std::move(result));
    }

    inline MathResult mod_inverse_be(const Bytes &a, const Bytes &modulus) {
        const auto a64 = detail::to_u64(a);
        const auto m64 = detail::to_u64(modulus);
        if (!a64.is_ok() || !m64.is_ok()) {
            echo::warn("mod_inverse_be currently supports up to 64-bit operands in phase 1");
            return MathResult::err(dp::Error::invalid_argument("mod inverse currently limited to <=64-bit operands"));
        }

        const dp::u64 m = m64.value();
        if (m == 0) {
            return MathResult::err(dp::Error::invalid_argument("modulus must be non-zero"));
        }
        const dp::u64 x = a64.value() % m;

        dp::i64 t = 0;
        dp::i64 new_t = 1;
        dp::i64 r = static_cast<dp::i64>(m);
        dp::i64 new_r = static_cast<dp::i64>(x);

        while (new_r != 0) {
            const dp::i64 q = r / new_r;

            const dp::i64 next_t = t - q * new_t;
            t = new_t;
            new_t = next_t;

            const dp::i64 next_r = r - q * new_r;
            r = new_r;
            new_r = next_r;
        }

        if (r != 1) {
            return MathResult::err(dp::Error::invalid_argument("value has no modular inverse"));
        }

        if (t < 0) {
            t += static_cast<dp::i64>(m);
        }
        return MathResult::ok(detail::from_u64(static_cast<dp::u64>(t)));
    }

} // namespace keylock::crypto::sign_rsa::math
