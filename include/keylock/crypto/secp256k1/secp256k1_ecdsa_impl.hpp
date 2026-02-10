#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "keylock/crypto/rng/randombytes.hpp"
#include "keylock/crypto/secp256k1/secp256k1_point.hpp"
#include "keylock/hash/keccak/keccak.hpp"
#include "keylock/hash/sha256/sha256.hpp"

namespace keylock::crypto::sign_secp256k1 {

    using Bytes = dp::Vector<dp::u8>;

    struct RecoverResult {
        bool success;
        std::vector<uint8_t> public_key_uncompressed;
        std::string error_message;
    };

    struct VerifyResult {
        bool success;
        std::string error_message;
    };

    struct NormalizeVResult {
        bool success;
        uint8_t recovery_id;
        std::string error_message;
    };

    struct SignResult {
        bool success;
        std::vector<uint8_t> signature_compact;
        uint8_t recovery_id;
        std::string error_message;
    };

    namespace detail {

        inline RecoverResult make_recover_error(const std::string &message) { return {false, {}, message}; }

        inline VerifyResult make_verify_error(const std::string &message) { return {false, message}; }

        inline bool is_valid_scalar_non_zero_less_than_n(const Bytes &x32) {
            if (x32.size() != 32) {
                return false;
            }
            if (field::is_zero(x32)) {
                return false;
            }
            return field::compare_bytes(x32, field::order_n()) < 0;
        }

        inline dp::Result<point::Point> decompress_point(const Bytes &x, uint8_t y_parity) {
            auto x_mod = field::mod_p(x);
            if (x_mod.is_err()) {
                return dp::Result<point::Point>::err(x_mod.error());
            }

            auto x2 = field::mul_p(x_mod.value(), x_mod.value());
            if (x2.is_err()) {
                return dp::Result<point::Point>::err(x2.error());
            }
            auto x3 = field::mul_p(x2.value(), x_mod.value());
            if (x3.is_err()) {
                return dp::Result<point::Point>::err(x3.error());
            }
            auto rhs = field::add_p(x3.value(), Bytes{0x07});
            if (rhs.is_err()) {
                return dp::Result<point::Point>::err(rhs.error());
            }

            auto y = field::sqrt_p(rhs.value());
            if (y.is_err()) {
                return dp::Result<point::Point>::err(y.error());
            }

            Bytes yy = y.value();
            const uint8_t parity = static_cast<uint8_t>(yy[31] & 1U);
            if (parity != (y_parity & 1U)) {
                auto neg = field::sub_p(field::prime_p(), yy);
                if (neg.is_err()) {
                    return dp::Result<point::Point>::err(neg.error());
                }
                yy = neg.value();
            }

            point::Point p;
            p.infinity = false;
            p.x = x_mod.value();
            p.y = yy;

            auto on_curve = point::is_on_curve(p);
            if (on_curve.is_err() || !on_curve.value()) {
                return dp::Result<point::Point>::err(dp::Error::invalid_argument("recovered point is not on curve"));
            }

            return dp::Result<point::Point>::ok(std::move(p));
        }

        inline dp::Result<point::Point> parse_public_key(const std::vector<uint8_t> &public_key) {
            if (public_key.size() == 65) {
                if (public_key[0] != 0x04) {
                    return dp::Result<point::Point>::err(
                        dp::Error::invalid_argument("Invalid uncompressed public key prefix"));
                }

                point::Point p;
                p.infinity = false;
                p.x.assign(public_key.begin() + 1, public_key.begin() + 33);
                p.y.assign(public_key.begin() + 33, public_key.end());

                auto on_curve = point::is_on_curve(p);
                if (on_curve.is_err() || !on_curve.value()) {
                    return dp::Result<point::Point>::err(dp::Error::invalid_argument("Public key is not on curve"));
                }
                return dp::Result<point::Point>::ok(std::move(p));
            }

            if (public_key.size() == 33) {
                if (public_key[0] != 0x02 && public_key[0] != 0x03) {
                    return dp::Result<point::Point>::err(
                        dp::Error::invalid_argument("Invalid compressed public key prefix"));
                }

                Bytes x(public_key.begin() + 1, public_key.end());
                auto p = decompress_point(x, static_cast<uint8_t>(public_key[0] & 1U));
                if (p.is_err()) {
                    return p;
                }
                return p;
            }

            return dp::Result<point::Point>::err(dp::Error::invalid_argument(
                "Invalid public key size: expected 33-byte compressed or 65-byte uncompressed"));
        }

        inline std::vector<uint8_t> encode_uncompressed(const point::Point &p) {
            std::vector<uint8_t> out;
            out.reserve(65);
            out.push_back(0x04);
            out.insert(out.end(), p.x.begin(), p.x.end());
            out.insert(out.end(), p.y.begin(), p.y.end());
            return out;
        }

        inline Bytes to_bytes(const std::vector<uint8_t> &in) { return Bytes(in.begin(), in.end()); }

        inline std::string dp_error_message(const dp::Error &error) { return std::string(error.message.c_str()); }

        inline Bytes sha256_to_scalar(const std::vector<uint8_t> &message) {
            uint8_t digest[32];
            hash::sha256::hash(digest, message.data(), message.size());
            auto z = field::mod_n(Bytes(digest, digest + 32));
            if (z.is_ok()) {
                return z.value();
            }
            return Bytes(32, 0x00);
        }

    } // namespace detail

    inline NormalizeVResult normalize_recovery_id(uint8_t v) {
        if (v == 0 || v == 1) {
            return {true, v, ""};
        }
        if (v == 27 || v == 28) {
            return {true, static_cast<uint8_t>(v - 27), ""};
        }
        return {false, 0, "Invalid v: expected 0/1 or 27/28"};
    }

    inline bool is_low_s(const std::vector<uint8_t> &s32) {
        if (s32.size() != 32) {
            return false;
        }
        Bytes s = detail::to_bytes(s32);
        if (!detail::is_valid_scalar_non_zero_less_than_n(s)) {
            return false;
        }
        return field::compare_bytes(s, field::half_order_n()) <= 0;
    }

    inline dp::Result<point::Point> derive_public_key(const std::vector<uint8_t> &private_scalar_32) {
        Bytes d = detail::to_bytes(private_scalar_32);
        if (!detail::is_valid_scalar_non_zero_less_than_n(d)) {
            return dp::Result<point::Point>::err(dp::Error::invalid_argument("Invalid secp256k1 private scalar"));
        }

        auto q = point::scalar_mul(point::generator(), d);
        if (q.is_err()) {
            return q;
        }
        if (q.value().infinity) {
            return dp::Result<point::Point>::err(
                dp::Error::invalid_argument("Derived public key is point at infinity"));
        }
        return q;
    }

    inline SignResult sign_compact_digest32(const std::vector<uint8_t> &digest32,
                                            const std::vector<uint8_t> &private_scalar_32) {
        if (digest32.size() != 32) {
            return {false, {}, 0, "Invalid digest length: expected 32 bytes"};
        }

        Bytes d = detail::to_bytes(private_scalar_32);
        if (!detail::is_valid_scalar_non_zero_less_than_n(d)) {
            return {false, {}, 0, "Invalid secp256k1 private scalar"};
        }

        auto z_mod = field::mod_n(detail::to_bytes(digest32));
        if (z_mod.is_err()) {
            return {false, {}, 0, "Failed digest reduction"};
        }
        const Bytes z = z_mod.value();

        for (int attempt = 0; attempt < 64; ++attempt) {
            Bytes k(32, 0x00);
            do {
                rng::randombytes_buf(k.data(), k.size());
                auto mk = field::mod_n(k);
                if (mk.is_err()) {
                    return {false, {}, 0, "Failed nonce reduction"};
                }
                k = mk.value();
            } while (!detail::is_valid_scalar_non_zero_less_than_n(k));

            auto r_point = point::scalar_mul(point::generator(), k);
            if (r_point.is_err() || r_point.value().infinity) {
                continue;
            }

            if (field::compare_bytes(r_point.value().x, field::order_n()) >= 0) {
                continue;
            }

            Bytes r = r_point.value().x;
            if (field::is_zero(r)) {
                continue;
            }

            auto rd = field::mul_n(r, d);
            if (rd.is_err()) {
                continue;
            }
            auto z_plus_rd = field::add_n(z, rd.value());
            auto k_inv = field::inv_n(k);
            if (z_plus_rd.is_err() || k_inv.is_err()) {
                continue;
            }

            auto s = field::mul_n(k_inv.value(), z_plus_rd.value());
            if (s.is_err() || field::is_zero(s.value())) {
                continue;
            }

            Bytes s_out = s.value();
            if (field::compare_bytes(s_out, field::half_order_n()) > 0) {
                auto n_minus_s = field::sub_n(field::order_n(), s_out);
                if (n_minus_s.is_err()) {
                    continue;
                }
                s_out = n_minus_s.value();
            }

            std::vector<uint8_t> sig;
            sig.reserve(64);
            sig.insert(sig.end(), r.begin(), r.end());
            sig.insert(sig.end(), s_out.begin(), s_out.end());

            uint8_t recid = static_cast<uint8_t>(r_point.value().y[31] & 1U);
            return {true, std::move(sig), recid, ""};
        }

        return {false, {}, 0, "Failed to generate valid secp256k1 signature"};
    }

    inline SignResult sign_compact(const std::vector<uint8_t> &message, const std::vector<uint8_t> &private_scalar_32) {
        auto digest = detail::sha256_to_scalar(message);
        std::vector<uint8_t> digest_vec(digest.begin(), digest.end());
        return sign_compact_digest32(digest_vec, private_scalar_32);
    }

    inline RecoverResult recover_public_key(const std::vector<uint8_t> &digest32, const std::vector<uint8_t> &sig64,
                                            uint8_t recovery_id) {
        if (digest32.size() != 32) {
            return detail::make_recover_error("Invalid digest length: expected 32 bytes");
        }
        if (sig64.size() != 64) {
            return detail::make_recover_error("Invalid signature length: expected 64 bytes");
        }
        if (recovery_id != 0 && recovery_id != 1) {
            return detail::make_recover_error("Invalid recovery id: expected 0 or 1");
        }

        Bytes r(sig64.begin(), sig64.begin() + 32);
        Bytes s(sig64.begin() + 32, sig64.end());
        if (!detail::is_valid_scalar_non_zero_less_than_n(r)) {
            return detail::make_recover_error("Invalid signature r scalar");
        }
        if (!detail::is_valid_scalar_non_zero_less_than_n(s)) {
            return detail::make_recover_error("Invalid signature s scalar");
        }

        auto z_mod = field::mod_n(detail::to_bytes(digest32));
        if (z_mod.is_err()) {
            return detail::make_recover_error("Failed digest reduction");
        }
        Bytes z = z_mod.value();

        auto r_point = detail::decompress_point(r, recovery_id);
        if (r_point.is_err()) {
            return detail::make_recover_error("Failed to recover R point: " +
                                              detail::dp_error_message(r_point.error()));
        }

        auto n_r = point::scalar_mul(r_point.value(), field::order_n());
        if (n_r.is_err()) {
            return detail::make_recover_error("Failed subgroup check");
        }
        if (!n_r.value().infinity) {
            return detail::make_recover_error("Recovered R point is not in subgroup");
        }

        auto r_inv = field::inv_n(r);
        if (r_inv.is_err()) {
            return detail::make_recover_error("Failed to invert r");
        }

        auto u1 = field::mul_n(s, r_inv.value());
        if (u1.is_err()) {
            return detail::make_recover_error("Failed to compute u1");
        }

        Bytes neg_z = z;
        if (!field::is_zero(z)) {
            auto nz = field::sub_n(field::order_n(), z);
            if (nz.is_err()) {
                return detail::make_recover_error("Failed to compute -z mod n");
            }
            neg_z = nz.value();
        }
        auto u2 = field::mul_n(neg_z, r_inv.value());
        if (u2.is_err()) {
            return detail::make_recover_error("Failed to compute u2");
        }

        auto sr = point::scalar_mul(r_point.value(), u1.value());
        auto zg = point::scalar_mul(point::generator(), u2.value());
        if (sr.is_err() || zg.is_err()) {
            return detail::make_recover_error("Failed point multiplication during recovery");
        }

        auto q = point::add(sr.value(), zg.value());
        if (q.is_err()) {
            return detail::make_recover_error("Failed to combine recovery points");
        }
        if (q.value().infinity) {
            return detail::make_recover_error("Recovered public key is point at infinity");
        }

        return {true, detail::encode_uncompressed(q.value()), ""};
    }

    inline VerifyResult verify_compact(const std::vector<uint8_t> &digest32, const std::vector<uint8_t> &sig64,
                                       const std::vector<uint8_t> &public_key) {
        if (digest32.size() != 32) {
            return detail::make_verify_error("Invalid digest length: expected 32 bytes");
        }
        if (sig64.size() != 64) {
            return detail::make_verify_error("Invalid signature length: expected 64 bytes");
        }

        Bytes r(sig64.begin(), sig64.begin() + 32);
        Bytes s(sig64.begin() + 32, sig64.end());
        if (!detail::is_valid_scalar_non_zero_less_than_n(r)) {
            return detail::make_verify_error("Invalid signature r scalar");
        }
        if (!detail::is_valid_scalar_non_zero_less_than_n(s)) {
            return detail::make_verify_error("Invalid signature s scalar");
        }

        auto q = detail::parse_public_key(public_key);
        if (q.is_err()) {
            return detail::make_verify_error(detail::dp_error_message(q.error()));
        }

        auto z_mod = field::mod_n(detail::to_bytes(digest32));
        if (z_mod.is_err()) {
            return detail::make_verify_error("Failed digest reduction");
        }
        Bytes z = z_mod.value();

        auto w = field::inv_n(s);
        if (w.is_err()) {
            return detail::make_verify_error("Failed to invert s");
        }

        auto u1 = field::mul_n(z, w.value());
        auto u2 = field::mul_n(r, w.value());
        if (u1.is_err() || u2.is_err()) {
            return detail::make_verify_error("Failed scalar preparation for verification");
        }

        auto p1 = point::scalar_mul(point::generator(), u1.value());
        auto p2 = point::scalar_mul(q.value(), u2.value());
        if (p1.is_err() || p2.is_err()) {
            return detail::make_verify_error("Failed point multiplication for verification");
        }

        auto p = point::add(p1.value(), p2.value());
        if (p.is_err()) {
            return detail::make_verify_error("Failed point addition for verification");
        }
        if (p.value().infinity) {
            return {false, "Signature verification failed"};
        }

        auto x_mod_n = field::mod_n(p.value().x);
        if (x_mod_n.is_err()) {
            return detail::make_verify_error("Failed x-coordinate reduction");
        }

        if (x_mod_n.value() != r) {
            return {false, "Signature verification failed"};
        }
        return {true, ""};
    }

    inline std::vector<uint8_t> ethereum_address_from_uncompressed_pubkey(const std::vector<uint8_t> &public_key) {
        if (public_key.size() != 65 || public_key[0] != 0x04) {
            return {};
        }
        uint8_t digest[32];
        hash::keccak::hash_256(digest, public_key.data() + 1, 64);
        return std::vector<uint8_t>(digest + 12, digest + 32);
    }

} // namespace keylock::crypto::sign_secp256k1
