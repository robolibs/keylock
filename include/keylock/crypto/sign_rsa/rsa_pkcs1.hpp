#pragma once

#include <algorithm>

#include "keylock/crypto/sign_rsa/rsa_keys.hpp"

namespace keylock::crypto::sign_rsa::pkcs1 {

    using Bytes = dp::Vector<dp::u8>;

    namespace detail {

        inline Bytes trim_leading_zeros(const Bytes &x) {
            dp::usize i = 0;
            while (i + 1 < x.size() && x[i] == 0x00) {
                ++i;
            }
            Bytes out;
            out.reserve(x.size() - i);
            for (; i < x.size(); ++i) {
                out.push_back(x[i]);
            }
            return out;
        }

        inline Bytes write_len(dp::usize len) {
            if (len < 0x80) {
                return Bytes{static_cast<dp::u8>(len)};
            }
            Bytes bytes;
            dp::usize v = len;
            while (v > 0) {
                bytes.push_back(static_cast<dp::u8>(v & 0xff));
                v >>= 8;
            }
            std::reverse(bytes.begin(), bytes.end());
            Bytes out;
            out.push_back(static_cast<dp::u8>(0x80U | bytes.size()));
            for (dp::u8 b : bytes) {
                out.push_back(b);
            }
            return out;
        }

        inline bool read_len(const Bytes &in, dp::usize &off, dp::usize &len_out) {
            if (off >= in.size()) {
                return false;
            }
            dp::u8 first = in[off++];
            if ((first & 0x80U) == 0) {
                len_out = first;
                return true;
            }
            dp::u8 n = static_cast<dp::u8>(first & 0x7fU);
            if (n == 0 || n > 4 || off + n > in.size()) {
                return false;
            }
            len_out = 0;
            for (dp::u8 i = 0; i < n; ++i) {
                len_out = (len_out << 8) | in[off++];
            }
            return true;
        }

        inline Bytes encode_integer(const Bytes &x) {
            Bytes v = trim_leading_zeros(x);
            if (v.empty()) {
                v.push_back(0x00);
            }
            if ((v[0] & 0x80U) != 0) {
                v.insert(v.begin(), 0x00);
            }
            Bytes out{0x02};
            auto len = write_len(v.size());
            out.insert(out.end(), len.begin(), len.end());
            out.insert(out.end(), v.begin(), v.end());
            return out;
        }

        inline dp::Result<Bytes> decode_integer(const Bytes &in, dp::usize &off) {
            if (off >= in.size() || in[off++] != 0x02) {
                return dp::Result<Bytes>::err(dp::Error::invalid_argument("pkcs1 integer tag missing"));
            }
            dp::usize len = 0;
            if (!read_len(in, off, len) || len == 0 || off + len > in.size()) {
                return dp::Result<Bytes>::err(dp::Error::invalid_argument("pkcs1 integer length invalid"));
            }
            Bytes v;
            v.reserve(len);
            for (dp::usize i = 0; i < len; ++i) {
                v.push_back(in[off++]);
            }
            if ((v[0] & 0x80U) != 0) {
                return dp::Result<Bytes>::err(dp::Error::invalid_argument("pkcs1 negative integer"));
            }
            if (v.size() > 1 && v[0] == 0x00 && (v[1] & 0x80U) == 0) {
                return dp::Result<Bytes>::err(dp::Error::invalid_argument("pkcs1 non-canonical integer"));
            }
            return dp::Result<Bytes>::ok(trim_leading_zeros(v));
        }

    } // namespace detail

    inline dp::Result<Bytes> encode_public_key_der(const RsaPublicKey &key) {
        auto valid = validate_public_key(key);
        if (valid.is_err()) {
            return dp::Result<Bytes>::err(valid.error());
        }

        Bytes body = detail::encode_integer(key.modulus);
        auto e = detail::encode_integer(key.public_exponent);
        body.insert(body.end(), e.begin(), e.end());

        Bytes out{0x30};
        auto len = detail::write_len(body.size());
        out.insert(out.end(), len.begin(), len.end());
        out.insert(out.end(), body.begin(), body.end());
        return dp::Result<Bytes>::ok(std::move(out));
    }

    inline dp::Result<RsaPublicKey> decode_public_key_der(const Bytes &der) {
        dp::usize off = 0;
        if (off >= der.size() || der[off++] != 0x30) {
            return dp::Result<RsaPublicKey>::err(dp::Error::invalid_argument("pkcs1 public key sequence missing"));
        }
        dp::usize len = 0;
        if (!detail::read_len(der, off, len) || off + len != der.size()) {
            return dp::Result<RsaPublicKey>::err(dp::Error::invalid_argument("pkcs1 public key length invalid"));
        }

        auto n = detail::decode_integer(der, off);
        auto e = detail::decode_integer(der, off);
        if (n.is_err() || e.is_err() || off != der.size()) {
            return dp::Result<RsaPublicKey>::err(dp::Error::invalid_argument("pkcs1 public key parse failed"));
        }

        RsaPublicKey key{n.value(), e.value()};
        auto valid = validate_public_key(key);
        if (valid.is_err()) {
            return dp::Result<RsaPublicKey>::err(valid.error());
        }
        return dp::Result<RsaPublicKey>::ok(std::move(key));
    }

    inline dp::Result<Bytes> encode_private_key_der(const RsaPrivateKey &key) {
        auto valid = validate_private_key(key);
        if (valid.is_err()) {
            return dp::Result<Bytes>::err(valid.error());
        }

        Bytes body = detail::encode_integer(Bytes{0x00}); // version
        auto n = detail::encode_integer(key.modulus);
        auto e = detail::encode_integer(key.public_exponent);
        auto d = detail::encode_integer(key.private_exponent);
        body.insert(body.end(), n.begin(), n.end());
        body.insert(body.end(), e.begin(), e.end());
        body.insert(body.end(), d.begin(), d.end());

        if (has_crt_parameters(key)) {
            auto p = detail::encode_integer(key.prime_p);
            auto q = detail::encode_integer(key.prime_q);
            auto dp_i = detail::encode_integer(key.crt_dp);
            auto dq_i = detail::encode_integer(key.crt_dq);
            auto qinv = detail::encode_integer(key.crt_qinv);
            body.insert(body.end(), p.begin(), p.end());
            body.insert(body.end(), q.begin(), q.end());
            body.insert(body.end(), dp_i.begin(), dp_i.end());
            body.insert(body.end(), dq_i.begin(), dq_i.end());
            body.insert(body.end(), qinv.begin(), qinv.end());
        }

        Bytes out{0x30};
        auto len = detail::write_len(body.size());
        out.insert(out.end(), len.begin(), len.end());
        out.insert(out.end(), body.begin(), body.end());
        return dp::Result<Bytes>::ok(std::move(out));
    }

    inline dp::Result<RsaPrivateKey> decode_private_key_der(const Bytes &der) {
        dp::usize off = 0;
        if (off >= der.size() || der[off++] != 0x30) {
            return dp::Result<RsaPrivateKey>::err(dp::Error::invalid_argument("pkcs1 private key sequence missing"));
        }
        dp::usize len = 0;
        if (!detail::read_len(der, off, len) || off + len != der.size()) {
            return dp::Result<RsaPrivateKey>::err(dp::Error::invalid_argument("pkcs1 private key length invalid"));
        }

        auto ver = detail::decode_integer(der, off);
        auto n = detail::decode_integer(der, off);
        auto e = detail::decode_integer(der, off);
        auto d = detail::decode_integer(der, off);
        if (ver.is_err() || n.is_err() || e.is_err() || d.is_err()) {
            return dp::Result<RsaPrivateKey>::err(dp::Error::invalid_argument("pkcs1 private key parse failed"));
        }

        RsaPrivateKey key;
        key.modulus = n.value();
        key.public_exponent = e.value();
        key.private_exponent = d.value();

        if (off < der.size()) {
            auto p = detail::decode_integer(der, off);
            auto q = detail::decode_integer(der, off);
            auto dp_i = detail::decode_integer(der, off);
            auto dq_i = detail::decode_integer(der, off);
            auto qinv = detail::decode_integer(der, off);
            if (p.is_err() || q.is_err() || dp_i.is_err() || dq_i.is_err() || qinv.is_err()) {
                return dp::Result<RsaPrivateKey>::err(dp::Error::invalid_argument("pkcs1 crt parse failed"));
            }
            key.prime_p = p.value();
            key.prime_q = q.value();
            key.crt_dp = dp_i.value();
            key.crt_dq = dq_i.value();
            key.crt_qinv = qinv.value();
        }

        if (off != der.size()) {
            return dp::Result<RsaPrivateKey>::err(dp::Error::invalid_argument("pkcs1 trailing bytes"));
        }

        auto valid = validate_private_key(key);
        if (valid.is_err()) {
            return dp::Result<RsaPrivateKey>::err(valid.error());
        }
        return dp::Result<RsaPrivateKey>::ok(std::move(key));
    }

} // namespace keylock::crypto::sign_rsa::pkcs1
