#pragma once

#include "keylock/crypto/sign_common/dp_echo_compat.hpp"
#include "keylock/crypto/sign_ecdsa_p256/p256_field.hpp"

namespace keylock::crypto::sign_ecdsa_p256::der {

    using Bytes = dp::Vector<dp::u8>;

    namespace detail {

        inline Bytes trim_leading_zeros(const Bytes &in) {
            dp::usize i = 0;
            while (i + 1 < in.size() && in[i] == 0x00) {
                ++i;
            }
            Bytes out;
            out.reserve(in.size() - i);
            for (; i < in.size(); ++i) {
                out.push_back(in[i]);
            }
            return out;
        }

        inline dp::Result<Bytes> canonical_integer_bytes(const Bytes &x) {
            Bytes v = trim_leading_zeros(x);
            if (v.empty()) {
                v.push_back(0x00);
            }
            if ((v[0] & 0x80U) != 0) {
                Bytes prefixed;
                prefixed.reserve(v.size() + 1);
                prefixed.push_back(0x00);
                for (dp::u8 b : v) {
                    prefixed.push_back(b);
                }
                return dp::Result<Bytes>::ok(std::move(prefixed));
            }
            return dp::Result<Bytes>::ok(std::move(v));
        }

        inline bool read_len(const Bytes &in, dp::usize &offset, dp::usize &len_out) {
            if (offset >= in.size()) {
                return false;
            }
            const dp::u8 first = in[offset++];
            if ((first & 0x80U) == 0) {
                len_out = first;
                return true;
            }

            const dp::u8 nbytes = static_cast<dp::u8>(first & 0x7fU);
            if (nbytes == 0 || nbytes > 2) {
                return false;
            }
            if (offset + nbytes > in.size()) {
                return false;
            }

            len_out = 0;
            for (dp::u8 i = 0; i < nbytes; ++i) {
                len_out = (len_out << 8) | in[offset++];
            }
            return true;
        }

        inline Bytes write_len(dp::usize len) {
            if (len < 0x80) {
                return Bytes{static_cast<dp::u8>(len)};
            }
            if (len <= 0xff) {
                return Bytes{0x81, static_cast<dp::u8>(len)};
            }
            return Bytes{0x82, static_cast<dp::u8>((len >> 8) & 0xff), static_cast<dp::u8>(len & 0xff)};
        }

        inline dp::Result<Bytes> parse_der_integer_to_fixed32(const Bytes &in, dp::usize &offset) {
            if (offset >= in.size() || in[offset++] != 0x02) {
                return dp::Result<Bytes>::err(dp::Error::invalid_argument("DER INTEGER tag missing"));
            }
            dp::usize len = 0;
            if (!read_len(in, offset, len) || len == 0 || offset + len > in.size()) {
                return dp::Result<Bytes>::err(dp::Error::invalid_argument("invalid DER INTEGER length"));
            }

            Bytes v;
            v.reserve(len);
            for (dp::usize i = 0; i < len; ++i) {
                v.push_back(in[offset++]);
            }

            if ((v[0] & 0x80U) != 0) {
                return dp::Result<Bytes>::err(dp::Error::invalid_argument("negative DER INTEGER not allowed"));
            }
            if (v.size() > 1 && v[0] == 0x00 && (v[1] & 0x80U) == 0) {
                return dp::Result<Bytes>::err(dp::Error::invalid_argument("non-canonical DER INTEGER"));
            }

            if (v.size() > 33) {
                return dp::Result<Bytes>::err(dp::Error::invalid_argument("DER INTEGER too large for P-256"));
            }
            if (v.size() == 33) {
                if (v[0] != 0x00) {
                    return dp::Result<Bytes>::err(dp::Error::invalid_argument("DER INTEGER overflow"));
                }
                Bytes shrunk;
                shrunk.reserve(32);
                for (dp::usize i = 1; i < v.size(); ++i) {
                    shrunk.push_back(v[i]);
                }
                v = std::move(shrunk);
            }

            return dp::Result<Bytes>::ok(field::to_fixed32(v));
        }

    } // namespace detail

    inline dp::Result<Bytes> encode_raw_to_der(const Bytes &raw_signature_64) {
        if (raw_signature_64.size() != 64) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("raw ECDSA signature must be 64 bytes"));
        }

        Bytes r(raw_signature_64.begin(), raw_signature_64.begin() + 32);
        Bytes s(raw_signature_64.begin() + 32, raw_signature_64.end());

        auto r_int = detail::canonical_integer_bytes(r);
        auto s_int = detail::canonical_integer_bytes(s);
        if (r_int.is_err()) {
            return dp::Result<Bytes>::err(r_int.error());
        }
        if (s_int.is_err()) {
            return dp::Result<Bytes>::err(s_int.error());
        }

        Bytes r_tlv{0x02};
        auto r_len = detail::write_len(r_int.value().size());
        r_tlv.insert(r_tlv.end(), r_len.begin(), r_len.end());
        r_tlv.insert(r_tlv.end(), r_int.value().begin(), r_int.value().end());

        Bytes s_tlv{0x02};
        auto s_len = detail::write_len(s_int.value().size());
        s_tlv.insert(s_tlv.end(), s_len.begin(), s_len.end());
        s_tlv.insert(s_tlv.end(), s_int.value().begin(), s_int.value().end());

        Bytes seq_body = r_tlv;
        seq_body.insert(seq_body.end(), s_tlv.begin(), s_tlv.end());

        Bytes out{0x30};
        auto seq_len = detail::write_len(seq_body.size());
        out.insert(out.end(), seq_len.begin(), seq_len.end());
        out.insert(out.end(), seq_body.begin(), seq_body.end());
        return dp::Result<Bytes>::ok(std::move(out));
    }

    inline dp::Result<Bytes> decode_der_to_raw(const Bytes &der_signature) {
        dp::usize offset = 0;
        if (offset >= der_signature.size() || der_signature[offset++] != 0x30) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("DER SEQUENCE tag missing"));
        }

        dp::usize seq_len = 0;
        if (!detail::read_len(der_signature, offset, seq_len) || offset + seq_len != der_signature.size()) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("invalid DER SEQUENCE length"));
        }

        auto r = detail::parse_der_integer_to_fixed32(der_signature, offset);
        if (r.is_err()) {
            return dp::Result<Bytes>::err(r.error());
        }
        auto s = detail::parse_der_integer_to_fixed32(der_signature, offset);
        if (s.is_err()) {
            return dp::Result<Bytes>::err(s.error());
        }

        if (offset != der_signature.size()) {
            return dp::Result<Bytes>::err(dp::Error::invalid_argument("trailing bytes after DER signature"));
        }

        Bytes raw;
        raw.reserve(64);
        raw.insert(raw.end(), r.value().begin(), r.value().end());
        raw.insert(raw.end(), s.value().begin(), s.value().end());
        return dp::Result<Bytes>::ok(std::move(raw));
    }

} // namespace keylock::crypto::sign_ecdsa_p256::der
