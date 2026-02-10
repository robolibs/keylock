#include <doctest/doctest.h>

#include <keylock/keylock.hpp>

namespace {
    void append_u32_be(std::vector<uint8_t> &out, uint32_t v) {
        out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
        out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
        out.push_back(static_cast<uint8_t>(v & 0xff));
    }

    std::vector<uint8_t> make_rsa_public_blob(const std::vector<uint8_t> &n, const std::vector<uint8_t> &e) {
        std::vector<uint8_t> out;
        append_u32_be(out, static_cast<uint32_t>(n.size()));
        out.insert(out.end(), n.begin(), n.end());
        append_u32_be(out, static_cast<uint32_t>(e.size()));
        out.insert(out.end(), e.begin(), e.end());
        return out;
    }

    std::vector<uint8_t> make_rsa_private_blob(const std::vector<uint8_t> &n, const std::vector<uint8_t> &e,
                                               const std::vector<uint8_t> &d) {
        auto out = make_rsa_public_blob(n, e);
        append_u32_be(out, static_cast<uint32_t>(d.size()));
        out.insert(out.end(), d.begin(), d.end());
        return out;
    }
} // namespace

TEST_SUITE("Signature Negative Cases") {
    TEST_CASE("RSA rejects malformed private key blob") {
        keylock::keylock ctx(keylock::Algorithm::RSA_PKCS1v15_SHA256);
        std::vector<uint8_t> msg{'b', 'a', 'd'};

        std::vector<uint8_t> malformed = {0x00, 0x00, 0x00, 0x04, 0xaa}; // truncated modulus
        auto sig = ctx.sign(msg, malformed);
        CHECK_FALSE(sig.success);
    }

    TEST_CASE("RSA rejects malformed public key blob") {
        keylock::keylock ctx(keylock::Algorithm::RSA_PSS_SHA256);
        std::vector<uint8_t> msg{'b', 'a', 'd'};
        std::vector<uint8_t> sig(128, 0x00);

        std::vector<uint8_t> malformed = {0x00, 0x00, 0x00, 0x00}; // empty modulus
        auto ok = ctx.verify(msg, sig, malformed);
        CHECK_FALSE(ok.success);
    }

    TEST_CASE("RSA rejects weak or invalid exponents") {
        keylock::keylock ctx(keylock::Algorithm::RSA_PKCS1v15_SHA256);
        std::vector<uint8_t> msg{'b', 'a', 'd'};

        std::vector<uint8_t> n(128, 0xff);
        n[0] = 0x80;
        n.back() = 0x03;

        auto priv_e1 = make_rsa_private_blob(n, std::vector<uint8_t>{0x01}, std::vector<uint8_t>{0x01});
        auto sig1 = ctx.sign(msg, priv_e1);
        CHECK_FALSE(sig1.success);

        auto priv_e2 = make_rsa_private_blob(n, std::vector<uint8_t>{0x02}, std::vector<uint8_t>{0x01});
        auto sig2 = ctx.sign(msg, priv_e2);
        CHECK_FALSE(sig2.success);

        auto pub_e1 = make_rsa_public_blob(n, std::vector<uint8_t>{0x01});
        std::vector<uint8_t> fake_sig(128, 0x00);
        auto ok1 = ctx.verify(msg, fake_sig, pub_e1);
        CHECK_FALSE(ok1.success);

        auto pub_e2 = make_rsa_public_blob(n, std::vector<uint8_t>{0x02});
        auto ok2 = ctx.verify(msg, fake_sig, pub_e2);
        CHECK_FALSE(ok2.success);
    }

    TEST_CASE("ECDSA rejects invalid key sizes") {
        keylock::keylock ctx(keylock::Algorithm::ECDSA_P256_SHA256);
        std::vector<uint8_t> msg{'k'};

        std::vector<uint8_t> short_priv(31, 0x01);
        auto sig = ctx.sign(msg, short_priv);
        CHECK_FALSE(sig.success);

        std::vector<uint8_t> sig_blob(64, 0x00);
        std::vector<uint8_t> short_pub(63, 0x02);
        auto ok = ctx.verify(msg, sig_blob, short_pub);
        CHECK_FALSE(ok.success);
    }
}
