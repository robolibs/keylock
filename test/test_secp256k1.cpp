#include <doctest/doctest.h>

#include <string>
#include <vector>

#include "keylock/crypto/secp256k1/secp256k1.hpp"

namespace {
    uint8_t hex_nibble(char c) {
        if (c >= '0' && c <= '9') {
            return static_cast<uint8_t>(c - '0');
        }
        if (c >= 'a' && c <= 'f') {
            return static_cast<uint8_t>(10 + (c - 'a'));
        }
        if (c >= 'A' && c <= 'F') {
            return static_cast<uint8_t>(10 + (c - 'A'));
        }
        return 0;
    }

    std::vector<uint8_t> from_hex(const std::string &hex) {
        std::vector<uint8_t> out;
        out.reserve(hex.size() / 2);
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            out.push_back(static_cast<uint8_t>((hex_nibble(hex[i]) << 4) | hex_nibble(hex[i + 1])));
        }
        return out;
    }
} // namespace

TEST_SUITE("secp256k1") {
    TEST_CASE("recover public key from compact signature") {
        const auto digest = from_hex("0000000000000000000000000000000000000000000000000000000000000001");
        const auto sig = from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                                  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81799");
        const auto expected_pubkey = from_hex("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                                              "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");

        auto recovered = keylock::crypto::secp256k1::recover_public_key(digest, sig, 0);
        REQUIRE(recovered.success);
        CHECK(recovered.public_key_uncompressed == expected_pubkey);
    }

    TEST_CASE("reject invalid recovery id") {
        const auto digest = from_hex("0000000000000000000000000000000000000000000000000000000000000001");
        const auto sig = from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                                  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81799");

        auto recovered = keylock::crypto::secp256k1::recover_public_key(digest, sig, 2);
        CHECK_FALSE(recovered.success);
        CHECK(recovered.error_message == "Invalid recovery id: expected 0 or 1");
    }

    TEST_CASE("reject malformed compact signature length") {
        const auto digest = from_hex("0000000000000000000000000000000000000000000000000000000000000001");
        auto sig = from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81799");
        sig.pop_back();

        auto recovered = keylock::crypto::secp256k1::recover_public_key(digest, sig, 0);
        CHECK_FALSE(recovered.success);
        CHECK(recovered.error_message == "Invalid signature length: expected 64 bytes");
    }

    TEST_CASE("verify compact signature with compressed and uncompressed keys") {
        const auto digest = from_hex("0000000000000000000000000000000000000000000000000000000000000001");
        const auto sig = from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                                  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81799");
        const auto pub_uncompressed = from_hex("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                                               "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
        const auto pub_compressed = from_hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

        auto ok_uncompressed = keylock::crypto::secp256k1::verify_compact(digest, sig, pub_uncompressed);
        REQUIRE(ok_uncompressed.success);

        auto ok_compressed = keylock::crypto::secp256k1::verify_compact(digest, sig, pub_compressed);
        REQUIRE(ok_compressed.success);
    }

    TEST_CASE("verify fails for wrong public key") {
        const auto digest = from_hex("0000000000000000000000000000000000000000000000000000000000000001");
        const auto sig = from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                                  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81799");
        const auto wrong_pub_compressed =
            from_hex("0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

        auto ok = keylock::crypto::secp256k1::verify_compact(digest, sig, wrong_pub_compressed);
        CHECK_FALSE(ok.success);
        CHECK(ok.error_message == "Signature verification failed");
    }

    TEST_CASE("low-s helper") {
        const auto low_s = from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81799");
        const auto high_s = from_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");

        CHECK(keylock::crypto::secp256k1::is_low_s(low_s));
        CHECK_FALSE(keylock::crypto::secp256k1::is_low_s(high_s));
    }

    TEST_CASE("v normalization") {
        auto v0 = keylock::crypto::secp256k1::normalize_recovery_id(0);
        auto v1 = keylock::crypto::secp256k1::normalize_recovery_id(28);
        auto bad = keylock::crypto::secp256k1::normalize_recovery_id(29);

        REQUIRE(v0.success);
        CHECK(v0.recovery_id == 0);
        REQUIRE(v1.success);
        CHECK(v1.recovery_id == 1);
        CHECK_FALSE(bad.success);
    }
}
