#include <doctest/doctest.h>

#include <cstdint>
#include <string>
#include <vector>

#include <keylock/keylock.hpp>

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

TEST_SUITE("OpenSSL Interop Vectors") {
    TEST_CASE("Ed25519 verify OpenSSL vector") {
        const auto msg = from_hex("6d73672d696e7465726f70");
        const auto spki =
            from_hex("302a300506032b6570032100bad0bf8ad854797ee48d2a718f46c30592b9e8edd7723d4de93ddd7abfaf334c");
        const auto sig = from_hex("1ef6d05b8bd66a4de647ca17cfb5228a8b5cb10dacd2feb443f56210f5478b1a75b25b2dd232b1a2f8f8"
                                  "fb2ef78943470e188525d538e6de7c9b255237c60f0a");

        auto pub = keylock::keylock::decode_ed25519_public_key_spki_der(spki);
        REQUIRE(pub.success);

        keylock::keylock ctx(keylock::Algorithm::Ed25519);
        auto ok = ctx.verify(msg, sig, pub.data);
        REQUIRE(ok.success);
    }

    TEST_CASE("ECDSA P-256 verify OpenSSL vector") {
        const auto msg = from_hex("6d73672d696e7465726f70");
        const auto spki =
            from_hex("3059301306072a8648ce3d020106082a8648ce3d0301070342000455e2cdcb5a1f2be0243fe674b44bdfd91cbf0bc5842"
                     "dbec5bb6ad5df5cc083d74863a1fcb01ee7bae983e4026d7036bc16feb6b31c2a6cb32a3dc99b53aebc2b");
        const auto sig_der = from_hex("3044022043e6f802f41d4494400ea2c0112903ae6d3a960c669fc77608dcb2ee1d0461770220008f"
                                      "cfb5b1bccf66a8830841d3a44e86b1f7190598defc97c40804e2aed27b0f");

        auto pub = keylock::keylock::decode_ecdsa_p256_public_key_spki_der(spki);
        REQUIRE(pub.success);
        auto sig_raw = keylock::keylock::decode_ecdsa_p256_signature_der(sig_der);
        REQUIRE(sig_raw.success);

        keylock::keylock ctx(keylock::Algorithm::ECDSA_P256_SHA256);
        auto ok = ctx.verify(msg, sig_raw.data, pub.data);
        REQUIRE(ok.success);
    }

    TEST_CASE("RSA PKCS1v1.5 verify OpenSSL vector") {
        const auto msg = from_hex("6d73672d696e7465726f70");
        const auto rsa_pub_der =
            from_hex("30818902818100be01495689a21ca5e8271e6119b3f9b5ecc0b9db132da1efeaf1f7c8269b2efa503686ff821a0e5b0fa"
                     "18e68d04dec340bf1b0ebe92fe3dad5090877a7c95bac1c750a426a3fea07c56a1ad4863e7bf8f84ea8cf6af4bba55e93"
                     "9eae09b7eb27eb69053cf8cb589f6ca1cda4d5639866bd8d5061ad2dea8386c58f384828d3b10203010001");
        const auto sig =
            from_hex("49104a38412064640859b736b123695f8e8b65664f9a7477ac4051bd0b025e4c12a86f22039210e044571a409c52ac7fb"
                     "8c7402d5c3619550511556b32dc7f5b3f037baf38756f730b49e8434d1f69db0d313f742ad6d63c117b195ab9c3052e56"
                     "1a7e44948af07c048e24e313260564f4432aa9bee1ddfee5edfa3ca0094aa2");

        auto pub_blob = keylock::keylock::decode_rsa_public_key_pkcs1_der(rsa_pub_der);
        REQUIRE(pub_blob.success);

        keylock::keylock ctx(keylock::Algorithm::RSA_PKCS1v15_SHA256);
        auto ok = ctx.verify(msg, sig, pub_blob.data);
        REQUIRE(ok.success);
    }

    TEST_CASE("RSA PSS verify OpenSSL vector") {
        const auto msg = from_hex("6d73672d696e7465726f70");
        const auto rsa_pub_der =
            from_hex("30818902818100be01495689a21ca5e8271e6119b3f9b5ecc0b9db132da1efeaf1f7c8269b2efa503686ff821a0e5b0fa"
                     "18e68d04dec340bf1b0ebe92fe3dad5090877a7c95bac1c750a426a3fea07c56a1ad4863e7bf8f84ea8cf6af4bba55e93"
                     "9eae09b7eb27eb69053cf8cb589f6ca1cda4d5639866bd8d5061ad2dea8386c58f384828d3b10203010001");
        const auto sig =
            from_hex("aedbcc9e8de1a7b6954de0e964d1d57cb41a6ec3384958483f80343f1aa68bbd0ec114407cb4d3a535fa8b7945bab8ba4"
                     "e9b779464143c6632649d697ff8b57c31f529cdea8537ac11b76bc66ce6c9c9e5e1224afeaf59a34a3aadc562b0da0161"
                     "613fe2d813ad91c845bedd454711fbe397d9c115436b441c1e808d9a13aae9");

        auto pub_blob = keylock::keylock::decode_rsa_public_key_pkcs1_der(rsa_pub_der);
        REQUIRE(pub_blob.success);

        keylock::keylock ctx(keylock::Algorithm::RSA_PSS_SHA256);
        auto ok = ctx.verify(msg, sig, pub_blob.data);
        REQUIRE(ok.success);
    }
}
