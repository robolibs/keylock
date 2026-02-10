#include <doctest/doctest.h>

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

TEST_SUITE("secp256k1 Context Integration") {
    TEST_CASE("Context verify for compact secp256k1") {
        keylock::keylock ctx(keylock::Algorithm::ECDSA_SECP256K1_COMPACT);
        const auto digest = from_hex("0000000000000000000000000000000000000000000000000000000000000001");
        const auto sig = from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                                  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81799");
        const auto pub_compressed = from_hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

        auto ok = ctx.verify(digest, sig, pub_compressed);
        REQUIRE(ok.success);
    }

    TEST_CASE("Context key generation and sign verify for secp256k1") {
        keylock::keylock ctx(keylock::Algorithm::ECDSA_SECP256K1_COMPACT);
        auto keypair = ctx.generate_keypair();
        REQUIRE(keypair.public_key.size() == 65);
        REQUIRE(keypair.private_key.size() == 32);

        const std::vector<uint8_t> message = {'k', 'e', 'y', 'l', 'o', 'c', 'k'};
        auto sig = ctx.sign(message, keypair.private_key);
        REQUIRE(sig.success);
        REQUIRE(sig.data.size() == 65);

        auto ok = ctx.verify(message, sig.data, keypair.public_key);
        CHECK(ok.success);

        auto bad_key = keypair;
        bad_key.public_key[10] ^= 0x01;
        auto bad = ctx.verify(message, sig.data, bad_key.public_key);
        CHECK_FALSE(bad.success);
    }

    TEST_CASE("Context static secp256k1 helpers") {
        const auto digest = from_hex("0000000000000000000000000000000000000000000000000000000000000001");
        const auto sig = from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                                  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81799");

        auto recovered = keylock::keylock::recover_secp256k1_public_key(digest, sig, 0);
        REQUIRE(recovered.success);

        auto addr = keylock::keylock::ethereum_address_from_uncompressed_pubkey(recovered.public_key_uncompressed);
        REQUIRE(addr.success);
        CHECK(addr.data.size() == 20);

        auto low_s = keylock::keylock::is_secp256k1_low_s(
            from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81799"));
        CHECK(low_s);

        auto v = keylock::keylock::normalize_ethereum_recovery_id(28);
        REQUIRE(v.success);
        CHECK(v.recovery_id == 1);
    }

    TEST_CASE("Context supports KECCAK256 hash mode") {
        keylock::keylock ctx(keylock::Algorithm::XChaCha20_Poly1305, keylock::HashAlgorithm::KECCAK256);
        const std::vector<uint8_t> msg = {'a', 'b', 'c'};
        auto h = ctx.hash(msg);
        REQUIRE(h.success);
        CHECK(h.data.size() == 32);

        auto r = keylock::keylock::keccak256(msg);
        REQUIRE(r.success);
        CHECK(h.data == r.data);
    }
}
