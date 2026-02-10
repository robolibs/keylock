#include <doctest/doctest.h>

#include <string>
#include <vector>

#include "keylock/hash/context.hpp"

namespace {
    std::string bytes_to_hex(const std::vector<uint8_t> &data) {
        static const char hex_chars[] = "0123456789abcdef";
        std::string out;
        out.reserve(data.size() * 2);
        for (uint8_t b : data) {
            out.push_back(hex_chars[(b >> 4) & 0x0f]);
            out.push_back(hex_chars[b & 0x0f]);
        }
        return out;
    }
} // namespace

TEST_SUITE("Keccak-256") {
    TEST_CASE("keccak256 empty message") {
        auto r = keylock::hash::keccak256({});
        REQUIRE(r.success);
        CHECK(bytes_to_hex(r.data) == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    }

    TEST_CASE("keccak256 abc") {
        const std::vector<uint8_t> msg = {'a', 'b', 'c'};
        auto r = keylock::hash::keccak256(msg);
        REQUIRE(r.success);
        CHECK(bytes_to_hex(r.data) == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
    }
}
