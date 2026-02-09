#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#if __has_include(<datapod/datapod.hpp>)
#include <datapod/datapod.hpp>
#else
namespace dp {
    using u8 = std::uint8_t;
    using u32 = std::uint32_t;
    using u64 = std::uint64_t;
    using i64 = std::int64_t;
    using usize = std::size_t;
    using String = std::string;

    template <typename T> using Vector = std::vector<T>;

    struct Error {
        std::uint32_t code = 0;
        String message;

        static Error invalid_argument(const char *msg) { return Error{1, String(msg)}; }
    };

    template <typename T, typename E = Error> struct Result {
        bool ok_state = false;
        T value_state{};
        E error_state{};

        static Result ok(T value) {
            Result r;
            r.ok_state = true;
            r.value_state = std::move(value);
            return r;
        }

        static Result err(E error) {
            Result r;
            r.ok_state = false;
            r.error_state = std::move(error);
            return r;
        }

        bool is_ok() const { return ok_state; }
        bool is_err() const { return !ok_state; }

        T &value() { return value_state; }
        const T &value() const { return value_state; }

        E &error() { return error_state; }
        const E &error() const { return error_state; }
    };
} // namespace dp
#endif

#if __has_include(<echo/echo.hpp>)
#include <echo/echo.hpp>
#else
namespace echo {
    template <typename... Args> inline void trace(Args &&...) {}
    template <typename... Args> inline void debug(Args &&...) {}
    template <typename... Args> inline void info(Args &&...) {}
    template <typename... Args> inline void warn(Args &&...) {}
    template <typename... Args> inline void error(Args &&...) {}
} // namespace echo
#endif
