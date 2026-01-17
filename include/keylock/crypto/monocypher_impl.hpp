#pragma once

// Monocypher - Complete header-only implementation
// Adapted from Monocypher (BSD-2-Clause OR CC0-1.0)
// Original: Copyright (c) 2017-2020, Loup Vaillant
//
// This header provides X25519 key exchange and Ed25519 signatures.
// All functions are inlined for header-only usage.

#include <cstddef>
#include <cstdint>
#include <cstring>

#ifndef MONOCYPHER_CPP_NAMESPACE
#define MONOCYPHER_CPP_NAMESPACE keylock_monocypher_internal
#endif

namespace MONOCYPHER_CPP_NAMESPACE {

    /////////////////
    /// Utilities ///
    /////////////////
    using u8 = uint8_t;
    using u32 = uint32_t;
    using u64 = uint64_t;
    using i8 = int8_t;
    using i16 = int16_t;
    using i32 = int32_t;
    using i64 = int64_t;

#define MC_FOR(i, start, end) for (size_t i = (start); i < (end); i++)
#define MC_FOR_T(type, i, start, end) for (type i = (start); i < (end); i++)
#define MC_COPY(dst, src, size) MC_FOR(_i_, 0, size)(dst)[_i_] = (src)[_i_]
#define MC_ZERO(buf, size) MC_FOR(_i_, 0, size)(buf)[_i_] = 0
#define MC_WIPE_CTX(ctx) crypto_wipe(ctx, sizeof(*(ctx)))
#define MC_WIPE_BUFFER(buffer) crypto_wipe(buffer, sizeof(buffer))
#define MC_MIN(a, b) ((a) <= (b) ? (a) : (b))
#define MC_MAX(a, b) ((a) >= (b) ? (a) : (b))

    inline void crypto_wipe(void *secret, size_t size) {
        volatile u8 *v_secret = (u8 *)secret;
        MC_ZERO(v_secret, size);
    }

    inline u32 load24_le(const u8 s[3]) { return ((u32)s[0] << 0) | ((u32)s[1] << 8) | ((u32)s[2] << 16); }

    inline u32 load32_le(const u8 s[4]) {
        return ((u32)s[0] << 0) | ((u32)s[1] << 8) | ((u32)s[2] << 16) | ((u32)s[3] << 24);
    }

    inline u64 load64_le(const u8 s[8]) { return load32_le(s) | ((u64)load32_le(s + 4) << 32); }

    inline void store32_le(u8 out[4], u32 in) {
        out[0] = in & 0xff;
        out[1] = (in >> 8) & 0xff;
        out[2] = (in >> 16) & 0xff;
        out[3] = (in >> 24) & 0xff;
    }

    inline void store64_le(u8 out[8], u64 in) {
        store32_le(out, (u32)in);
        store32_le(out + 4, in >> 32);
    }

    inline void load32_le_buf(u32 *dst, const u8 *src, size_t size) {
        MC_FOR(i, 0, size) { dst[i] = load32_le(src + i * 4); }
    }

    inline void load64_le_buf(u64 *dst, const u8 *src, size_t size) {
        MC_FOR(i, 0, size) { dst[i] = load64_le(src + i * 8); }
    }

    inline void store32_le_buf(u8 *dst, const u32 *src, size_t size) {
        MC_FOR(i, 0, size) { store32_le(dst + i * 4, src[i]); }
    }

    inline void store64_le_buf(u8 *dst, const u64 *src, size_t size) {
        MC_FOR(i, 0, size) { store64_le(dst + i * 8, src[i]); }
    }

    inline u64 rotr64(u64 x, u64 n) { return (x >> n) ^ (x << (64 - n)); }
    inline u32 rotl32(u32 x, u32 n) { return (x << n) ^ (x >> (32 - n)); }

    inline int neq0(u64 diff) {
        u64 half = (diff >> 32) | ((u32)diff);
        return (1 & ((half - 1) >> 32)) - 1;
    }

    inline u64 x16(const u8 a[16], const u8 b[16]) {
        return (load64_le(a + 0) ^ load64_le(b + 0)) | (load64_le(a + 8) ^ load64_le(b + 8));
    }

    inline u64 x32(const u8 a[32], const u8 b[32]) { return x16(a, b) | x16(a + 16, b + 16); }

    inline u64 x64(const u8 a[64], const u8 b[64]) { return x32(a, b) | x32(a + 32, b + 32); }

    inline int crypto_verify16(const u8 a[16], const u8 b[16]) { return neq0(x16(a, b)); }
    inline int crypto_verify32(const u8 a[32], const u8 b[32]) { return neq0(x32(a, b)); }
    inline int crypto_verify64(const u8 a[64], const u8 b[64]) { return neq0(x64(a, b)); }

    ////////////////////////////////////
    /// Arithmetic modulo 2^255 - 19 ///
    ////////////////////////////////////

    // Field element type
    using fe = i32[10];

    // Field constants
    inline constexpr i32 fe_one_data[10] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    inline constexpr i32 sqrtm1_data[10] = {
        -32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482,
    };
    inline constexpr i32 d_data[10] = {
        -10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116,
    };
    inline constexpr i32 D2_data[10] = {
        -21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199,
    };

    inline void fe_0(fe h) { MC_ZERO(h, 10); }
    inline void fe_1(fe h) {
        h[0] = 1;
        MC_ZERO(h + 1, 9);
    }

    inline void fe_copy(fe h, const fe f) { MC_FOR(i, 0, 10) h[i] = f[i]; }
    inline void fe_neg(fe h, const fe f) { MC_FOR(i, 0, 10) h[i] = -f[i]; }
    inline void fe_add(fe h, const fe f, const fe g) { MC_FOR(i, 0, 10) h[i] = f[i] + g[i]; }
    inline void fe_sub(fe h, const fe f, const fe g) { MC_FOR(i, 0, 10) h[i] = f[i] - g[i]; }

    inline void fe_cswap(fe f, fe g, int b) {
        i32 mask = -b;
        MC_FOR(i, 0, 10) {
            i32 x = (f[i] ^ g[i]) & mask;
            f[i] = f[i] ^ x;
            g[i] = g[i] ^ x;
        }
    }

    inline void fe_ccopy(fe f, const fe g, int b) {
        i32 mask = -b;
        MC_FOR(i, 0, 10) {
            i32 x = (f[i] ^ g[i]) & mask;
            f[i] = f[i] ^ x;
        }
    }

// Carry propagation macro
#define FE_CARRY                                                                                                       \
    i64 c;                                                                                                             \
    c = (t0 + ((i64)1 << 25)) >> 26;                                                                                   \
    t0 -= c * ((i64)1 << 26);                                                                                          \
    t1 += c;                                                                                                           \
    c = (t4 + ((i64)1 << 25)) >> 26;                                                                                   \
    t4 -= c * ((i64)1 << 26);                                                                                          \
    t5 += c;                                                                                                           \
    c = (t1 + ((i64)1 << 24)) >> 25;                                                                                   \
    t1 -= c * ((i64)1 << 25);                                                                                          \
    t2 += c;                                                                                                           \
    c = (t5 + ((i64)1 << 24)) >> 25;                                                                                   \
    t5 -= c * ((i64)1 << 25);                                                                                          \
    t6 += c;                                                                                                           \
    c = (t2 + ((i64)1 << 25)) >> 26;                                                                                   \
    t2 -= c * ((i64)1 << 26);                                                                                          \
    t3 += c;                                                                                                           \
    c = (t6 + ((i64)1 << 25)) >> 26;                                                                                   \
    t6 -= c * ((i64)1 << 26);                                                                                          \
    t7 += c;                                                                                                           \
    c = (t3 + ((i64)1 << 24)) >> 25;                                                                                   \
    t3 -= c * ((i64)1 << 25);                                                                                          \
    t4 += c;                                                                                                           \
    c = (t7 + ((i64)1 << 24)) >> 25;                                                                                   \
    t7 -= c * ((i64)1 << 25);                                                                                          \
    t8 += c;                                                                                                           \
    c = (t4 + ((i64)1 << 25)) >> 26;                                                                                   \
    t4 -= c * ((i64)1 << 26);                                                                                          \
    t5 += c;                                                                                                           \
    c = (t8 + ((i64)1 << 25)) >> 26;                                                                                   \
    t8 -= c * ((i64)1 << 26);                                                                                          \
    t9 += c;                                                                                                           \
    c = (t9 + ((i64)1 << 24)) >> 25;                                                                                   \
    t9 -= c * ((i64)1 << 25);                                                                                          \
    t0 += c * 19;                                                                                                      \
    c = (t0 + ((i64)1 << 25)) >> 26;                                                                                   \
    t0 -= c * ((i64)1 << 26);                                                                                          \
    t1 += c;                                                                                                           \
    h[0] = (i32)t0;                                                                                                    \
    h[1] = (i32)t1;                                                                                                    \
    h[2] = (i32)t2;                                                                                                    \
    h[3] = (i32)t3;                                                                                                    \
    h[4] = (i32)t4;                                                                                                    \
    h[5] = (i32)t5;                                                                                                    \
    h[6] = (i32)t6;                                                                                                    \
    h[7] = (i32)t7;                                                                                                    \
    h[8] = (i32)t8;                                                                                                    \
    h[9] = (i32)t9

    inline void fe_frombytes_mask(fe h, const u8 s[32], unsigned nb_mask) {
        u32 mask = 0xffffff >> nb_mask;
        i64 t0 = load32_le(s);
        i64 t1 = load24_le(s + 4) << 6;
        i64 t2 = load24_le(s + 7) << 5;
        i64 t3 = load24_le(s + 10) << 3;
        i64 t4 = load24_le(s + 13) << 2;
        i64 t5 = load32_le(s + 16);
        i64 t6 = load24_le(s + 20) << 7;
        i64 t7 = load24_le(s + 23) << 5;
        i64 t8 = load24_le(s + 26) << 4;
        i64 t9 = (load24_le(s + 29) & mask) << 2;
        FE_CARRY;
    }

    inline void fe_frombytes(fe h, const u8 s[32]) { fe_frombytes_mask(h, s, 1); }

    inline void fe_tobytes(u8 s[32], const fe h) {
        i32 t[10];
        MC_COPY(t, h, 10);
        i32 q = (19 * t[9] + (((i32)1) << 24)) >> 25;
        MC_FOR(i, 0, 5) {
            q += t[2 * i];
            q >>= 26;
            q += t[2 * i + 1];
            q >>= 25;
        }
        q *= 19;
        MC_FOR(i, 0, 5) {
            t[i * 2] += q;
            q = t[i * 2] >> 26;
            t[i * 2] -= q * ((i32)1 << 26);
            t[i * 2 + 1] += q;
            q = t[i * 2 + 1] >> 25;
            t[i * 2 + 1] -= q * ((i32)1 << 25);
        }
        store32_le(s + 0, ((u32)t[0] >> 0) | ((u32)t[1] << 26));
        store32_le(s + 4, ((u32)t[1] >> 6) | ((u32)t[2] << 19));
        store32_le(s + 8, ((u32)t[2] >> 13) | ((u32)t[3] << 13));
        store32_le(s + 12, ((u32)t[3] >> 19) | ((u32)t[4] << 6));
        store32_le(s + 16, ((u32)t[5] >> 0) | ((u32)t[6] << 25));
        store32_le(s + 20, ((u32)t[6] >> 7) | ((u32)t[7] << 19));
        store32_le(s + 24, ((u32)t[7] >> 13) | ((u32)t[8] << 12));
        store32_le(s + 28, ((u32)t[8] >> 20) | ((u32)t[9] << 6));
        MC_WIPE_BUFFER(t);
    }

    inline void fe_mul_small(fe h, const fe f, i32 g) {
        i64 t0 = f[0] * (i64)g;
        i64 t1 = f[1] * (i64)g;
        i64 t2 = f[2] * (i64)g;
        i64 t3 = f[3] * (i64)g;
        i64 t4 = f[4] * (i64)g;
        i64 t5 = f[5] * (i64)g;
        i64 t6 = f[6] * (i64)g;
        i64 t7 = f[7] * (i64)g;
        i64 t8 = f[8] * (i64)g;
        i64 t9 = f[9] * (i64)g;
        FE_CARRY;
    }

    inline void fe_mul(fe h, const fe f, const fe g) {
        i32 f0 = f[0];
        i32 f1 = f[1];
        i32 f2 = f[2];
        i32 f3 = f[3];
        i32 f4 = f[4];
        i32 f5 = f[5];
        i32 f6 = f[6];
        i32 f7 = f[7];
        i32 f8 = f[8];
        i32 f9 = f[9];
        i32 g0 = g[0];
        i32 g1 = g[1];
        i32 g2 = g[2];
        i32 g3 = g[3];
        i32 g4 = g[4];
        i32 g5 = g[5];
        i32 g6 = g[6];
        i32 g7 = g[7];
        i32 g8 = g[8];
        i32 g9 = g[9];
        i32 F1 = f1 * 2;
        i32 F3 = f3 * 2;
        i32 F5 = f5 * 2;
        i32 F7 = f7 * 2;
        i32 F9 = f9 * 2;
        i32 G1 = g1 * 19;
        i32 G2 = g2 * 19;
        i32 G3 = g3 * 19;
        i32 G4 = g4 * 19;
        i32 G5 = g5 * 19;
        i32 G6 = g6 * 19;
        i32 G7 = g7 * 19;
        i32 G8 = g8 * 19;
        i32 G9 = g9 * 19;

        i64 t0 = f0 * (i64)g0 + F1 * (i64)G9 + f2 * (i64)G8 + F3 * (i64)G7 + f4 * (i64)G6 + F5 * (i64)G5 +
                 f6 * (i64)G4 + F7 * (i64)G3 + f8 * (i64)G2 + F9 * (i64)G1;
        i64 t1 = f0 * (i64)g1 + f1 * (i64)g0 + f2 * (i64)G9 + f3 * (i64)G8 + f4 * (i64)G7 + f5 * (i64)G6 +
                 f6 * (i64)G5 + f7 * (i64)G4 + f8 * (i64)G3 + f9 * (i64)G2;
        i64 t2 = f0 * (i64)g2 + F1 * (i64)g1 + f2 * (i64)g0 + F3 * (i64)G9 + f4 * (i64)G8 + F5 * (i64)G7 +
                 f6 * (i64)G6 + F7 * (i64)G5 + f8 * (i64)G4 + F9 * (i64)G3;
        i64 t3 = f0 * (i64)g3 + f1 * (i64)g2 + f2 * (i64)g1 + f3 * (i64)g0 + f4 * (i64)G9 + f5 * (i64)G8 +
                 f6 * (i64)G7 + f7 * (i64)G6 + f8 * (i64)G5 + f9 * (i64)G4;
        i64 t4 = f0 * (i64)g4 + F1 * (i64)g3 + f2 * (i64)g2 + F3 * (i64)g1 + f4 * (i64)g0 + F5 * (i64)G9 +
                 f6 * (i64)G8 + F7 * (i64)G7 + f8 * (i64)G6 + F9 * (i64)G5;
        i64 t5 = f0 * (i64)g5 + f1 * (i64)g4 + f2 * (i64)g3 + f3 * (i64)g2 + f4 * (i64)g1 + f5 * (i64)g0 +
                 f6 * (i64)G9 + f7 * (i64)G8 + f8 * (i64)G7 + f9 * (i64)G6;
        i64 t6 = f0 * (i64)g6 + F1 * (i64)g5 + f2 * (i64)g4 + F3 * (i64)g3 + f4 * (i64)g2 + F5 * (i64)g1 +
                 f6 * (i64)g0 + F7 * (i64)G9 + f8 * (i64)G8 + F9 * (i64)G7;
        i64 t7 = f0 * (i64)g7 + f1 * (i64)g6 + f2 * (i64)g5 + f3 * (i64)g4 + f4 * (i64)g3 + f5 * (i64)g2 +
                 f6 * (i64)g1 + f7 * (i64)g0 + f8 * (i64)G9 + f9 * (i64)G8;
        i64 t8 = f0 * (i64)g8 + F1 * (i64)g7 + f2 * (i64)g6 + F3 * (i64)g5 + f4 * (i64)g4 + F5 * (i64)g3 +
                 f6 * (i64)g2 + F7 * (i64)g1 + f8 * (i64)g0 + F9 * (i64)G9;
        i64 t9 = f0 * (i64)g9 + f1 * (i64)g8 + f2 * (i64)g7 + f3 * (i64)g6 + f4 * (i64)g5 + f5 * (i64)g4 +
                 f6 * (i64)g3 + f7 * (i64)g2 + f8 * (i64)g1 + f9 * (i64)g0;
        FE_CARRY;
    }

    inline void fe_sq(fe h, const fe f) {
        i32 f0 = f[0];
        i32 f1 = f[1];
        i32 f2 = f[2];
        i32 f3 = f[3];
        i32 f4 = f[4];
        i32 f5 = f[5];
        i32 f6 = f[6];
        i32 f7 = f[7];
        i32 f8 = f[8];
        i32 f9 = f[9];
        i32 f0_2 = f0 * 2;
        i32 f1_2 = f1 * 2;
        i32 f2_2 = f2 * 2;
        i32 f3_2 = f3 * 2;
        i32 f4_2 = f4 * 2;
        i32 f5_2 = f5 * 2;
        i32 f6_2 = f6 * 2;
        i32 f7_2 = f7 * 2;
        i32 f5_38 = f5 * 38;
        i32 f6_19 = f6 * 19;
        i32 f7_38 = f7 * 38;
        i32 f8_19 = f8 * 19;
        i32 f9_38 = f9 * 38;

        i64 t0 = f0 * (i64)f0 + f1_2 * (i64)f9_38 + f2_2 * (i64)f8_19 + f3_2 * (i64)f7_38 + f4_2 * (i64)f6_19 +
                 f5 * (i64)f5_38;
        i64 t1 = f0_2 * (i64)f1 + f2 * (i64)f9_38 + f3_2 * (i64)f8_19 + f4 * (i64)f7_38 + f5_2 * (i64)f6_19;
        i64 t2 = f0_2 * (i64)f2 + f1_2 * (i64)f1 + f3_2 * (i64)f9_38 + f4_2 * (i64)f8_19 + f5_2 * (i64)f7_38 +
                 f6 * (i64)f6_19;
        i64 t3 = f0_2 * (i64)f3 + f1_2 * (i64)f2 + f4 * (i64)f9_38 + f5_2 * (i64)f8_19 + f6 * (i64)f7_38;
        i64 t4 =
            f0_2 * (i64)f4 + f1_2 * (i64)f3_2 + f2 * (i64)f2 + f5_2 * (i64)f9_38 + f6_2 * (i64)f8_19 + f7 * (i64)f7_38;
        i64 t5 = f0_2 * (i64)f5 + f1_2 * (i64)f4 + f2_2 * (i64)f3 + f6 * (i64)f9_38 + f7_2 * (i64)f8_19;
        i64 t6 =
            f0_2 * (i64)f6 + f1_2 * (i64)f5_2 + f2_2 * (i64)f4 + f3_2 * (i64)f3 + f7_2 * (i64)f9_38 + f8 * (i64)f8_19;
        i64 t7 = f0_2 * (i64)f7 + f1_2 * (i64)f6 + f2_2 * (i64)f5 + f3_2 * (i64)f4 + f8 * (i64)f9_38;
        i64 t8 = f0_2 * (i64)f8 + f1_2 * (i64)f7_2 + f2_2 * (i64)f6 + f3_2 * (i64)f5_2 + f4 * (i64)f4 + f9 * (i64)f9_38;
        i64 t9 = f0_2 * (i64)f9 + f1_2 * (i64)f8 + f2_2 * (i64)f7 + f3_2 * (i64)f6 + f4 * (i64)f5_2;
        FE_CARRY;
    }

    inline int fe_isodd(const fe f) {
        u8 s[32];
        fe_tobytes(s, f);
        u8 isodd = s[0] & 1;
        MC_WIPE_BUFFER(s);
        return isodd;
    }

    inline int fe_isequal(const fe f, const fe g) {
        u8 fs[32];
        u8 gs[32];
        fe_tobytes(fs, f);
        fe_tobytes(gs, g);
        int isdifferent = crypto_verify32(fs, gs);
        MC_WIPE_BUFFER(fs);
        MC_WIPE_BUFFER(gs);
        return 1 + isdifferent;
    }

    inline int invsqrt(fe isr, const fe x) {
        fe t0, t1, t2;

        fe_sq(t0, x);
        fe_sq(t1, t0);
        fe_sq(t1, t1);
        fe_mul(t1, x, t1);
        fe_mul(t0, t0, t1);
        fe_sq(t0, t0);
        fe_mul(t0, t1, t0);
        fe_sq(t1, t0);
        MC_FOR(i, 1, 5) { fe_sq(t1, t1); }
        fe_mul(t0, t1, t0);
        fe_sq(t1, t0);
        MC_FOR(i, 1, 10) { fe_sq(t1, t1); }
        fe_mul(t1, t1, t0);
        fe_sq(t2, t1);
        MC_FOR(i, 1, 20) { fe_sq(t2, t2); }
        fe_mul(t1, t2, t1);
        fe_sq(t1, t1);
        MC_FOR(i, 1, 10) { fe_sq(t1, t1); }
        fe_mul(t0, t1, t0);
        fe_sq(t1, t0);
        MC_FOR(i, 1, 50) { fe_sq(t1, t1); }
        fe_mul(t1, t1, t0);
        fe_sq(t2, t1);
        MC_FOR(i, 1, 100) { fe_sq(t2, t2); }
        fe_mul(t1, t2, t1);
        fe_sq(t1, t1);
        MC_FOR(i, 1, 50) { fe_sq(t1, t1); }
        fe_mul(t0, t1, t0);
        fe_sq(t0, t0);
        MC_FOR(i, 1, 2) { fe_sq(t0, t0); }
        fe_mul(t0, t0, x);

        i32 *quartic = t1;
        fe_sq(quartic, t0);
        fe_mul(quartic, quartic, x);

        i32 *check = t2;
        fe_0(check);
        int z0 = fe_isequal(x, check);
        fe_1(check);
        int p1 = fe_isequal(quartic, check);
        fe_neg(check, check);
        int m1 = fe_isequal(quartic, check);

        fe sqrtm1_copy;
        MC_COPY(sqrtm1_copy, sqrtm1_data, 10);
        fe_neg(check, sqrtm1_copy);
        int ms = fe_isequal(quartic, check);

        fe_mul(isr, t0, sqrtm1_copy);
        fe_ccopy(isr, t0, 1 - (m1 | ms));

        MC_WIPE_BUFFER(t0);
        MC_WIPE_BUFFER(t1);
        MC_WIPE_BUFFER(t2);
        return p1 | m1 | z0;
    }

    inline void fe_invert(fe out, const fe x) {
        fe tmp;
        fe_sq(tmp, x);
        invsqrt(tmp, tmp);
        fe_sq(tmp, tmp);
        fe_mul(out, tmp, x);
        MC_WIPE_BUFFER(tmp);
    }

    ///////////////
    /// X-25519 ///
    ///////////////

    inline void crypto_eddsa_trim_scalar(u8 out[32], const u8 in[32]) {
        MC_COPY(out, in, 32);
        out[0] &= 248;
        out[31] &= 127;
        out[31] |= 64;
    }

    inline int scalar_bit(const u8 s[32], int i) {
        if (i < 0) {
            return 0;
        }
        return (s[i >> 3] >> (i & 7)) & 1;
    }

    inline void scalarmult(u8 q[32], const u8 scalar[32], const u8 p[32], int nb_bits) {
        fe x1;
        fe_frombytes(x1, p);

        fe x2, z2, x3, z3, t0, t1;
        fe_1(x2);
        fe_0(z2);
        fe_copy(x3, x1);
        fe_1(z3);
        int swap = 0;
        for (int pos = nb_bits - 1; pos >= 0; --pos) {
            int b = scalar_bit(scalar, pos);
            swap ^= b;
            fe_cswap(x2, x3, swap);
            fe_cswap(z2, z3, swap);
            swap = b;

            fe_sub(t0, x3, z3);
            fe_sub(t1, x2, z2);
            fe_add(x2, x2, z2);
            fe_add(z2, x3, z3);
            fe_mul(z3, t0, x2);
            fe_mul(z2, z2, t1);
            fe_sq(t0, t1);
            fe_sq(t1, x2);
            fe_add(x3, z3, z2);
            fe_sub(z2, z3, z2);
            fe_mul(x2, t1, t0);
            fe_sub(t1, t1, t0);
            fe_sq(z2, z2);
            fe_mul_small(z3, t1, 121666);
            fe_sq(x3, x3);
            fe_add(t0, t0, z3);
            fe_mul(z3, x1, z2);
            fe_mul(z2, t1, t0);
        }
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);

        fe_invert(z2, z2);
        fe_mul(x2, x2, z2);
        fe_tobytes(q, x2);

        MC_WIPE_BUFFER(x1);
        MC_WIPE_BUFFER(x2);
        MC_WIPE_BUFFER(z2);
        MC_WIPE_BUFFER(t0);
        MC_WIPE_BUFFER(x3);
        MC_WIPE_BUFFER(z3);
        MC_WIPE_BUFFER(t1);
    }

    inline void crypto_x25519(u8 raw_shared_secret[32], const u8 your_secret_key[32], const u8 their_public_key[32]) {
        u8 e[32];
        crypto_eddsa_trim_scalar(e, your_secret_key);
        scalarmult(raw_shared_secret, e, their_public_key, 255);
        MC_WIPE_BUFFER(e);
    }

    inline void crypto_x25519_public_key(u8 public_key[32], const u8 secret_key[32]) {
        static const u8 base_point[32] = {9};
        crypto_x25519(public_key, secret_key, base_point);
    }

    ///////////////////////////
    /// Arithmetic modulo L ///
    ///////////////////////////
    inline constexpr u32 L[8] = {
        0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de, 0x00000000, 0x00000000, 0x00000000, 0x10000000,
    };

    inline void multiply(u32 p[16], const u32 a[8], const u32 b[8]) {
        MC_FOR(i, 0, 8) {
            u64 carry = 0;
            MC_FOR(j, 0, 8) {
                carry += p[i + j] + (u64)a[i] * b[j];
                p[i + j] = (u32)carry;
                carry >>= 32;
            }
            p[i + 8] = (u32)carry;
        }
    }

    inline int is_above_l(const u32 x[8]) {
        u64 carry = 1;
        MC_FOR(i, 0, 8) {
            carry += (u64)x[i] + (~L[i] & 0xffffffff);
            carry >>= 32;
        }
        return (int)carry;
    }

    inline void remove_l(u32 r[8], const u32 x[8]) {
        u64 carry = (u64)is_above_l(x);
        u32 mask = ~(u32)carry + 1;
        MC_FOR(i, 0, 8) {
            carry += (u64)x[i] + (~L[i] & mask);
            r[i] = (u32)carry;
            carry >>= 32;
        }
    }

    inline void mod_l(u8 reduced[32], const u32 x[16]) {
        static constexpr u32 r[9] = {
            0x0a2c131b, 0xed9ce5a3, 0x086329a7, 0x2106215d, 0xffffffeb, 0xffffffff, 0xffffffff, 0xffffffff, 0xf,
        };
        u32 xr[25] = {0};
        MC_FOR(i, 0, 9) {
            u64 carry = 0;
            MC_FOR(j, 0, 16) {
                carry += xr[i + j] + (u64)r[i] * x[j];
                xr[i + j] = (u32)carry;
                carry >>= 32;
            }
            xr[i + 16] = (u32)carry;
        }
        MC_ZERO(xr, 8);
        MC_FOR(i, 0, 8) {
            u64 carry = 0;
            for (size_t j = 0; j < 8 - i; j++) {
                carry += xr[i + j] + (u64)xr[i + 16] * L[j];
                xr[i + j] = (u32)carry;
                carry >>= 32;
            }
        }
        u64 carry = 1;
        MC_FOR(i, 0, 8) {
            carry += (u64)x[i] + (~xr[i] & 0xffffffff);
            xr[i] = (u32)carry;
            carry >>= 32;
        }
        remove_l(xr, xr);
        store32_le_buf(reduced, xr, 8);
        MC_WIPE_BUFFER(xr);
    }

    inline void crypto_eddsa_reduce(u8 reduced[32], const u8 expanded[64]) {
        u32 x[16];
        load32_le_buf(x, expanded, 16);
        mod_l(reduced, x);
        MC_WIPE_BUFFER(x);
    }

    inline void crypto_eddsa_mul_add(u8 r[32], const u8 a[32], const u8 b[32], const u8 c[32]) {
        u32 A[8];
        load32_le_buf(A, a, 8);
        u32 B[8];
        load32_le_buf(B, b, 8);
        u32 p[16];
        load32_le_buf(p, c, 8);
        MC_ZERO(p + 8, 8);
        multiply(p, A, B);
        mod_l(r, p);
        MC_WIPE_BUFFER(p);
        MC_WIPE_BUFFER(A);
        MC_WIPE_BUFFER(B);
    }

    ///////////////
    /// Ed25519 ///
    ///////////////

    struct ge {
        fe X;
        fe Y;
        fe Z;
        fe T;
    };
    struct ge_cached {
        fe Yp;
        fe Ym;
        fe Z;
        fe T2;
    };
    struct ge_precomp {
        fe Yp;
        fe Ym;
        fe T2;
    };

    inline void ge_zero(ge *p) {
        fe_0(p->X);
        fe_1(p->Y);
        fe_1(p->Z);
        fe_0(p->T);
    }

    inline void ge_tobytes(u8 s[32], const ge *h) {
        fe recip, x, y;
        fe_invert(recip, h->Z);
        fe_mul(x, h->X, recip);
        fe_mul(y, h->Y, recip);
        fe_tobytes(s, y);
        s[31] ^= fe_isodd(x) << 7;
        MC_WIPE_BUFFER(recip);
        MC_WIPE_BUFFER(x);
        MC_WIPE_BUFFER(y);
    }

    inline int ge_frombytes_neg_vartime(ge *h, const u8 s[32]) {
        fe d_copy;
        MC_COPY(d_copy, d_data, 10);

        fe_frombytes(h->Y, s);
        fe_1(h->Z);
        fe_sq(h->T, h->Y);
        fe_mul(h->X, h->T, d_copy);
        fe_sub(h->T, h->T, h->Z);
        fe_add(h->X, h->X, h->Z);
        fe_mul(h->X, h->T, h->X);
        int is_square = invsqrt(h->X, h->X);
        if (!is_square) {
            return -1;
        }
        fe_mul(h->X, h->T, h->X);
        if (fe_isodd(h->X) == (s[31] >> 7)) {
            fe_neg(h->X, h->X);
        }
        fe_mul(h->T, h->X, h->Y);
        return 0;
    }

    inline void ge_cache(ge_cached *c, const ge *p) {
        fe D2_copy;
        MC_COPY(D2_copy, D2_data, 10);

        fe_add(c->Yp, p->Y, p->X);
        fe_sub(c->Ym, p->Y, p->X);
        fe_copy(c->Z, p->Z);
        fe_mul(c->T2, p->T, D2_copy);
    }

    inline void ge_add(ge *s, const ge *p, const ge_cached *q) {
        fe a, b;
        fe_add(a, p->Y, p->X);
        fe_sub(b, p->Y, p->X);
        fe_mul(a, a, q->Yp);
        fe_mul(b, b, q->Ym);
        fe_add(s->Y, a, b);
        fe_sub(s->X, a, b);

        fe_add(s->Z, p->Z, p->Z);
        fe_mul(s->Z, s->Z, q->Z);
        fe_mul(s->T, p->T, q->T2);
        fe_add(a, s->Z, s->T);
        fe_sub(b, s->Z, s->T);

        fe_mul(s->T, s->X, s->Y);
        fe_mul(s->X, s->X, b);
        fe_mul(s->Y, s->Y, a);
        fe_mul(s->Z, a, b);
    }

    inline void ge_sub(ge *s, const ge *p, const ge_cached *q) {
        ge_cached neg;
        fe_copy(neg.Ym, q->Yp);
        fe_copy(neg.Yp, q->Ym);
        fe_copy(neg.Z, q->Z);
        fe_neg(neg.T2, q->T2);
        ge_add(s, p, &neg);
    }

    inline void ge_madd(ge *s, const ge *p, const ge_precomp *q, fe a, fe b) {
        fe_add(a, p->Y, p->X);
        fe_sub(b, p->Y, p->X);
        fe_mul(a, a, q->Yp);
        fe_mul(b, b, q->Ym);
        fe_add(s->Y, a, b);
        fe_sub(s->X, a, b);

        fe_add(s->Z, p->Z, p->Z);
        fe_mul(s->T, p->T, q->T2);
        fe_add(a, s->Z, s->T);
        fe_sub(b, s->Z, s->T);

        fe_mul(s->T, s->X, s->Y);
        fe_mul(s->X, s->X, b);
        fe_mul(s->Y, s->Y, a);
        fe_mul(s->Z, a, b);
    }

    inline void ge_double(ge *s, const ge *p, ge *q) {
        fe_sq(q->X, p->X);
        fe_sq(q->Y, p->Y);
        fe_sq(q->Z, p->Z);
        fe_mul_small(q->Z, q->Z, 2);
        fe_add(q->T, p->X, p->Y);
        fe_sq(s->T, q->T);
        fe_add(q->T, q->Y, q->X);
        fe_sub(q->Y, q->Y, q->X);
        fe_sub(q->X, s->T, q->T);
        fe_sub(q->Z, q->Z, q->Y);

        fe_mul(s->X, q->X, q->Z);
        fe_mul(s->Y, q->T, q->Y);
        fe_mul(s->Z, q->Y, q->Z);
        fe_mul(s->T, q->X, q->T);
    }

    // Base point precomputed table (5-bit signed window)
    inline const ge_precomp b_window[8] = {
        {
            {
                25967493,
                -14356035,
                29566456,
                3660896,
                -12694345,
                4014787,
                27544626,
                -11754271,
                -6079156,
                2047605,
            },
            {
                -12545711,
                934262,
                -2722910,
                3049990,
                -727428,
                9406986,
                12720692,
                5043384,
                19500929,
                -15469378,
            },
            {
                -8738181,
                4489570,
                9688441,
                -14785194,
                10184609,
                -12363380,
                29287919,
                11864899,
                -24514362,
                -4438546,
            },
        },
        {
            {
                15636291,
                -9688557,
                24204773,
                -7912398,
                616977,
                -16685262,
                27787600,
                -14772189,
                28944400,
                -1550024,
            },
            {
                16568933,
                4717097,
                -11556148,
                -1102322,
                15682896,
                -11807043,
                16354577,
                -11775962,
                7689662,
                11199574,
            },
            {
                30464156,
                -5976125,
                -11779434,
                -15670865,
                23220365,
                15915852,
                7512774,
                10017326,
                -17749093,
                -9920357,
            },
        },
        {
            {
                10861363,
                11473154,
                27284546,
                1981175,
                -30064349,
                12577861,
                32867885,
                14515107,
                -15438304,
                10819380,
            },
            {
                4708026,
                6336745,
                20377586,
                9066809,
                -11272109,
                6594696,
                -25653668,
                12483688,
                -12668491,
                5581306,
            },
            {
                19563160,
                16186464,
                -29386857,
                4097519,
                10237984,
                -4348115,
                28542350,
                13850243,
                -23678021,
                -15815942,
            },
        },
        {
            {
                5153746,
                9909285,
                1723747,
                -2777874,
                30523605,
                5516873,
                19480852,
                5230134,
                -23952439,
                -15175766,
            },
            {
                -30269007,
                -3463509,
                7665486,
                10083793,
                28475525,
                1649722,
                20654025,
                16520125,
                30598449,
                7715701,
            },
            {
                28881845,
                14381568,
                9657904,
                3680757,
                -20181635,
                7843316,
                -31400660,
                1370708,
                29794553,
                -1409300,
            },
        },
        {
            {
                -22518993,
                -6692182,
                14201702,
                -8745502,
                -23510406,
                8844726,
                18474211,
                -1361450,
                -13062696,
                13821877,
            },
            {
                -6455177,
                -7839871,
                3374702,
                -4740862,
                -27098617,
                -10571707,
                31655028,
                -7212327,
                18853322,
                -14220951,
            },
            {
                4566830,
                -12963868,
                -28974889,
                -12240689,
                -7602672,
                -2830569,
                -8514358,
                -10431137,
                2207753,
                -3209784,
            },
        },
        {
            {
                -25154831,
                -4185821,
                29681144,
                7868801,
                -6854661,
                -9423865,
                -12437364,
                -663000,
                -31111463,
                -16132436,
            },
            {
                25576264,
                -2703214,
                7349804,
                -11814844,
                16472782,
                9300885,
                3844789,
                15725684,
                171356,
                6466918,
            },
            {
                23103977,
                13316479,
                9739013,
                -16149481,
                817875,
                -15038942,
                8965339,
                -14088058,
                -30714912,
                16193877,
            },
        },
        {
            {
                -33521811,
                3180713,
                -2394130,
                14003687,
                -16903474,
                -16270840,
                17238398,
                4729455,
                -18074513,
                9256800,
            },
            {
                -25182317,
                -4174131,
                32336398,
                5036987,
                -21236817,
                11360617,
                22616405,
                9761698,
                -19827198,
                630305,
            },
            {
                -13720693,
                2639453,
                -24237460,
                -7406481,
                9494427,
                -5774029,
                -6554551,
                -15960994,
                -2449256,
                -14291300,
            },
        },
        {
            {
                -3151181,
                -5046075,
                9282714,
                6866145,
                -31907062,
                -863023,
                -18940575,
                15033784,
                25105118,
                -7894876,
            },
            {
                -24326370,
                15950226,
                -31801215,
                -14592823,
                -11662737,
                -5090925,
                1573892,
                -2625887,
                2198790,
                -15804619,
            },
            {
                -3099351,
                10324967,
                -2241613,
                7453183,
                -5446979,
                -2735503,
                -13812022,
                -16236442,
                -32461234,
                -12290683,
            },
        },
    };

    // Precomputed comb tables for efficient scalar multiplication
    inline const ge_precomp b_comb_low[8] = {
        {
            {
                -6816601,
                -2324159,
                -22559413,
                124364,
                18015490,
                8373481,
                19993724,
                1979872,
                -18549925,
                9085059,
            },
            {
                10306321,
                403248,
                14839893,
                9633706,
                8463310,
                -8354981,
                -14305673,
                14668847,
                26301366,
                2818560,
            },
            {
                -22701500,
                -3210264,
                -13831292,
                -2927732,
                -16326337,
                -14016360,
                12940910,
                177905,
                12165515,
                -2397893,
            },
        },
        {
            {
                -12282262,
                -7022066,
                9920413,
                -3064358,
                -32147467,
                2927790,
                22392436,
                -14852487,
                2719975,
                16402117,
            },
            {
                -7236961,
                -4729776,
                2685954,
                -6525055,
                -24242706,
                -15940211,
                -6238521,
                14082855,
                10047669,
                12228189,
            },
            {
                -30495588,
                -12893761,
                -11161261,
                3539405,
                -11502464,
                16491580,
                -27286798,
                -15030530,
                -7272871,
                -15934455,
            },
        },
        {
            {
                17650926,
                582297,
                -860412,
                -187745,
                -12072900,
                -10683391,
                -20352381,
                15557840,
                -31072141,
                -5019061,
            },
            {
                -6283632,
                -2259834,
                -4674247,
                -4598977,
                -4089240,
                12435688,
                -31278303,
                1060251,
                6256175,
                10480726,
            },
            {
                -13871026,
                2026300,
                -21928428,
                -2741605,
                -2406664,
                -8034988,
                7355518,
                15733500,
                -23379862,
                7489131,
            },
        },
        {
            {
                6883359,
                695140,
                23196907,
                9644202,
                -33430614,
                11354760,
                -20134606,
                6388313,
                -8263585,
                -8491918,
            },
            {
                -7716174,
                -13605463,
                -13646110,
                14757414,
                -19430591,
                -14967316,
                10359532,
                -11059670,
                -21935259,
                12082603,
            },
            {
                -11253345,
                -15943946,
                10046784,
                5414629,
                24840771,
                8086951,
                -6694742,
                9868723,
                15842692,
                -16224787,
            },
        },
        {
            {
                9639399,
                11810955,
                -24007778,
                -9320054,
                3912937,
                -9856959,
                996125,
                -8727907,
                -8919186,
                -14097242,
            },
            {
                7248867,
                14468564,
                25228636,
                -8795035,
                14346339,
                8224790,
                6388427,
                -7181107,
                6468218,
                -8720783,
            },
            {
                15513115,
                15439095,
                7342322,
                -10157390,
                18005294,
                -7265713,
                2186239,
                4884640,
                10826567,
                7135781,
            },
        },
        {
            {
                -14204238,
                5297536,
                -5862318,
                -6004934,
                28095835,
                4236101,
                -14203318,
                1958636,
                -16816875,
                3837147,
            },
            {
                -5511166,
                -13176782,
                -29588215,
                12339465,
                15325758,
                -15945770,
                -8813185,
                11075932,
                -19608050,
                -3776283,
            },
            {
                11728032,
                9603156,
                -4637821,
                -5304487,
                -7827751,
                2724948,
                31236191,
                -16760175,
                -7268616,
                14799772,
            },
        },
        {
            {
                -28842672,
                4840636,
                -12047946,
                -9101456,
                -1445464,
                381905,
                -30977094,
                -16523389,
                1290540,
                12798615,
            },
            {
                27246947,
                -10320914,
                14792098,
                -14518944,
                5302070,
                -8746152,
                -3403974,
                -4149637,
                -27061213,
                10749585,
            },
            {
                25572375,
                -6270368,
                -15353037,
                16037944,
                1146292,
                32198,
                23487090,
                9585613,
                24714571,
                -1418265,
            },
        },
        {
            {
                19844825,
                282124,
                -17583147,
                11004019,
                -32004269,
                -2716035,
                6105106,
                -1711007,
                -21010044,
                14338445,
            },
            {
                8027505,
                8191102,
                -18504907,
                -12335737,
                25173494,
                -5923905,
                15446145,
                7483684,
                -30440441,
                10009108,
            },
            {
                -14134701,
                -4174411,
                10246585,
                -14677495,
                33553567,
                -14012935,
                23366126,
                15080531,
                -7969992,
                7663473,
            },
        },
    };

    inline const ge_precomp b_comb_high[8] = {
        {
            {
                33055887,
                -4431773,
                -521787,
                6654165,
                951411,
                -6266464,
                -5158124,
                6995613,
                -5397442,
                -6985227,
            },
            {
                4014062,
                6967095,
                -11977872,
                3960002,
                8001989,
                5130302,
                -2154812,
                -1899602,
                -31954493,
                -16173976,
            },
            {
                16271757,
                -9212948,
                23792794,
                731486,
                -25808309,
                -3546396,
                6964344,
                -4767590,
                10976593,
                10050757,
            },
        },
        {
            {
                2533007,
                -4288439,
                -24467768,
                -12387405,
                -13450051,
                14542280,
                12876301,
                13893535,
                15067764,
                8594792,
            },
            {
                20073501,
                -11623621,
                3165391,
                -13119866,
                13188608,
                -11540496,
                -10751437,
                -13482671,
                29588810,
                2197295,
            },
            {
                -1084082,
                11831693,
                6031797,
                14062724,
                14748428,
                -8159962,
                -20721760,
                11742548,
                31368706,
                13161200,
            },
        },
        {
            {
                2050412,
                -6457589,
                15321215,
                5273360,
                25484180,
                124590,
                -18187548,
                -7097255,
                -6691621,
                -14604792,
            },
            {
                9938196,
                2162889,
                -6158074,
                -1711248,
                4278932,
                -2598531,
                -22865792,
                -7168500,
                -24323168,
                11746309,
            },
            {
                -22691768,
                -14268164,
                5965485,
                9383325,
                20443693,
                5854192,
                28250679,
                -1381811,
                -10837134,
                13717818,
            },
        },
        {
            {
                -8495530,
                16382250,
                9548884,
                -4971523,
                -4491811,
                -3902147,
                6182256,
                -12832479,
                26628081,
                10395408,
            },
            {
                27329048,
                -15853735,
                7715764,
                8717446,
                -9215518,
                -14633480,
                28982250,
                -5668414,
                4227628,
                242148,
            },
            {
                -13279943,
                -7986904,
                -7100016,
                8764468,
                -27276630,
                3096719,
                29678419,
                -9141299,
                3906709,
                11265498,
            },
        },
        {
            {
                11918285,
                15686328,
                -17757323,
                -11217300,
                -27548967,
                4853165,
                -27168827,
                6807359,
                6871949,
                -1075745,
            },
            {
                -29002610,
                13984323,
                -27111812,
                -2713442,
                28107359,
                -13266203,
                6155126,
                15104658,
                3538727,
                -7513788,
            },
            {
                14103158,
                11233913,
                -33165269,
                9279850,
                31014152,
                4335090,
                -1827936,
                4590951,
                13960841,
                12787712,
            },
        },
        {
            {
                1469134,
                -16738009,
                33411928,
                13942824,
                8092558,
                -8778224,
                -11165065,
                1437842,
                22521552,
                -2792954,
            },
            {
                31352705,
                -4807352,
                -25327300,
                3962447,
                12541566,
                -9399651,
                -27425693,
                7964818,
                -23829869,
                5541287,
            },
            {
                -25732021,
                -6864887,
                23848984,
                3039395,
                -9147354,
                6022816,
                -27421653,
                10590137,
                25309915,
                -1584678,
            },
        },
        {
            {
                -22951376,
                5048948,
                31139401,
                -190316,
                -19542447,
                -626310,
                -17486305,
                -16511925,
                -18851313,
                -12985140,
            },
            {
                -9684890,
                14681754,
                30487568,
                7717771,
                -10829709,
                9630497,
                30290549,
                -10531496,
                -27798994,
                -13812825,
            },
            {
                5827835,
                16097107,
                -24501327,
                12094619,
                7413972,
                11447087,
                28057551,
                -1793987,
                -14056981,
                4359312,
            },
        },
        {
            {
                26323183,
                2342588,
                -21887793,
                -1623758,
                -6062284,
                2107090,
                -28724907,
                9036464,
                -19618351,
                -13055189,
            },
            {
                -29697200,
                14829398,
                -4596333,
                14220089,
                -30022969,
                2955645,
                12094100,
                -13693652,
                -5941445,
                7047569,
            },
            {
                -3201977,
                14413268,
                -12058324,
                -16417589,
                -9035655,
                -7224648,
                9258160,
                1399236,
                30397584,
                -5684634,
            },
        },
    };

    inline void ge_msub(ge *s, const ge *p, const ge_precomp *q, fe a, fe b) {
        ge_precomp neg;
        fe_copy(neg.Ym, q->Yp);
        fe_copy(neg.Yp, q->Ym);
        fe_neg(neg.T2, q->T2);
        ge_madd(s, p, &neg, a, b);
    }

    inline void lookup_add(ge *p, ge_precomp *tmp_c, fe tmp_a, fe tmp_b, const ge_precomp comb[8], const u8 scalar[32],
                           int i) {
        u8 teeth = (u8)((scalar_bit(scalar, i)) + (scalar_bit(scalar, i + 32) << 1) +
                        (scalar_bit(scalar, i + 64) << 2) + (scalar_bit(scalar, i + 96) << 3));
        u8 high = teeth >> 3;
        u8 index = (teeth ^ (high - 1)) & 7;
        MC_FOR(j, 0, 8) {
            i32 select = 1 & (((j ^ index) - 1) >> 8);
            fe_ccopy(tmp_c->Yp, comb[j].Yp, select);
            fe_ccopy(tmp_c->Ym, comb[j].Ym, select);
            fe_ccopy(tmp_c->T2, comb[j].T2, select);
        }
        fe_neg(tmp_a, tmp_c->T2);
        fe_cswap(tmp_c->T2, tmp_a, high ^ 1);
        fe_cswap(tmp_c->Yp, tmp_c->Ym, high ^ 1);
        ge_madd(p, p, tmp_c, tmp_a, tmp_b);
    }

    inline void ge_scalarmult_base(ge *p, const u8 scalar[32]) {
        // 1 / 2 modulo L
        static const u8 half_mod_L[32] = {
            247, 233, 122, 46, 141, 49, 9, 44, 107, 206, 123, 81, 239, 124, 111, 10,
            0,   0,   0,   0,  0,   0,  0, 0,  0,   0,   0,   0,  0,   0,   0,   8,
        };
        // (2^256 - 1) / 2 modulo L
        static const u8 half_ones[32] = {
            142, 74,  204, 70,  186, 24,  118, 107, 184, 231, 190, 57,  250, 173, 119, 99,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 7,
        };

        u8 s_scalar[32];
        crypto_eddsa_mul_add(s_scalar, scalar, half_mod_L, half_ones);

        fe tmp_a, tmp_b;
        ge_precomp tmp_c;
        ge tmp_d;
        fe_1(tmp_c.Yp);
        fe_1(tmp_c.Ym);
        fe_0(tmp_c.T2);

        ge_zero(p);
        lookup_add(p, &tmp_c, tmp_a, tmp_b, b_comb_low, s_scalar, 31);
        lookup_add(p, &tmp_c, tmp_a, tmp_b, b_comb_high, s_scalar, 31 + 128);
        for (int i = 30; i >= 0; i--) {
            ge_double(p, p, &tmp_d);
            lookup_add(p, &tmp_c, tmp_a, tmp_b, b_comb_low, s_scalar, i);
            lookup_add(p, &tmp_c, tmp_a, tmp_b, b_comb_high, s_scalar, i + 128);
        }

        MC_WIPE_BUFFER(tmp_a);
        MC_WIPE_BUFFER(tmp_b);
        MC_WIPE_BUFFER(s_scalar);
    }

    inline void crypto_eddsa_scalarbase(u8 point[32], const u8 scalar[32]) {
        ge P;
        ge_scalarmult_base(&P, scalar);
        ge_tobytes(point, &P);
    }

    // Sliding window context for verification
    struct slide_ctx {
        i16 next_index;
        i8 next_digit;
        u8 next_check;
    };

    inline void slide_init(slide_ctx *ctx, const u8 scalar[32]) {
        int i = 252;
        while (i > 0 && scalar_bit(scalar, i) == 0) {
            i--;
        }
        ctx->next_check = (u8)(i + 1);
        ctx->next_index = -1;
        ctx->next_digit = -1;
    }

    inline int slide_step(slide_ctx *ctx, int width, int i, const u8 scalar[32]) {
        if (i == ctx->next_check) {
            if (scalar_bit(scalar, i) == scalar_bit(scalar, i - 1)) {
                ctx->next_check--;
            } else {
                int w = MC_MIN(width, i + 1);
                int v = -(scalar_bit(scalar, i) << (w - 1));
                for (int j = 0; j < w - 1; j++) {
                    v += scalar_bit(scalar, i - (w - 1) + j) << j;
                }
                v += scalar_bit(scalar, i - w);
                int lsb = v & (~v + 1);
                int s = (((lsb & 0xAA) != 0) << 0) | (((lsb & 0xCC) != 0) << 1) | (((lsb & 0xF0) != 0) << 2);
                ctx->next_index = (i16)(i - (w - 1) + s);
                ctx->next_digit = (i8)(v >> s);
                ctx->next_check -= (u8)w;
            }
        }
        return i == ctx->next_index ? ctx->next_digit : 0;
    }

#define P_W_WIDTH 3
#define B_W_WIDTH 5
#define P_W_SIZE (1 << (P_W_WIDTH - 2))

    // Check Ed25519 signature equation: [s]B = R + [h]A
    inline int crypto_eddsa_check_equation(const u8 signature[64], const u8 public_key[32], const u8 h[32]) {
        ge minus_A;
        ge minus_R;
        const u8 *s = signature + 32;

        // Check that A and R are on the curve
        // Check that 0 <= S < L
        {
            u32 s32[8];
            load32_le_buf(s32, s, 8);
            if (ge_frombytes_neg_vartime(&minus_A, public_key) || ge_frombytes_neg_vartime(&minus_R, signature) ||
                is_above_l(s32)) {
                return -1;
            }
        }

        // Build lookup table for minus_A
        ge_cached lutA[P_W_SIZE];
        {
            ge minus_A2, tmp;
            ge_double(&minus_A2, &minus_A, &tmp);
            ge_cache(&lutA[0], &minus_A);
            MC_FOR(i, 1, P_W_SIZE) {
                ge_add(&tmp, &minus_A2, &lutA[i - 1]);
                ge_cache(&lutA[i], &tmp);
            }
        }

        // Compute sum = [s]B - [h]A using double-and-add with sliding windows
        slide_ctx h_slide;
        slide_init(&h_slide, h);
        slide_ctx s_slide;
        slide_init(&s_slide, s);
        int i = MC_MAX(h_slide.next_check, s_slide.next_check);
        ge *sum = &minus_A;
        ge_zero(sum);
        while (i >= 0) {
            ge tmp;
            ge_double(sum, sum, &tmp);
            int h_digit = slide_step(&h_slide, P_W_WIDTH, i, h);
            int s_digit = slide_step(&s_slide, B_W_WIDTH, i, s);
            if (h_digit > 0) {
                ge_add(sum, sum, &lutA[h_digit / 2]);
            }
            if (h_digit < 0) {
                ge_sub(sum, sum, &lutA[-h_digit / 2]);
            }
            fe t1, t2;
            if (s_digit > 0) {
                ge_madd(sum, sum, b_window + s_digit / 2, t1, t2);
            }
            if (s_digit < 0) {
                ge_msub(sum, sum, b_window + -s_digit / 2, t1, t2);
            }
            i--;
        }

        // Compare [8](sum-R) and the zero point
        ge_cached cached;
        u8 check[32];
        static const u8 zero_point[32] = {1};
        ge_cache(&cached, &minus_R);
        ge_add(sum, sum, &cached);
        ge_double(sum, sum, &minus_R);
        ge_double(sum, sum, &minus_R);
        ge_double(sum, sum, &minus_R);
        ge_tobytes(check, sum);
        return crypto_verify32(check, zero_point);
    }

#undef P_W_WIDTH
#undef B_W_WIDTH
#undef P_W_SIZE

// Clean up macros
#undef MC_FOR
#undef MC_FOR_T
#undef MC_COPY
#undef MC_ZERO
#undef MC_WIPE_CTX
#undef MC_WIPE_BUFFER
#undef MC_MIN
#undef MC_MAX
#undef FE_CARRY

} // namespace MONOCYPHER_CPP_NAMESPACE
