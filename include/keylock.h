#ifndef KEYLOCK_H
#define KEYLOCK_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Borrowed byte view used by the C ABI.
 */
typedef struct {
  const uint8_t *ptr;
  uintptr_t len;
} KeylockBytes;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Returns a pointer to the last error message, or NULL if there is none.
 * The pointer is valid until the next FFI call on this thread.
 */
const char *keylock_last_error_message(void);

/**
 * Crate version, as a static NUL-terminated string.
 */
const char *keylock_version(void);

/**
 * Fill `out` with cryptographically secure random bytes.
 */
bool keylock_random_bytes(uint8_t *out, uintptr_t out_len);

/**
 * Uniform random `u32` in `[0, upper_bound)`, or 0 when `upper_bound < 2`.
 */
uint32_t keylock_random_uniform(uint32_t upper_bound);

/**
 * Compute SHA-256 into a caller-owned 32-byte output buffer.
 */
bool keylock_sha256(const uint8_t *input, uintptr_t input_len, uint8_t *out, uintptr_t out_len);

/**
 * Compute Keccak-256 into a caller-owned 32-byte output buffer.
 */
bool keylock_keccak256(const uint8_t *input, uintptr_t input_len, uint8_t *out, uintptr_t out_len);

/**
 * Constant-time byte equality. Returns false for null pointers with nonzero length.
 */
bool keylock_bytes_equal(const uint8_t *a, uintptr_t a_len, const uint8_t *b, uintptr_t b_len);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* KEYLOCK_H */
