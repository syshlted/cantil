#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * Fill `out` with `count` randomly selected baby names as raw UTF-8 bytes.
 * Each name is followed by a 0xFF separator byte.  0xFF is an invalid UTF-8
 * byte and therefore an unambiguous delimiter for any name in any language.
 *
 * `count` is clamped to NAMES_BATCH_MAX.
 *
 * Returns the number of bytes written into `out`, or a negative errno on
 * error.
 */
int names_get_random_batch(uint16_t count, uint8_t *out, size_t out_size);
