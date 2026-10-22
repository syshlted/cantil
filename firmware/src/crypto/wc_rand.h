/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

#pragma once

#include <stdint.h>
#include <stddef.h>

/*
 * The single entropy seam between Zephyr and wolfCrypt.
 *
 * Both wolfSSL backend files need randomness, and so does wolfCrypt itself:
 * X25519 blinding (WOLFSSL_CURVE25519_BLINDING, on by default) calls
 * wc_InitRng() from inside wc_curve25519_generic(), so even the DH path — which
 * takes no RNG argument — pulls one in. Keeping the source in one file means
 * there is one place where "where does Cantil's entropy come from" is answered,
 * rather than a copy per backend.
 */

/* Raw Zephyr entropy device — the nRF52840's CC310 hardware TRNG.
 * Returns 0 or a negative errno, like the rest of the codebase. */
int cantil_wc_trng(uint8_t *buf, size_t len);

/*
 * wolfCrypt's CUSTOM_RAND_GENERATE_BLOCK hook (see
 * firmware/include/cantil_wolfssl_user_settings.h). Returns 0 on success and
 * non-zero on failure, which is wolfCrypt's convention, not errno's.
 *
 * Declared in the settings header as well, because wolfCrypt's random.c sees
 * only that; the two declarations must stay identical or the call goes through
 * a mismatched prototype.
 */
int cantil_wc_rand_block(unsigned char *output, unsigned int sz);
