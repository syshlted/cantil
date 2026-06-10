/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

#pragma once

/*
 * Test-only injection hooks for session.c.  Only compiled when
 * CONFIG_CANTIL_TEST_INJECT_NOISE_KEYS=y (test builds — never production).
 *
 * The test binary provides strong definitions of these two functions.  Each
 * returns 0 on success and fills the priv/pub pair with bytes drawn from a
 * precomputed Noise_XX vector.  When this Kconfig is enabled, session.c
 * calls these instead of touching storage or noise_crypto_dh_keygen, which
 * makes the responder's wire output bit-deterministic against the vector.
 */

#include <stdint.h>
#include <stddef.h>

int cantil_test_inject_static_keypair(uint8_t priv[32], uint8_t pub[32]);
int cantil_test_inject_ephemeral_keypair(uint8_t priv[32], uint8_t pub[32]);

/*
 * Identity cert chain (T-04). session.c calls this in test builds instead of
 * reading the session slot. Fills up to `max` borrowed (ptr,len) pairs with
 * the leaf-first chain and returns the count (0 -> empty handshake payload),
 * or -errno. Pointers must outlive the handshake.
 */
int cantil_test_inject_local_chain(const uint8_t *certs[], size_t lens[],
				   size_t max);
