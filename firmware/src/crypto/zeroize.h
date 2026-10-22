/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

#pragma once

#include <stddef.h>

/*
 * Scrub sensitive bytes so the write cannot be optimised away.
 *
 * A plain memset() on a buffer that is about to leave scope is a dead store,
 * and the compiler is entitled to delete it — the classic reason a decrypted
 * key survives in stack memory after the function that "cleared" it returns.
 * This is Cantil's backend-independent stand-in for mbedtls_platform_zeroize():
 * it lets the crypto and session code scrub key material without every such
 * file having to pull in a crypto library for that one call. session_slot.c in
 * particular then links no crypto library at all.
 *
 * A NULL buf or zero len is a no-op.
 */
void cantil_zeroize(void *buf, size_t len);
