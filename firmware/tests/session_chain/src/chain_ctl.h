/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

#pragma once

#include <stdint.h>
#include <stddef.h>

/* Arm the responder's injected static + ephemeral X25519 keypairs. */
void test_inject_arm(const uint8_t s_priv[32], const uint8_t s_pub[32],
		     const uint8_t e_priv[32], const uint8_t e_pub[32]);

/*
 * Set the identity cert chain the responder emits on msg2 (leaf-first).
 * Pointers are borrowed and must outlive the handshake. n == 0 clears it,
 * yielding an empty handshake payload.
 */
void test_inject_chain_set(const uint8_t *const certs[], const size_t lens[],
			   size_t n);
