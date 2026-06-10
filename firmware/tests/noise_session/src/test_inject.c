/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

#include <string.h>
#include <errno.h>

#include "session/test_inject.h"
#include "test_inject_ctl.h"

static struct {
	uint8_t s_priv[32], s_pub[32];
	uint8_t e_priv[32], e_pub[32];
	bool armed;
} g_inject;

void test_inject_arm(const uint8_t s_priv[32], const uint8_t s_pub[32],
		     const uint8_t e_priv[32], const uint8_t e_pub[32])
{
	memcpy(g_inject.s_priv, s_priv, 32);
	memcpy(g_inject.s_pub, s_pub, 32);
	memcpy(g_inject.e_priv, e_priv, 32);
	memcpy(g_inject.e_pub, e_pub, 32);
	g_inject.armed = true;
}

void test_inject_disarm(void)
{
	memset(&g_inject, 0, sizeof(g_inject));
}

int cantil_test_inject_static_keypair(uint8_t priv[32], uint8_t pub[32])
{
	if (!g_inject.armed) {
		return -EFAULT;
	}
	memcpy(priv, g_inject.s_priv, 32);
	memcpy(pub, g_inject.s_pub, 32);
	return 0;
}

int cantil_test_inject_ephemeral_keypair(uint8_t priv[32], uint8_t pub[32])
{
	if (!g_inject.armed) {
		return -EFAULT;
	}
	memcpy(priv, g_inject.e_priv, 32);
	memcpy(pub, g_inject.e_pub, 32);
	return 0;
}

/*
 * This vector suite exercises the bare Noise_XX math with empty handshake
 * payloads (matching the precomputed trace), so the responder sends no
 * identity chain.
 */
int cantil_test_inject_local_chain(const uint8_t *certs[], size_t lens[],
				   size_t max)
{
	(void)certs;
	(void)lens;
	(void)max;
	return 0;
}
