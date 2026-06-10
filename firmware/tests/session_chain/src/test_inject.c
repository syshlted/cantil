/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

#include <string.h>
#include <errno.h>
#include <stdbool.h>

#include "session/test_inject.h"
#include "chain_ctl.h"

#define MAX_CERTS 4

static struct {
	uint8_t s_priv[32], s_pub[32];
	uint8_t e_priv[32], e_pub[32];
	bool armed;

	const uint8_t *certs[MAX_CERTS];
	size_t         lens[MAX_CERTS];
	size_t         count;
} g;

void test_inject_arm(const uint8_t s_priv[32], const uint8_t s_pub[32],
		     const uint8_t e_priv[32], const uint8_t e_pub[32])
{
	memcpy(g.s_priv, s_priv, 32);
	memcpy(g.s_pub, s_pub, 32);
	memcpy(g.e_priv, e_priv, 32);
	memcpy(g.e_pub, e_pub, 32);
	g.armed = true;
}

void test_inject_chain_set(const uint8_t *const certs[], const size_t lens[],
			   size_t n)
{
	if (n > MAX_CERTS) {
		n = MAX_CERTS;
	}
	for (size_t i = 0; i < n; i++) {
		g.certs[i] = certs[i];
		g.lens[i] = lens[i];
	}
	g.count = n;
}

int cantil_test_inject_static_keypair(uint8_t priv[32], uint8_t pub[32])
{
	if (!g.armed) {
		return -EFAULT;
	}
	memcpy(priv, g.s_priv, 32);
	memcpy(pub, g.s_pub, 32);
	return 0;
}

int cantil_test_inject_ephemeral_keypair(uint8_t priv[32], uint8_t pub[32])
{
	if (!g.armed) {
		return -EFAULT;
	}
	memcpy(priv, g.e_priv, 32);
	memcpy(pub, g.e_pub, 32);
	return 0;
}

int cantil_test_inject_local_chain(const uint8_t *certs[], size_t lens[],
				   size_t max)
{
	size_t n = g.count < max ? g.count : max;

	for (size_t i = 0; i < n; i++) {
		certs[i] = g.certs[i];
		lens[i] = g.lens[i];
	}
	return (int)n;
}
