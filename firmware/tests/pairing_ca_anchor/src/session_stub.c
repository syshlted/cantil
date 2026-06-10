/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

/*
 * Session stub for the pairing_ca_anchor ztest suite (T-19).
 *
 * pairing.c (PAIRING_CA_ANCHOR) calls:
 *   session_get_client_cert_count() — how many client certs the peer sent
 *   session_get_client_cert()       — borrow the Nth cert DER
 *
 * Test controls (called from main.c):
 *   ca_anchor_test_session()           — return the stub cantil_session_t
 *   ca_anchor_test_set_client_certs()  — inject cert chain for next call
 *   ca_anchor_test_clear_client_certs() — reset to "no cert" (cert_count == 0)
 */

#include <zephyr/kernel.h>
#include <string.h>
#include <errno.h>

#include "session/session.h"

#define MAX_TEST_CERTS 4

/* Minimal concrete struct — opaque in session.h. */
struct cantil_session {
	bool established;
	/* Injected client cert chain (borrowed pointers — not freed here). */
	const uint8_t *cert_ders[MAX_TEST_CERTS];
	size_t         cert_lens[MAX_TEST_CERTS];
	size_t         cert_count;
};

static struct cantil_session stub_session = { .established = true };

cantil_session_t *ca_anchor_test_session(void)
{
	return &stub_session;
}

void ca_anchor_test_set_client_certs(const uint8_t *const ders[],
				     const size_t lens[], size_t count)
{
	stub_session.cert_count = (count > MAX_TEST_CERTS) ? MAX_TEST_CERTS : count;
	for (size_t i = 0; i < stub_session.cert_count; i++) {
		stub_session.cert_ders[i] = ders[i];
		stub_session.cert_lens[i] = lens[i];
	}
}

void ca_anchor_test_clear_client_certs(void)
{
	stub_session.cert_count = 0;
}

/* ── session API stubs ─────────────────────────────────────────────────── */

size_t session_get_client_cert_count(const cantil_session_t *s)
{
	return s ? s->cert_count : 0;
}

int session_get_client_cert(const cantil_session_t *s, size_t idx,
			    const uint8_t **der, size_t *len)
{
	if (!s || !der || !len) return -EINVAL;
	if (idx >= s->cert_count) return -ENOENT;
	*der = s->cert_ders[idx];
	*len = s->cert_lens[idx];
	return 0;
}

/* Remaining session API is not called by pairing.c (PAIRING_CA_ANCHOR). */

int session_open(cantil_transport_t *t, const uint8_t *pub,
		 cantil_session_t **out)
{
	ARG_UNUSED(t); ARG_UNUSED(pub); ARG_UNUSED(out);
	return -ENOSYS;
}

void session_close(cantil_session_t *s) { ARG_UNUSED(s); }

int session_send(cantil_session_t *s, const uint8_t *buf, size_t len)
{
	ARG_UNUSED(s); ARG_UNUSED(buf); ARG_UNUSED(len);
	return -ENOSYS;
}

int session_recv(cantil_session_t *s, uint8_t *buf, size_t max, size_t *got)
{
	ARG_UNUSED(s); ARG_UNUSED(buf); ARG_UNUSED(max); ARG_UNUSED(got);
	return -ENOSYS;
}

int session_get_remote_pubkey(cantil_session_t *s, uint8_t pub[32])
{
	ARG_UNUSED(s); ARG_UNUSED(pub);
	return -ENOSYS;
}

int session_get_local_pubkey(cantil_session_t *s, uint8_t pub[32])
{
	ARG_UNUSED(s); ARG_UNUSED(pub);
	return -ENOSYS;
}
