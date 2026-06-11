/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

/*
 * Session stub for the pairing_ca_anchor_passkey ztest suite (T-20).
 *
 * pairing.c (PAIRING_CA_ANCHOR_PLUS_PASSKEY) calls:
 *   session_get_client_cert_count() — how many client certs the peer sent
 *   session_get_client_cert()       — borrow the Nth cert DER
 *   session_recv()                  — receive CMD_PAIRING_PASSKEY_REPLY
 *   session_send()                  — send the pairing response
 *   session_get_local_pubkey()      — device static pubkey for PSK derivation
 *
 * Test controls:
 *   m5_test_session()                — return the stub cantil_session_t *
 *   m5_test_set_client_certs()       — inject client cert chain
 *   m5_test_clear_client_certs()     — reset to "no cert" (cert_count == 0)
 *   m5_test_set_reply_digits(d)      — session_recv returns CBOR{cmd=0x73, data=d}
 *   m5_test_lock_digits(d)           — same, but ignores hook overrides
 *   m5_test_set_reply_timeout()      — session_recv returns -ETIMEDOUT
 *   m5_test_last_response_err()      — last err value from session_send
 *   m5_test_reset()                  — clear all passkey/recv state
 */

#include <zephyr/kernel.h>
#include <string.h>
#include <errno.h>

#include "session/session.h"
#include "cantil_cbor.h"
#include "protocol/protocol.h"

#define MAX_TEST_CERTS 4

struct cantil_session {
	bool established;
	/* Injected client cert chain (borrowed pointers). */
	const uint8_t *cert_ders[MAX_TEST_CERTS];
	size_t         cert_lens[MAX_TEST_CERTS];
	size_t         cert_count;
};

static struct cantil_session stub_session = { .established = true };

cantil_session_t *m5_test_session(void)
{
	return &stub_session;
}

/* ── Cert injection controls ─────────────────────────────────────────────── */

void m5_test_set_client_certs(const uint8_t *const ders[],
			      const size_t lens[], size_t count)
{
	stub_session.cert_count =
		(count > MAX_TEST_CERTS) ? MAX_TEST_CERTS : count;
	for (size_t i = 0; i < stub_session.cert_count; i++) {
		stub_session.cert_ders[i] = ders[i];
		stub_session.cert_lens[i] = lens[i];
	}
}

void m5_test_clear_client_certs(void)
{
	stub_session.cert_count = 0;
}

/* ── Passkey reply controls ──────────────────────────────────────────────── */

static uint32_t stub_digits        = 0;
static bool     stub_digits_locked = false;
static bool     stub_timeout       = false;
static uint32_t stub_last_err      = UINT32_MAX;

void m5_test_set_reply_digits(uint32_t digits)
{
	if (!stub_digits_locked) {
		stub_digits = digits;
	}
}

void m5_test_lock_digits(uint32_t digits)
{
	stub_digits        = digits;
	stub_digits_locked = true;
}

void m5_test_set_reply_timeout(void)
{
	stub_timeout = true;
}

uint32_t m5_test_last_response_err(void)
{
	return stub_last_err;
}

void m5_test_reset(void)
{
	stub_session.cert_count = 0;
	stub_digits             = 0;
	stub_digits_locked      = false;
	stub_timeout            = false;
	stub_last_err           = UINT32_MAX;
}

/* ── session API stubs ───────────────────────────────────────────────────── */

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

int session_recv(cantil_session_t *session, uint8_t *buf,
		 size_t max_len, size_t *received)
{
	ARG_UNUSED(session);

	if (stub_timeout) {
		return -ETIMEDOUT;
	}

	uint8_t digit_cbor[9];
	size_t  digit_cbor_len = 0;

	if (cantil_cbor_emit_uint(digit_cbor, sizeof(digit_cbor),
				  &digit_cbor_len, stub_digits) != 0) {
		return -EIO;
	}

	int n = cantil_cbor_encode_request(buf, max_len,
					   CMD_PAIRING_PASSKEY_REPLY, 1,
					   digit_cbor, digit_cbor_len);
	if (n < 0) {
		return -ENOMEM;
	}
	*received = (size_t)n;
	return 0;
}

int session_send(cantil_session_t *session, const uint8_t *buf, size_t len)
{
	ARG_UNUSED(session);

	uint32_t seq = 0, err = UINT32_MAX;
	const uint8_t *data = NULL;
	size_t data_len = 0;

	if (cantil_cbor_decode_response(buf, len, &seq, &err, &data, &data_len) == 0) {
		stub_last_err = err;
	}
	return 0;
}

int session_get_local_pubkey(cantil_session_t *session, uint8_t pubkey[32])
{
	ARG_UNUSED(session);
	memset(pubkey, 0x55, 32);
	return 0;
}

int session_open(cantil_transport_t *t, const uint8_t *pub,
		 cantil_session_t **out)
{
	ARG_UNUSED(t); ARG_UNUSED(pub); ARG_UNUSED(out);
	return -ENOSYS;
}

void session_close(cantil_session_t *s) { ARG_UNUSED(s); }

int session_get_remote_pubkey(cantil_session_t *session, uint8_t pubkey[32])
{
	ARG_UNUSED(session); ARG_UNUSED(pubkey);
	return -ENOSYS;
}
