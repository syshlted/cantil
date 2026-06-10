/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXTENSIONS.md at the repo root. */

/*
 * Session stub for the pairing_passkey ztest suite (T-18).
 *
 * pairing.c (PAIRING_PASSKEY) calls:
 *   session_recv()             — receive the CMD_PAIRING_PASSKEY_REPLY frame
 *   session_send()             — send the response (OK/error)
 *   session_get_local_pubkey() — get device static pubkey for PSK derivation
 *
 * Control functions (called from test main.c):
 *   pairing_passkey_test_session()           — return the stub cantil_session_t
 *   pairing_passkey_test_set_reply_digits(d) — session_recv returns CBOR{cmd=0x73, data=d}
 *   pairing_passkey_test_lock_digits(d)      — same, but ignores hook overrides
 *   pairing_passkey_test_set_reply_timeout() — session_recv returns -ETIMEDOUT
 *   pairing_passkey_test_last_response_err() — last err captured from session_send
 *   pairing_passkey_test_reset()             — clear all state
 *
 * Hook integration: pairing_test_passkey_hook() in test/main.c calls
 * pairing_passkey_test_set_reply_digits() to prime the stub with the correct
 * passkey for success tests.  Tests that want a wrong passkey call
 * pairing_passkey_test_lock_digits(999999) BEFORE starting, so the hook
 * cannot override the value.
 *
 * cantil_session_t must be defined here (it is opaque in session.h).
 */

#include <zephyr/kernel.h>
#include <string.h>
#include <errno.h>

#include "session/session.h"
#include "cantil_cbor.h"
#include "protocol/protocol.h"

/* Minimal concrete struct definition — opaque in session.h. */
struct cantil_session {
	bool established;
};

static struct cantil_session stub_session = { .established = true };

cantil_session_t *pairing_passkey_test_session(void)
{
	return &stub_session;
}

/* ── Test controls ─────────────────────────────────────────────────────── */

static uint32_t stub_digits         = 0;
static bool     stub_digits_locked  = false;
static bool     stub_inject_timeout = false;
static uint32_t stub_last_err       = UINT32_MAX;

/* Set digits; overridable by the passkey hook (for success tests). */
void pairing_passkey_test_set_reply_digits(uint32_t digits)
{
	if (!stub_digits_locked) {
		stub_digits = digits;
	}
}

/* Set digits AND lock against hook override (for wrong-passkey tests). */
void pairing_passkey_test_lock_digits(uint32_t digits)
{
	stub_digits        = digits;
	stub_digits_locked = true;
}

void pairing_passkey_test_set_reply_timeout(void)
{
	stub_inject_timeout = true;
}

uint32_t pairing_passkey_test_last_response_err(void)
{
	return stub_last_err;
}

void pairing_passkey_test_reset(void)
{
	stub_digits         = 0;
	stub_digits_locked  = false;
	stub_inject_timeout = false;
	stub_last_err       = UINT32_MAX;
}

/* ── session API stubs ─────────────────────────────────────────────────── */

int session_recv(cantil_session_t *session, uint8_t *buf,
		 size_t max_len, size_t *received)
{
	ARG_UNUSED(session);

	if (stub_inject_timeout) {
		return -ETIMEDOUT;
	}

	/*
	 * Build a CBOR passkey-reply request:
	 *   data payload = CBOR uint32 (the digits value).
	 *   request      = {cmd: 0x73, seq: 1, data: bstr(<CBOR uint32>)}
	 */
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

void session_close(cantil_session_t *session) { ARG_UNUSED(session); }

int session_get_remote_pubkey(cantil_session_t *session, uint8_t pubkey[32])
{
	ARG_UNUSED(session); ARG_UNUSED(pubkey);
	return -ENOSYS;
}
