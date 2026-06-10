/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

/*
 * Tier-2 conformance test bodies for session.c, parameterized by vector.
 *
 * This file is intentionally NOT a translation unit on its own — it is
 * #included from a per-vector .c entry that supplies the vector header
 * (XX_* symbols) and a unique SUITE_NAME identifier before including it.
 *
 * See main.c (self-generated vector) and main_cacophony.c (Cacophony
 * reference vector); both drive session.c through a loopback transport
 * with the responder's keypairs injected from the precomputed trace.
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <string.h>
#include <errno.h>

#include "session/session.h"
#include "loopback.h"
#include "test_inject_ctl.h"

#ifndef SUITE_NAME
#error "SUITE_NAME must be defined before including noise_session_tests.inc"
#endif

/* ── shared loopback pair (responder is side_b) ─────────────────────────── */

static struct loopback_pair g_pair;

static void *suite_setup(void)
{
	loopback_pair_init(&g_pair);
	test_inject_arm(XX_RS_PRIV, XX_RS_PUB, XX_RE_PRIV, XX_RE_PUB);
	return NULL;
}

static void test_before(void *fixture)
{
	ARG_UNUSED(fixture);
	loopback_pair_init(&g_pair);
	test_inject_arm(XX_RS_PRIV, XX_RS_PUB, XX_RE_PRIV, XX_RE_PUB);
}

ZTEST_SUITE(SUITE_NAME, NULL, suite_setup, test_before, NULL, NULL);

/* ── helpers ────────────────────────────────────────────────────────────── */

static void stage_framed(struct loopback_pipe *p,
			 const uint8_t *payload, size_t len)
{
	uint8_t hdr[2] = {(uint8_t)(len >> 8), (uint8_t)(len & 0xFF)};

	loopback_stage_rx(p, hdr, 2);
	loopback_stage_rx(p, payload, len);
}

static size_t drain_framed(struct loopback_pipe *p,
			   uint8_t *out, size_t out_max)
{
	uint8_t hdr[2];
	size_t n = loopback_drain_tx(p, hdr, 2);

	zassert_equal(n, 2, "missing 2-byte length prefix in framed read");
	size_t frame_len = ((size_t)hdr[0] << 8) | hdr[1];

	zassert_true(frame_len <= out_max, "frame too large for out buffer");
	n = loopback_drain_tx(p, out, frame_len);
	zassert_equal(n, frame_len, "short read on framed payload");
	return frame_len;
}

/* ── Test 1: handshake vector replay ────────────────────────────────────── */

ZTEST(SUITE_NAME, handshake_matches_vector)
{
	/* Pre-stage both initiator-side messages so the single-threaded
	 * responder can drive the handshake to completion without a peer
	 * thread.  msg1 + msg3 are precomputed against the injected
	 * responder static/ephemeral so they verify against the vector.
	 */
	stage_framed(&g_pair.a_to_b, XX_MSG1, sizeof(XX_MSG1));
	stage_framed(&g_pair.a_to_b, XX_MSG3, sizeof(XX_MSG3));

	cantil_session_t *sess = NULL;
	int ret = session_open(&g_pair.side_b, NULL, &sess);

	zassert_ok(ret, "session_open failed: %d", ret);
	zassert_not_null(sess, "session handle was NULL");

	/* Inspect what the responder put on the wire — should be exactly
	 * msg2 from the vector, framed by a 2-byte big-endian length.
	 */
	uint8_t got_msg2[96];
	size_t got_len = drain_framed(&g_pair.b_to_a, got_msg2, sizeof(got_msg2));

	zassert_equal(got_len, sizeof(XX_MSG2),
		      "msg2 length %u != vector %u",
		      (unsigned)got_len, (unsigned)sizeof(XX_MSG2));
	zassert_mem_equal(got_msg2, XX_MSG2, sizeof(XX_MSG2),
			  "msg2 bytes diverge from Noise_XX reference trace");

	/* Remote pubkey should be the initiator's static pubkey from msg3. */
	uint8_t remote_pub[32];

	zassert_ok(session_get_remote_pubkey(sess, remote_pub),
		   "get_remote_pubkey");
	zassert_mem_equal(remote_pub, XX_IS_PUB, 32,
			  "remote pubkey != initiator static pub");

	uint8_t local_pub[32];

	zassert_ok(session_get_local_pubkey(sess, local_pub),
		   "get_local_pubkey");
	zassert_mem_equal(local_pub, XX_RS_PUB, 32,
			  "local pubkey != injected responder static pub");

	session_close(sess);
}

/* ── Test 2: post-handshake transport ciphertexts match vector ──────────── */

ZTEST(SUITE_NAME, transport_ciphertexts_match_vector)
{
	stage_framed(&g_pair.a_to_b, XX_MSG1, sizeof(XX_MSG1));
	stage_framed(&g_pair.a_to_b, XX_MSG3, sizeof(XX_MSG3));

	cantil_session_t *sess = NULL;
	int ret = session_open(&g_pair.side_b, NULL, &sess);

	zassert_ok(ret, "session_open failed: %d", ret);

	/* Drain msg2 we don't need; already validated by the previous test. */
	uint8_t scratch[96];
	(void)drain_framed(&g_pair.b_to_a, scratch, sizeof(scratch));

	/* (a) Initiator → responder: stage the vector's ciphertext, decrypt
	 * via session_recv, expect the vector's plaintext back.  Confirms
	 * the responder's rx_key matches initiator_tx_key from the trace.
	 */
	stage_framed(&g_pair.a_to_b, XX_MSG_A_CT, sizeof(XX_MSG_A_CT));

	uint8_t pt[64];
	size_t pt_len = 0;

	ret = session_recv(sess, pt, sizeof(pt), &pt_len);
	zassert_ok(ret, "session_recv failed: %d", ret);
	zassert_equal(pt_len, sizeof(XX_MSG_A_PT), "msg_a plaintext length");
	zassert_mem_equal(pt, XX_MSG_A_PT, sizeof(XX_MSG_A_PT),
			  "msg_a plaintext mismatch");

	/* (b) Responder → initiator: encrypt the vector's plaintext via
	 * session_send, expect the framed bytes on the wire to match the
	 * vector's ciphertext.  Confirms responder's tx_key matches
	 * responder_tx_key from the trace, with nonce 0 and empty AD.
	 */
	ret = session_send(sess, XX_MSG_B_PT, sizeof(XX_MSG_B_PT));
	zassert_ok(ret, "session_send failed: %d", ret);

	uint8_t got_ct[64];
	size_t got_len = drain_framed(&g_pair.b_to_a, got_ct, sizeof(got_ct));

	zassert_equal(got_len, sizeof(XX_MSG_B_CT),
		      "msg_b ct length %u != %u",
		      (unsigned)got_len, (unsigned)sizeof(XX_MSG_B_CT));
	zassert_mem_equal(got_ct, XX_MSG_B_CT, sizeof(XX_MSG_B_CT),
			  "msg_b ciphertext diverges from vector");

	session_close(sess);
}

/* ── Test 3: pinned client key — mismatch is rejected ───────────────────── */

ZTEST(SUITE_NAME, expected_client_pub_mismatch_rejected)
{
	stage_framed(&g_pair.a_to_b, XX_MSG1, sizeof(XX_MSG1));
	stage_framed(&g_pair.a_to_b, XX_MSG3, sizeof(XX_MSG3));

	uint8_t wrong_pub[32];
	memset(wrong_pub, 0xAA, 32);

	cantil_session_t *sess = NULL;
	int ret = session_open(&g_pair.side_b, wrong_pub, &sess);

	zassert_equal(ret, -EACCES,
		      "expected -EACCES for client key mismatch, got %d", ret);
	zassert_is_null(sess, "session handle should be NULL on rejection");
}

/* ── Test 4: live initiator over loopback with concurrent threads ───────── */

/*
 * Drive the initiator side of the handshake from a worker thread, using the
 * vector's precomputed wire bytes.  The responder runs on the main test
 * thread.  This exercises the loopback transport under genuine concurrent
 * send/recv (recv has to spin-wait on the peer thread), which the
 * pre-staged tests do not.
 */
/* Each translation unit including this template defines its own stack —
 * K_THREAD_STACK_DEFINE creates a non-static global, so paste the suite
 * name in to avoid link-time collisions when two TUs are linked together.
 */
#define _STK_NAME(s) s##_initiator_stack
#define STK_NAME(s) _STK_NAME(s)
K_THREAD_STACK_DEFINE(STK_NAME(SUITE_NAME), 4096);
#define initiator_stack STK_NAME(SUITE_NAME)
static struct k_thread initiator_thread;

struct initiator_args {
	struct loopback_pair *pair;
	int result;
	uint8_t echoed_pt[64];
	size_t echoed_len;
};

static int raw_recv_exact_blocking(cantil_transport_t *t,
				   uint8_t *buf, size_t len)
{
	size_t got = 0;

	while (got < len) {
		size_t n = 0;
		int r = t->recv(t, buf + got, len - got, &n);

		if (r) {
			return r;
		}
		got += n;
		if (n == 0) {
			k_msleep(1);
		}
	}
	return 0;
}

static int send_framed(cantil_transport_t *t, const uint8_t *buf, size_t len)
{
	uint8_t hdr[2] = {(uint8_t)(len >> 8), (uint8_t)(len & 0xFF)};
	int r = t->send(t, hdr, 2);

	if (r) {
		return r;
	}
	return t->send(t, buf, len);
}

static int recv_framed(cantil_transport_t *t, uint8_t *buf, size_t max_len,
		       size_t *got)
{
	uint8_t hdr[2];
	int r = raw_recv_exact_blocking(t, hdr, 2);

	if (r) {
		return r;
	}
	size_t frame_len = ((size_t)hdr[0] << 8) | hdr[1];

	if (frame_len > max_len) {
		return -ENOBUFS;
	}
	r = raw_recv_exact_blocking(t, buf, frame_len);
	if (r == 0) {
		*got = frame_len;
	}
	return r;
}

static void initiator_thread_fn(void *p1, void *p2, void *p3)
{
	struct initiator_args *args = p1;
	cantil_transport_t *t = &args->pair->side_a;

	/* msg1 → */
	args->result = send_framed(t, XX_MSG1, sizeof(XX_MSG1));
	if (args->result) {
		return;
	}

	/* ← msg2 (verify) */
	uint8_t msg2[96];
	size_t msg2_len = 0;

	args->result = recv_framed(t, msg2, sizeof(msg2), &msg2_len);
	if (args->result) {
		return;
	}
	if (msg2_len != sizeof(XX_MSG2) ||
	    memcmp(msg2, XX_MSG2, sizeof(XX_MSG2)) != 0) {
		args->result = -EBADMSG;
		return;
	}

	/* msg3 → */
	args->result = send_framed(t, XX_MSG3, sizeof(XX_MSG3));
	if (args->result) {
		return;
	}

	/* Transport: send msg_a (we are the initiator: tx_key = initiator_tx_key). */
	args->result = send_framed(t, XX_MSG_A_CT, sizeof(XX_MSG_A_CT));
	if (args->result) {
		return;
	}

	/* Receive msg_b ciphertext, store it for the main thread to verify. */
	args->result = recv_framed(t, args->echoed_pt, sizeof(args->echoed_pt),
				   &args->echoed_len);
}

ZTEST(SUITE_NAME, live_initiator_round_trip)
{
	struct initiator_args args = {
		.pair = &g_pair,
		.result = -EINPROGRESS,
	};

	k_thread_create(&initiator_thread, initiator_stack,
			K_THREAD_STACK_SIZEOF(initiator_stack),
			initiator_thread_fn, &args, NULL, NULL,
			K_PRIO_PREEMPT(5), 0, K_NO_WAIT);

	cantil_session_t *sess = NULL;
	int ret = session_open(&g_pair.side_b, XX_IS_PUB, &sess);

	zassert_ok(ret, "responder session_open failed: %d", ret);

	/* Receive initiator's transport message. */
	uint8_t pt[64];
	size_t pt_len = 0;

	ret = session_recv(sess, pt, sizeof(pt), &pt_len);
	zassert_ok(ret, "session_recv failed: %d", ret);
	zassert_equal(pt_len, sizeof(XX_MSG_A_PT));
	zassert_mem_equal(pt, XX_MSG_A_PT, sizeof(XX_MSG_A_PT));

	/* Reply with our own message. */
	ret = session_send(sess, XX_MSG_B_PT, sizeof(XX_MSG_B_PT));
	zassert_ok(ret, "session_send failed: %d", ret);

	/* Wait for initiator to finish reading our reply. */
	zassert_ok(k_thread_join(&initiator_thread, K_MSEC(2000)),
		   "initiator thread did not finish in time");
	zassert_ok(args.result, "initiator reported error: %d", args.result);
	zassert_equal(args.echoed_len, sizeof(XX_MSG_B_CT));
	zassert_mem_equal(args.echoed_pt, XX_MSG_B_CT, sizeof(XX_MSG_B_CT),
			  "responder's framed ciphertext != vector msg_b_ct");

	session_close(sess);
}
