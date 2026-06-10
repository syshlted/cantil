/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

/*
 * T-04: device identity cert chain on encrypted Noise msg2.
 *
 * The device-side responder (session.c) runs on a worker thread over a
 * loopback transport; a compact in-test Noise_XX initiator (built on the same
 * noise_crypto.h primitives session.c uses) runs on the main thread, completes
 * the handshake, decrypts the msg2 payload, and parses the CBOR
 * { 1: [ <leaf_der>, ... ] } chain. We assert the chain the responder emitted
 * (injected via test_inject_chain_set) arrives byte-for-byte, leaf-first, for
 * empty / single / 3-cert chains. This is the conformance contract the
 * libcantil initiator implements in parallel.
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <string.h>
#include <errno.h>

#include "session/session.h"
#include "noise_crypto.h"
#include "cantil_cbor.h"
#include "loopback.h"
#include "chain_ctl.h"

#define TAG 16

static const uint8_t PROTOCOL_NAME[32] = "Noise_XX_25519_ChaChaPoly_SHA256";

/* ── Minimal initiator symmetric state (mirrors session.c) ──────────────── */

struct sym {
	uint8_t  h[32];
	uint8_t  ck[32];
	uint8_t  k[32];
	uint64_t n;
	bool     has_key;
};

static void sym_init(struct sym *s)
{
	memcpy(s->h, PROTOCOL_NAME, 32);
	memcpy(s->ck, PROTOCOL_NAME, 32);
	memset(s->k, 0, 32);
	s->n = 0;
	s->has_key = false;
}

static int sym_mix_hash(struct sym *s, const uint8_t *d, size_t len)
{
	return noise_crypto_hash(s->h, s->h, 32, d, len);
}

static int sym_mix_key(struct sym *s, const uint8_t *ikm, size_t len)
{
	uint8_t ck[32], k[32];
	int r = noise_crypto_hkdf2(ck, k, s->ck, ikm, len);

	if (!r) {
		memcpy(s->ck, ck, 32);
		memcpy(s->k, k, 32);
		s->n = 0;
		s->has_key = true;
	}
	return r;
}

static int sym_enc(struct sym *s, const uint8_t *pt, size_t pt_len,
		   uint8_t *ct, size_t cap, size_t *ct_len)
{
	if (!s->has_key) {
		if (cap < pt_len) {
			return -ENOBUFS;
		}
		memcpy(ct, pt, pt_len);
		*ct_len = pt_len;
		return sym_mix_hash(s, ct, pt_len);
	}
	int r = noise_crypto_encrypt(ct, cap, ct_len, s->k, s->n, s->h, 32,
				     pt, pt_len);
	if (r) {
		return r;
	}
	s->n++;
	return sym_mix_hash(s, ct, *ct_len);
}

static int sym_dec(struct sym *s, const uint8_t *ct, size_t ct_len,
		   uint8_t *pt, size_t cap, size_t *pt_len)
{
	if (!s->has_key) {
		if (cap < ct_len) {
			return -ENOBUFS;
		}
		memcpy(pt, ct, ct_len);
		*pt_len = ct_len;
		return sym_mix_hash(s, ct, ct_len);
	}
	int r = noise_crypto_decrypt(pt, cap, pt_len, s->k, s->n, s->h, 32,
				     ct, ct_len);
	if (r) {
		return r;
	}
	s->n++;
	return sym_mix_hash(s, ct, ct_len);
}

/* ── Transport framing (blocking, peer-thread safe) ─────────────────────── */

static int tx_send(cantil_transport_t *t, const uint8_t *buf, size_t len)
{
	uint8_t hdr[2] = {(uint8_t)(len >> 8), (uint8_t)(len & 0xFF)};
	int r = t->send(t, hdr, 2);

	if (r) {
		return r;
	}
	return t->send(t, buf, len);
}

static int rx_exact(cantil_transport_t *t, uint8_t *buf, size_t len)
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

static int rx_frame(cantil_transport_t *t, uint8_t *buf, size_t cap, size_t *len)
{
	uint8_t hdr[2];
	int r = rx_exact(t, hdr, 2);

	if (r) {
		return r;
	}
	size_t fl = ((size_t)hdr[0] << 8) | hdr[1];

	if (fl > cap) {
		return -ENOBUFS;
	}
	r = rx_exact(t, buf, fl);
	if (!r) {
		*len = fl;
	}
	return r;
}

/* ── In-test initiator ──────────────────────────────────────────────────── */

struct chain_out {
	uint8_t certs[4][1024];
	size_t  lens[4];
	size_t  count;
	size_t  msg2_len;
};

static void parse_chain(struct chain_out *out, const uint8_t *pt, size_t pt_len)
{
	out->count = 0;
	if (pt_len == 0) {
		return;
	}

	size_t off = 0;
	uint8_t major;
	uint64_t val;

	if (cantil_cbor_read_head(pt, pt_len, &off, &major, &val) != 0 ||
	    major != CANTIL_CBOR_MT_MAP) {
		return;
	}
	for (size_t p = 0; p < (size_t)val; p++) {
		uint32_t key;

		if (cantil_cbor_read_uint32(pt, pt_len, &off, &key) != 0 ||
		    key != 1) {
			return;
		}
		uint8_t amaj;
		uint64_t acount;

		if (cantil_cbor_read_head(pt, pt_len, &off, &amaj, &acount) != 0 ||
		    amaj != CANTIL_CBOR_MT_ARRAY) {
			return;
		}
		for (size_t i = 0; i < (size_t)acount && i < 4; i++) {
			const uint8_t *c;
			size_t cl;

			if (cantil_cbor_read_bstr(pt, pt_len, &off, &c, &cl) != 0 ||
			    cl > sizeof(out->certs[0])) {
				return;
			}
			memcpy(out->certs[out->count], c, cl);
			out->lens[out->count] = cl;
			out->count++;
		}
		return;
	}
}

/* Run the initiator handshake against side_a, capture the device chain. */
static int run_initiator(cantil_transport_t *t, struct chain_out *out)
{
	uint8_t is_priv[32], is_pub[32];   /* initiator static */
	uint8_t ie_priv[32], ie_pub[32];   /* initiator ephemeral */
	struct sym sym;
	int r;

	r = noise_crypto_dh_keygen(is_priv, is_pub);
	if (r) {
		return r;
	}
	r = noise_crypto_dh_keygen(ie_priv, ie_pub);
	if (r) {
		return r;
	}

	sym_init(&sym);
	sym_mix_hash(&sym, NULL, 0);                 /* prologue "" */

	/* msg1 → e */
	sym_mix_hash(&sym, ie_pub, 32);
	sym_mix_hash(&sym, NULL, 0);                 /* empty payload */
	r = tx_send(t, ie_pub, 32);
	if (r) {
		return r;
	}

	/* msg2 ← e, ee, s, es, chain */
	uint8_t msg2[2048];
	size_t  msg2_len = 0;

	r = rx_frame(t, msg2, sizeof(msg2), &msg2_len);
	if (r) {
		return r;
	}
	out->msg2_len = msg2_len;
	if (msg2_len < 96) {
		return -EPROTO;
	}

	uint8_t er_pub[32];

	memcpy(er_pub, msg2, 32);
	sym_mix_hash(&sym, er_pub, 32);

	uint8_t dh[32];

	r = noise_crypto_dh(dh, ie_priv, er_pub);    /* ee */
	if (r) {
		return r;
	}
	sym_mix_key(&sym, dh, 32);

	uint8_t dev_s_pub[32];
	size_t  dlen;

	r = sym_dec(&sym, msg2 + 32, 48, dev_s_pub, 32, &dlen);   /* s */
	if (r) {
		return r;
	}

	r = noise_crypto_dh(dh, ie_priv, dev_s_pub); /* es */
	if (r) {
		return r;
	}
	sym_mix_key(&sym, dh, 32);

	uint8_t chain_pt[2048];
	size_t  chain_len = 0;

	r = sym_dec(&sym, msg2 + 80, msg2_len - 80,
		    chain_pt, sizeof(chain_pt), &chain_len);
	if (r) {
		return r;
	}
	parse_chain(out, chain_pt, chain_len);

	/* msg3 → s, se, {} */
	uint8_t msg3[96];
	size_t  pos = 0, enc_len;

	r = sym_enc(&sym, is_pub, 32, msg3, sizeof(msg3), &enc_len);  /* s */
	if (r) {
		return r;
	}
	pos += enc_len;

	r = noise_crypto_dh(dh, is_priv, er_pub);    /* se */
	if (r) {
		return r;
	}
	sym_mix_key(&sym, dh, 32);

	const uint8_t empty_map[1] = {0xA0};

	r = sym_enc(&sym, empty_map, 1, msg3 + pos, sizeof(msg3) - pos, &enc_len);
	if (r) {
		return r;
	}
	pos += enc_len;

	return tx_send(t, msg3, pos);
}

/* ── Responder worker thread ────────────────────────────────────────────── */

K_THREAD_STACK_DEFINE(responder_stack, 8192);
static struct k_thread responder_thread;

struct resp_args {
	struct loopback_pair *pair;
	cantil_session_t     *sess;
	int                   ret;
};

static void responder_fn(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);
	struct resp_args *a = p1;

	a->ret = session_open(&a->pair->side_b, NULL, &a->sess);
}

/* ── Fixtures ───────────────────────────────────────────────────────────── */

static struct loopback_pair g_pair;

static void arm_responder_keys(void)
{
	uint8_t rs_priv[32], rs_pub[32], re_priv[32], re_pub[32];

	zassert_ok(noise_crypto_dh_keygen(rs_priv, rs_pub), "rs keygen");
	zassert_ok(noise_crypto_dh_keygen(re_priv, re_pub), "re keygen");
	test_inject_arm(rs_priv, rs_pub, re_priv, re_pub);
}

static void test_before(void *fixture)
{
	ARG_UNUSED(fixture);
	loopback_pair_init(&g_pair);
	arm_responder_keys();
	test_inject_chain_set(NULL, NULL, 0);
}

ZTEST_SUITE(session_chain, NULL, NULL, test_before, NULL, NULL);

/*
 * Run a full handshake with the currently-injected chain and return the
 * initiator's view of the device chain. Asserts both sides complete cleanly.
 */
static void do_handshake(struct chain_out *out)
{
	struct resp_args args = {.pair = &g_pair, .ret = -EINPROGRESS};

	k_thread_create(&responder_thread, responder_stack,
			K_THREAD_STACK_SIZEOF(responder_stack),
			responder_fn, &args, NULL, NULL,
			K_PRIO_PREEMPT(5), 0, K_NO_WAIT);

	int r = run_initiator(&g_pair.side_a, out);

	zassert_ok(r, "initiator handshake failed: %d", r);
	zassert_ok(k_thread_join(&responder_thread, K_MSEC(3000)),
		   "responder thread hung");
	zassert_ok(args.ret, "responder session_open failed: %d", args.ret);

	session_close(args.sess);
}

/* ── Tests ──────────────────────────────────────────────────────────────── */

ZTEST(session_chain, empty_chain_self_signed)
{
	/* No identity injected -> empty handshake payload, legacy 96-byte msg2. */
	struct chain_out out;

	do_handshake(&out);

	zassert_equal(out.msg2_len, 96, "empty chain should give 96-byte msg2, got %zu",
		      out.msg2_len);
	zassert_equal(out.count, 0, "expected no certs, got %zu", out.count);
}

ZTEST(session_chain, single_cert_chain)
{
	static uint8_t leaf[200];

	for (size_t i = 0; i < sizeof(leaf); i++) {
		leaf[i] = (uint8_t)(0x30 + (i & 0x3F));
	}
	const uint8_t *certs[1] = {leaf};
	const size_t   lens[1]  = {sizeof(leaf)};

	test_inject_chain_set(certs, lens, 1);

	struct chain_out out;

	do_handshake(&out);

	zassert_true(out.msg2_len > 96, "non-empty chain should grow msg2");
	zassert_equal(out.count, 1, "expected 1 cert, got %zu", out.count);
	zassert_equal(out.lens[0], sizeof(leaf), "leaf length");
	zassert_mem_equal(out.certs[0], leaf, sizeof(leaf), "leaf bytes");
}

ZTEST(session_chain, three_cert_chain)
{
	static uint8_t c0[50], c1[150], c2[400];

	for (size_t i = 0; i < sizeof(c0); i++) {
		c0[i] = (uint8_t)(i + 1);
	}
	for (size_t i = 0; i < sizeof(c1); i++) {
		c1[i] = (uint8_t)(i * 3 + 7);
	}
	for (size_t i = 0; i < sizeof(c2); i++) {
		c2[i] = (uint8_t)(i ^ 0xA5);
	}
	const uint8_t *certs[3] = {c0, c1, c2};
	const size_t   lens[3]  = {sizeof(c0), sizeof(c1), sizeof(c2)};

	test_inject_chain_set(certs, lens, 3);

	struct chain_out out;

	do_handshake(&out);

	zassert_equal(out.count, 3, "expected 3 certs, got %zu", out.count);
	zassert_equal(out.lens[0], sizeof(c0), "c0 len");
	zassert_equal(out.lens[1], sizeof(c1), "c1 len");
	zassert_equal(out.lens[2], sizeof(c2), "c2 len");
	zassert_mem_equal(out.certs[0], c0, sizeof(c0), "c0 bytes (leaf-first)");
	zassert_mem_equal(out.certs[1], c1, sizeof(c1), "c1 bytes");
	zassert_mem_equal(out.certs[2], c2, sizeof(c2), "c2 bytes");
}
