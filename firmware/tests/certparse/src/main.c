/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

/*
 * certparse conformance — run against BOTH backends (certparse/ builds the
 * mbedTLS one, certparse_wolfssl/ the wolfCrypt one), which must agree.
 *
 * This suite exists because step 6a discovered that ca.c's chain verification
 * had NO test coverage at all — not under mbedTLS either. That was tolerable
 * while the walker was mbedTLS's, battle-tested code called through one
 * function. It stopped being tolerable the moment the WOLFCRYPT_ONLY build
 * required Cantil to build certificate paths itself (see
 * src/ca/certparse_wolfssl.c for why it cannot call a library walker).
 *
 * The cases that matter most are the negative ones. A chain verifier that
 * accepts everything passes every "valid chain verifies" test ever written;
 * only the refusals show it is doing anything. In particular
 * test_trust_anchor_trap encodes the bug that shipped in the first draft of
 * the host's equivalent (libcantil/src/x509_wolfssl.c): treating a
 * peer-supplied intermediate as trusted rather than verifying it first.
 *
 * Fixtures are the openssl-CLI-generated certificates in
 * libcantil/tests/fixtures.h — a third implementation, shared with the host
 * seam's tests so both sides of the wire are checked against the same bytes.
 */

#include <zephyr/ztest.h>
#include <string.h>

#include "ca/certparse.h"

#include "fixtures.h"

#define SZ(x) (x), sizeof(x)

/* ── field extraction ───────────────────────────────────────────────────── */

ZTEST(certparse, test_01_parse_leaf_fields)
{
	certparse_cert_t c;

	zassert_ok(certparse_cert(SZ(fx_leaf), &c), "leaf should parse");
	zassert_true(c.serial_len > 0, "serial missing");
	zassert_str_equal(c.subject.cn, "Cantil-TESTSERIAL01", "CN wrong");
	zassert_str_equal(c.subject.o, "Cantil", "O wrong");
	zassert_str_equal(c.subject.ou, "Session", "OU wrong");
	zassert_str_equal(c.subject.c, "CA", "C wrong");
	zassert_str_equal(c.subject.st, "Ontario", "ST wrong");
	zassert_str_equal(c.subject.l, "Ottawa", "L wrong");
	zassert_false(c.dn_overflow, "no RDN should overflow");
	zassert_true(c.has_pubkey, "pubkey should be extractable");
	zassert_equal(c.pubkey[0], 0x04, "pubkey must be an uncompressed point");
	zassert_false(c.self_signed, "leaf is CA-signed");
	zassert_false(c.is_ca, "leaf is not a CA");
}

ZTEST(certparse, test_02_parse_root_is_ca_and_self_signed)
{
	certparse_cert_t c;

	zassert_ok(certparse_cert(SZ(fx_root), &c), "root should parse");
	zassert_true(c.is_ca, "root must be a CA");
	zassert_true(c.self_signed, "root must be self-signed");
	zassert_str_equal(c.subject.cn, "Cantil Test Root", "CN wrong");
}

/*
 * The subject DN must come back as a COMPLETE DER element — tag and length
 * included. The CRL encoder copies these bytes straight into the
 * CertificateList issuer field, so a backend returning the SEQUENCE contents
 * alone (which is what wolfSSL's subjectRaw natively points at) would emit a
 * CRL whose issuer Name is missing its header.
 */
ZTEST(certparse, test_03_subject_der_is_a_full_tlv)
{
	certparse_cert_t c;

	zassert_ok(certparse_cert(SZ(fx_leaf), &c), "leaf should parse");
	zassert_true(c.subject_der_len >= 2, "subject DER too short");
	zassert_equal(c.subject_der[0], 0x30,
		      "subject DER must start with the SEQUENCE tag, got 0x%02x", c.subject_der[0]);

	/* The encoded length must describe exactly the bytes that follow. */
	size_t content = c.subject_der[1];
	size_t hdr = 2;

	if (content & 0x80) {
		size_t n = content & 0x7F;

		content = 0;
		for (size_t i = 0; i < n; i++) {
			content = (content << 8) | c.subject_der[2 + i];
		}
		hdr = 2 + n;
	}
	zassert_equal(hdr + content, c.subject_der_len, "header says %zu bytes, buffer holds %zu",
		      hdr + content, c.subject_der_len);
}

ZTEST(certparse, test_04_garbage_is_rejected)
{
	const uint8_t junk[] = {0x30, 0x82, 0xff, 0xff, 0x00, 0x01};
	certparse_cert_t c;

	zassert_not_equal(certparse_cert(SZ(junk), &c), 0, "garbage must not parse");
}

/* ── chain verification: the positives ──────────────────────────────────── */

ZTEST(certparse, test_05_leaf_via_intermediate_verifies)
{
	const uint8_t *inter[] = {fx_inter};
	const size_t ilen[] = {sizeof(fx_inter)};

	zassert_ok(certparse_verify_chain(SZ(fx_leaf), inter, ilen, 1, SZ(fx_root)),
		   "leaf -> inter -> root should verify");
}

ZTEST(certparse, test_06_intermediate_directly_under_root)
{
	zassert_ok(certparse_verify_chain(SZ(fx_inter), NULL, NULL, 0, SZ(fx_root)),
		   "inter -> root should verify with no intermediates");
}

/* ── chain verification: the refusals that prove it works ───────────────── */

ZTEST(certparse, test_07_missing_intermediate_refused)
{
	/* The leaf is signed by the sub-CA, so the root alone cannot verify it.
	 * A verifier that returns OK here is trusting an incomplete chain. */
	zassert_not_equal(certparse_verify_chain(SZ(fx_leaf), NULL, NULL, 0, SZ(fx_root)), 0,
			  "leaf must NOT verify against the root directly");
}

ZTEST(certparse, test_08_unrelated_anchor_refused)
{
	const uint8_t *inter[] = {fx_inter};
	const size_t ilen[] = {sizeof(fx_inter)};

	zassert_not_equal(certparse_verify_chain(SZ(fx_leaf), inter, ilen, 1, SZ(fx_other)), 0,
			  "chain must NOT verify against an unrelated root");
}

/*
 * THE TRUST-ANCHOR TRAP.
 *
 * A peer supplies the intermediates. If the verifier trusts them because they
 * were supplied — rather than because they chain to the caller's anchor — then
 * presenting a self-signed certificate as an "intermediate" wins. This is the
 * bug that shipped in the first draft of libcantil/src/x509_wolfssl.c, where
 * wolfSSL_CertManagerLoadCABuffer turned every supplied cert into an anchor.
 *
 * Here the "intermediate" is fx_other: a perfectly valid self-signed CA that
 * simply has nothing to do with fx_root. It must not launder anything.
 */
ZTEST(certparse, test_09_trust_anchor_trap)
{
	/* fx_rogue is a valid leaf that fx_other really did sign. Supplying
	 * fx_other as an "intermediate" is the attack: if the verifier trusts a
	 * supplied intermediate because it was supplied, the rogue leaf verifies
	 * under an anchor that never certified anything in this chain.
	 *
	 * The fixture matters. An earlier version of this test used a leaf that
	 * fx_other had NOT signed, so it was refused for the wrong reason and
	 * passed even against a deliberately broken verifier — caught by mutating
	 * certparse_wolfssl.c to trust intermediates blindly and finding this
	 * test still green. */
	const uint8_t *inter[] = {fx_other};
	const size_t ilen[] = {sizeof(fx_other)};

	zassert_not_equal(certparse_verify_chain(SZ(fx_rogue), inter, ilen, 1, SZ(fx_root)), 0,
			  "a self-signed CA supplied as an intermediate must NOT be "
			  "trusted just because it was supplied");
}

ZTEST(certparse, test_10_unrelated_leaf_refused)
{
	/* fx_other is self-signed by a key fx_root never certified. */
	zassert_not_equal(certparse_verify_chain(SZ(fx_other), NULL, NULL, 0, SZ(fx_root)), 0,
			  "an unrelated self-signed cert must NOT verify under root");
}

ZTEST(certparse, test_11_garbage_inputs_refused)
{
	const uint8_t junk[] = {0x00, 0x01, 0x02, 0x03};

	zassert_not_equal(certparse_verify_chain(SZ(junk), NULL, NULL, 0, SZ(fx_root)), 0,
			  "unparseable leaf must be refused");
	zassert_not_equal(certparse_verify_chain(SZ(fx_leaf), NULL, NULL, 0, SZ(junk)), 0,
			  "unparseable anchor must be refused");
}

ZTEST(certparse, test_12_bad_intermediate_is_skipped_not_fatal)
{
	/* Documented behaviour in both backends: an intermediate that cannot be
	 * used is ignored, and the chain still verifies via the good one. */
	const uint8_t junk[] = {0x30, 0x03, 0x01, 0x02, 0x03};
	const uint8_t *inter[] = {junk, fx_inter};
	const size_t ilen[] = {sizeof(junk), sizeof(fx_inter)};

	zassert_ok(certparse_verify_chain(SZ(fx_leaf), inter, ilen, 2, SZ(fx_root)),
		   "an unusable intermediate must not break a valid chain");
}

/*
 * Validity dates are deliberately NOT checked: the device has no RTC and
 * issues a synthetic window, so a date-enforcing verifier would refuse every
 * real Cantil certificate. fx_expired expired in 2021.
 */
ZTEST(certparse, test_13_expiry_is_ignored_by_design)
{
	const uint8_t *inter[] = {fx_inter};
	const size_t ilen[] = {sizeof(fx_inter)};

	zassert_ok(certparse_verify_chain(SZ(fx_expired), inter, ilen, 1, SZ(fx_root)),
		   "an expired leaf must still verify — no RTC on device");
}

ZTEST_SUITE(certparse, NULL, NULL, NULL, NULL, NULL);
