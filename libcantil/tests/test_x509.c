/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

/*
 * Conformance tests for the src/x509.h backend seam (step 5 of
 * docs/roadmap/wolfssl-migration.md).
 *
 * The same binary is built once per backend (test_x509_openssl,
 * test_x509_wolfssl) and every one of them must produce identical answers. That
 * is the point: a seam whose implementations disagree is worse than no seam,
 * because the disagreement only shows up as a trust decision that silently flips
 * when someone rebuilds the client with a different -D.
 *
 * The expectations are hardcoded golden values, not cross-comparisons between
 * backends. Two backends agreeing on the wrong answer is a real outcome —
 * the subject-DER case below is exactly where it would happen — so each is
 * checked against a value derived independently, with the openssl CLI (see
 * gen_fixtures.sh). Note the openssl backend now shares a library *family* with
 * that oracle, so wolfSSL is what keeps the golden values honest across
 * implementations; the openssl CLI and libcrypto are still distinct code paths
 * (asn1parse vs i2d_X509_NAME), but the strong cross-check is the wolfSSL run.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "x509.h"
#include "fixtures.h"

static int failures;
static int checks;

#define CHECK(cond, fmt, ...) do {                                          \
	checks++;                                                           \
	if (!(cond)) {                                                      \
		failures++;                                                 \
		printf("  FAIL %s:%d: " fmt "\n",                           \
		       __FILE__, __LINE__, ##__VA_ARGS__);                  \
	}                                                                   \
} while (0)

#define SZ(x) (x), sizeof(x)

/*
 * The leaf's subject DN as a complete DER element, taken from the fixture with
 * the openssl CLI. Both backends must return exactly this — including the
 * leading 0x30 0x71 header.
 *
 * This is the case that justifies the whole test file. mbedTLS's subject_raw
 * spans the full TLV; wolfSSL's subjectRaw points past the tag and length at
 * the contents. A backend that returns the contents alone would still look
 * perfectly reasonable in isolation, still be self-consistent, and still
 * break every Tier 2 subject pin made by a client built the other way.
 */
static const unsigned char golden_subject[] = {
	0x30, 0x71, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
	0x13, 0x43, 0x61, 0x6e, 0x74, 0x69, 0x6c, 0x2d, 0x54, 0x45, 0x53, 0x54,
	0x53, 0x45, 0x52, 0x49, 0x41, 0x4c, 0x30, 0x31, 0x31, 0x0f, 0x30, 0x0d,
	0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06, 0x43, 0x61, 0x6e, 0x74, 0x69,
	0x6c, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x07,
	0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x31, 0x0b, 0x30, 0x09, 0x06,
	0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x41, 0x31, 0x10, 0x30, 0x0e,
	0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x07, 0x4f, 0x6e, 0x74, 0x61, 0x72,
	0x69, 0x6f, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c,
	0x06, 0x4f, 0x74, 0x74, 0x61, 0x77, 0x61,
};

/* ── subject DER ─────────────────────────────────────────────────────────── */

static void test_subject_der(void)
{
	uint8_t buf[CANTIL_X509_SUBJECT_MAX];
	size_t  len = 0;

	int rc = cantil_x509_subject_der(SZ(fx_leaf), buf, sizeof(buf), &len);

	CHECK(rc == CANTIL_X509_OK, "subject_der rc=%d", rc);
	CHECK(len == sizeof(golden_subject),
	      "subject_der len=%zu want=%zu", len, sizeof(golden_subject));
	if (len == sizeof(golden_subject))
		CHECK(memcmp(buf, golden_subject, len) == 0,
		      "subject_der bytes differ from the golden DN (len=%zu)", len);

	/* Spelled out separately so a failure says *which* invariant broke. */
	CHECK(len >= 2 && buf[0] == 0x30,
	      "subject_der must start with the SEQUENCE tag, got 0x%02x", buf[0]);
}

static void test_subject_der_too_small(void)
{
	uint8_t small[8];
	size_t  len = 0;

	int rc = cantil_x509_subject_der(SZ(fx_leaf), small, sizeof(small), &len);

	CHECK(rc == CANTIL_X509_ERR_SPACE, "short buffer rc=%d", rc);
}

static void test_subject_der_garbage(void)
{
	const uint8_t junk[] = { 0x30, 0x82, 0xff, 0xff, 0x00, 0x01, 0x02 };
	uint8_t buf[CANTIL_X509_SUBJECT_MAX];
	size_t  len = 0;

	int rc = cantil_x509_subject_der(SZ(junk), buf, sizeof(buf), &len);

	CHECK(rc == CANTIL_X509_ERR_PARSE, "garbage rc=%d", rc);
}

/* ── subject CN ──────────────────────────────────────────────────────────── */

static void test_subject_cn(void)
{
	char cn[128];

	int rc = cantil_x509_subject_cn(SZ(fx_leaf), cn, sizeof(cn));

	CHECK(rc == CANTIL_X509_OK, "subject_cn rc=%d", rc);
	if (rc == CANTIL_X509_OK)
		CHECK(strcmp(cn, "Cantil-TESTSERIAL01") == 0,
		      "subject_cn = \"%s\"", cn);
}

static void test_subject_cn_of_ca(void)
{
	char cn[128];

	int rc = cantil_x509_subject_cn(SZ(fx_root), cn, sizeof(cn));

	CHECK(rc == CANTIL_X509_OK, "root subject_cn rc=%d", rc);
	if (rc == CANTIL_X509_OK)
		CHECK(strcmp(cn, "Cantil Test Root") == 0,
		      "root subject_cn = \"%s\"", cn);
}

static void test_subject_cn_too_small(void)
{
	char tiny[4];

	int rc = cantil_x509_subject_cn(SZ(fx_leaf), tiny, sizeof(tiny));

	CHECK(rc == CANTIL_X509_ERR_SPACE, "short CN buffer rc=%d", rc);
}

/* ── chain verification ──────────────────────────────────────────────────── */

static void test_chain_via_intermediate(void)
{
	const uint8_t *inter[] = { fx_inter };
	const size_t   ilen[]  = { sizeof(fx_inter) };

	int rc = cantil_x509_verify_chain(SZ(fx_leaf), inter, ilen, 1,
					  SZ(fx_root));

	CHECK(rc == CANTIL_X509_OK, "leaf->inter->root rc=%d", rc);
}

static void test_chain_missing_intermediate(void)
{
	/* The leaf is signed by the sub-CA, so the root alone cannot verify it.
	 * A backend that returned OK here would be trusting an incomplete
	 * chain — the failure mode that matters most. */
	int rc = cantil_x509_verify_chain(SZ(fx_leaf), NULL, NULL, 0,
					  SZ(fx_root));

	CHECK(rc == CANTIL_X509_ERR_CHAIN, "leaf->root (gap) rc=%d", rc);
}

static void test_chain_wrong_anchor(void)
{
	const uint8_t *inter[] = { fx_inter };
	const size_t   ilen[]  = { sizeof(fx_inter) };

	int rc = cantil_x509_verify_chain(SZ(fx_leaf), inter, ilen, 1,
					  SZ(fx_other));

	CHECK(rc == CANTIL_X509_ERR_CHAIN, "unrelated anchor rc=%d", rc);
}

static void test_chain_intermediate_directly(void)
{
	/* The sub-CA is signed by the root, so it verifies with no
	 * intermediates of its own. */
	int rc = cantil_x509_verify_chain(SZ(fx_inter), NULL, NULL, 0,
					  SZ(fx_root));

	CHECK(rc == CANTIL_X509_OK, "inter->root rc=%d", rc);
}

static void test_chain_ignores_expiry(void)
{
	/* Deliberate policy, not an oversight: the device has no RTC and issues
	 * a synthetic validity window, so enforcing dates would reject every
	 * real Cantil certificate. */
	const uint8_t *inter[] = { fx_inter };
	const size_t   ilen[]  = { sizeof(fx_inter) };

	int rc = cantil_x509_verify_chain(SZ(fx_expired), inter, ilen, 1,
					  SZ(fx_root));

	CHECK(rc == CANTIL_X509_OK, "expired leaf rc=%d (dates must be ignored)",
	      rc);
}

static void test_chain_rejects_non_p256(void)
{
	/*
	 * An RSA chain is perfectly valid X.509 and would verify anywhere; it is
	 * outside Cantil's P-256/SHA-256 profile, so both backends must refuse
	 * it. mbedTLS gets this from its profile struct, wolfSSL from the
	 * explicit OID check in x509_wolfssl.c — which is why the case exists.
	 *
	 * Refusal is asserted, not a specific code. The two backends reach it by
	 * different routes: mbedTLS parses the certificate and then rejects it on
	 * policy (ERR_CHAIN), while a host wolfSSL built without RSA — which
	 * scripts/setup_wolfssl_host.sh does, since Cantil has no use for it —
	 * cannot decode the key at all and stops at ERR_PARSE. Pinning one code
	 * here would be asserting a property of the *build configuration* rather
	 * than of the seam. What the seam guarantees is that this never returns
	 * CANTIL_X509_OK.
	 */
	int rc = cantil_x509_verify_chain(SZ(fx_rsa_leaf), NULL, NULL, 0,
					  SZ(fx_rsa_root));

	CHECK(rc != CANTIL_X509_OK, "RSA chain rc=%d (must be refused)", rc);
}

static void test_chain_garbage_inputs(void)
{
	const uint8_t junk[] = { 0x00, 0x01, 0x02, 0x03 };

	int rc = cantil_x509_verify_chain(SZ(junk), NULL, NULL, 0, SZ(fx_root));
	CHECK(rc == CANTIL_X509_ERR_PARSE, "garbage leaf rc=%d", rc);

	rc = cantil_x509_verify_chain(SZ(fx_leaf), NULL, NULL, 0, SZ(junk));
	CHECK(rc == CANTIL_X509_ERR_PARSE, "garbage anchor rc=%d", rc);
}

static void test_chain_tolerates_bad_intermediate(void)
{
	/* An unparseable intermediate is skipped, not fatal — the device may
	 * ship a chain element this client cannot use, and the chain can still
	 * verify without it. Both backends document this behaviour. */
	const uint8_t junk[] = { 0x30, 0x03, 0x01, 0x02, 0x03 };
	const uint8_t *inter[] = { junk, fx_inter };
	const size_t   ilen[]  = { sizeof(junk), sizeof(fx_inter) };

	int rc = cantil_x509_verify_chain(SZ(fx_leaf), inter, ilen, 2,
					  SZ(fx_root));

	CHECK(rc == CANTIL_X509_OK, "bad intermediate should be skipped, rc=%d",
	      rc);
}

int main(void)
{
	printf("x509 backend: %s\n", cantil_x509_backend_name());

	test_subject_der();
	test_subject_der_too_small();
	test_subject_der_garbage();
	test_subject_cn();
	test_subject_cn_of_ca();
	test_subject_cn_too_small();
	test_chain_via_intermediate();
	test_chain_missing_intermediate();
	test_chain_wrong_anchor();
	test_chain_intermediate_directly();
	test_chain_ignores_expiry();
	test_chain_rejects_non_p256();
	test_chain_garbage_inputs();
	test_chain_tolerates_bad_intermediate();

	printf("%s: %d checks, %d failures\n",
	       failures ? "FAIL" : "PASS", checks, failures);
	return failures ? 1 : 0;
}
