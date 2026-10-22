/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

/*
 * Slot 0 bootstrap conformance on native_sim.
 *
 * Drives ca.c + storage.c against the simulated flash partition declared in
 * boards/native_sim.overlay.  Each test starts from a known LittleFS state
 * thanks to suite_setup() (one-shot mkfs + mount) and test_before() (wipe
 * slot 0 + slot 1 directories so tests are order-independent).
 *
 * The flow under test, per AGENTS.md "Slot 0 bootstrap" finalized design:
 *   1. First boot, no key                  -> ca_init() writes NOTHING;
 *                                             ca_provision() writes key+meta,
 *                                             no cert, ca_ready() == false.
 *   2. Client pushes PUSH_KEY_X509(slot=0) -> self-signed cert emitted,
 *                                             ca_ready() == true.
 *   3. Bootstrap exemption                 -> 2nd push to protected slot 0
 *                                             after cert exists returns -EACCES.
 *   4. Crash recovery                      -> delete cert.der, re-run ca_init,
 *                                             cert regenerates from x509_data.bin.
 *   5. Idempotent re-init                  -> ca_init() with a fully-provisioned
 *                                             slot is a no-op.
 *   7. ca_provision() never overwrites     -> second call returns -EEXIST.
 *
 * Note the split in test 1. ca_init() used to provision when it found slot 0
 * empty; it no longer does, because an empty slot 0 is exactly what a
 * provisioned device looks like when its storage partition has been
 * misdeclared (unit #1, 2026-07-22). Minting a CA is now CMD_PROVISION_CA —
 * unlocked, authenticated, tap-confirmed — and ca_provision() is what it
 * calls.
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/fs/fs.h>
#include <string.h>
#include <errno.h>

#include "ca/certparse.h"

#include "ca/ca.h"
#include "storage/storage.h"
#include "test_artifacts.h"

#define LFS_MOUNT  "/lfs"
#define SLOT0_DIR  LFS_MOUNT "/keys/0"
#define SLOT0_KEY  SLOT0_DIR "/key.bin"
#define SLOT0_META SLOT0_DIR "/meta.bin"
#define SLOT0_X509 SLOT0_DIR "/x509_data.bin"
#define SLOT0_CERT SLOT0_DIR "/cert.der"

/* ── helpers ──────────────────────────────────────────────────────────── */

static int file_exists(const char *path)
{
	struct fs_dirent ent;
	int ret = fs_stat(path, &ent);

	if (ret == 0) {
		return 1;
	}
	if (ret == -ENOENT) {
		return 0;
	}
	return ret;
}

static void wipe_dir(const char *dir)
{
	struct fs_dir_t d;
	struct fs_dirent ent;
	char path[128];

	fs_dir_t_init(&d);
	if (fs_opendir(&d, dir) != 0) {
		return;
	}
	while (fs_readdir(&d, &ent) == 0 && ent.name[0] != '\0') {
		snprintf(path, sizeof(path), "%s/%s", dir, ent.name);
		fs_unlink(path);
	}
	fs_closedir(&d);
	fs_unlink(dir);
}

/* Build the flat x509-data blob accepted by ca_push_key_x509. */
static size_t build_x509_blob(uint8_t *out, size_t cap, uint16_t validity_days, bool is_ca,
			      uint8_t path_len, uint16_t key_usage, const char *cn, const char *o,
			      const char *c)
{
	size_t off = 0;

	zassert_true(cap >= 32, "blob buffer too small");
	out[off++] = (uint8_t)(validity_days >> 8);
	out[off++] = (uint8_t)(validity_days & 0xFF);
	out[off++] = is_ca ? 1 : 0;
	out[off++] = path_len;
	out[off++] = (uint8_t)(key_usage >> 8);
	out[off++] = (uint8_t)(key_usage & 0xFF);

#define APPEND(s)                                                                                  \
	do {                                                                                       \
		size_t n = (s) ? strlen(s) : 0;                                                    \
		zassert_true(off + 1 + n <= cap, "blob overflow");                                 \
		out[off++] = (uint8_t)n;                                                           \
		if (n) {                                                                           \
			memcpy(out + off, (s), n);                                                 \
			off += n;                                                                  \
		}                                                                                  \
	} while (0)
	APPEND(cn);
	APPEND(o);
	APPEND(NULL); /* ou */
	APPEND(c);
	APPEND(NULL); /* st */
	APPEND(NULL); /* l  */
#undef APPEND
	return off;
}

/* ── suite scaffolding ────────────────────────────────────────────────── */

static void *suite_setup(void)
{
	int ret = storage_init();

	zassert_ok(ret, "storage_init failed: %d", ret);

	/*
	 * A fresh native_sim volume has no identity marker, and minting is now
	 * refused on an unmarked, empty volume — that combination is what a
	 * misdeclared partition looks like. Mark it, which is exactly what the
	 * factory image does to real hardware before anything is provisioned.
	 */
	(void)storage_volume_marker_write();
	return NULL;
}

static void test_before(void *fixture)
{
	ARG_UNUSED(fixture);
	wipe_dir(SLOT0_DIR);
	wipe_dir(LFS_MOUNT "/keys/1");
}

ZTEST_SUITE(ca_bootstrap, NULL, suite_setup, test_before, NULL, NULL);

/* ── tests ────────────────────────────────────────────────────────────── */

ZTEST(ca_bootstrap, test_01_fresh_storage_provisions_key_only)
{
	/* ca_init() on an empty slot 0 must succeed and write nothing. It is
	 * not an error state — it is a device the factory image prepared — but
	 * it is also what a misdeclared partition looks like, so nothing is
	 * created without an explicit command. */
	zassert_ok(ca_init(), "ca_init first boot");
	zassert_false(ca_provisioned(), "ca_init must not create a key");
	zassert_equal(file_exists(SLOT0_KEY), 0, "ca_init must not write key.bin");
	zassert_equal(file_exists(SLOT0_META), 0, "ca_init must not write meta.bin");

	/* The explicit command does create it — key and meta only, no cert. */
	zassert_ok(ca_provision(0), "ca_provision");
	zassert_true(ca_provisioned(), "ca_provisioned after ca_provision");

	zassert_equal(file_exists(SLOT0_KEY), 1, "key.bin should exist");
	zassert_equal(file_exists(SLOT0_META), 1, "meta.bin should exist");
	zassert_equal(file_exists(SLOT0_X509), 0, "x509_data.bin must not exist yet");
	zassert_equal(file_exists(SLOT0_CERT), 0, "cert.der must not exist yet");
	zassert_false(ca_ready(), "ca_ready() should be false before PUSH_KEY_X509");
}

ZTEST(ca_bootstrap, test_07_provision_never_overwrites_an_existing_key)
{
	zassert_ok(ca_provision(0), "first provision");
	zassert_true(ca_provisioned(), "provisioned");

	/* Read the key blob so we can prove it is untouched afterwards. */
	uint8_t before[512];
	size_t before_len = sizeof(before);

	zassert_ok(storage_key_read(0, before, &before_len), "read key blob");
	zassert_true(before_len > 0, "key blob non-empty");

	/*
	 * ca_provision() is reachable from the wire now, so this is the last
	 * line between a request and unrecoverable key loss — the CA private
	 * key has no backup and cannot be exported. The dispatcher checks too;
	 * this asserts the check that does not depend on the dispatcher.
	 */
	zassert_equal(ca_provision(0), -EEXIST, "second ca_provision must return -EEXIST");

	uint8_t after[512];
	size_t after_len = sizeof(after);

	zassert_ok(storage_key_read(0, after, &after_len), "re-read key blob");
	zassert_equal(after_len, before_len, "key blob length changed");
	zassert_mem_equal(after, before, before_len, "key blob was overwritten");
}

ZTEST(ca_bootstrap, test_08_provision_rejects_unsupported_key_type)
{
	/* 0 means "the P-256 default"; anything else unknown is refused
	 * before a key is generated, so the slot stays empty and provisionable. */
	zassert_equal(ca_provision(0xEE), -ENOTSUP, "unknown key type");
	zassert_false(ca_provisioned(), "slot must stay empty after a rejected type");
	zassert_ok(ca_provision(0), "still provisionable afterwards");
}

ZTEST(ca_bootstrap, test_02_push_x509_emits_self_signed_cert)
{
	zassert_ok(ca_provision(0), "ca_provision");

	uint8_t blob[128];
	size_t blob_len = build_x509_blob(blob, sizeof(blob),
					  /* validity_days */ 365,
					  /* is_ca         */ true,
					  /* path_len      */ 0,
					  /* key_usage     */ 0,
					  /* cn */ "Test Root CA",
					  /* o  */ "cantil tests",
					  /* c  */ "CA");

	zassert_ok(ca_push_key_x509(0, blob, blob_len), "push_x509");
	zassert_equal(file_exists(SLOT0_X509), 1, "x509_data.bin written");
	zassert_equal(file_exists(SLOT0_CERT), 1, "cert.der written");
	zassert_true(ca_ready(), "ca_ready() true after push");

	/* Read back the cert and validate it is a well-formed self-signed CA
	 * cert with the fields we requested. The DER structure and the
	 * self-signature are checked independently by the OpenSSL gate
	 * (test_10_export_for_openssl_gate); here we read the field values with
	 * the firmware's own certparse seam. */
	uint8_t der[2048];
	size_t der_len = sizeof(der);

	zassert_ok(ca_get_cert(der, &der_len), "ca_get_cert");
	zassert_true(der_len > 0 && der_len < sizeof(der), "cert length sane: %zu", der_len);

	certparse_cert_t crt;

	zassert_ok(certparse_cert(der, der_len, &crt), "certparse");

	/* Self-signed: issuer DN bytes equal subject DN bytes. */
	zassert_true(crt.self_signed, "subject != issuer (not self-signed)");

	/* Basic constraints: cA = true. */
	zassert_true(crt.is_ca, "is_ca should be set");

	/* Key usage: ca.c forces KEY_CERT_SIGN | CRL_SIGN when is_ca=1. */
	zassert_true(crt.key_usage & CERTGEN_KU_KEY_CERT_SIGN,
		     "keyCertSign should be set on CA cert");
	zassert_true(crt.key_usage & CERTGEN_KU_CRL_SIGN, "cRLSign should be set on CA cert");
}

ZTEST(ca_bootstrap, test_03_second_push_to_protected_slot_returns_eacces)
{
	zassert_ok(ca_provision(0), "ca_provision");

	uint8_t blob[128];
	size_t blob_len =
		build_x509_blob(blob, sizeof(blob), 365, true, 0, 0, "Test Root CA", NULL, NULL);

	zassert_ok(ca_push_key_x509(0, blob, blob_len), "first push (bootstrap exempt)");
	zassert_true(ca_ready(), "ca_ready after first push");

	/* Cert now present; slot 0 is protected by default. Second push must
	 * be refused with -EACCES — the bootstrap exemption is one-shot. */
	int rc = ca_push_key_x509(0, blob, blob_len);

	zassert_equal(rc, -EACCES, "second push must return -EACCES, got %d", rc);
}

ZTEST(ca_bootstrap, test_04_crash_recovery_regenerates_cert)
{
	zassert_ok(ca_provision(0), "ca_provision");

	uint8_t blob[128];
	size_t blob_len =
		build_x509_blob(blob, sizeof(blob), 365, true, 0, 0, "Recovery CA", NULL, NULL);

	zassert_ok(ca_push_key_x509(0, blob, blob_len), "push_x509");
	zassert_equal(file_exists(SLOT0_CERT), 1, "cert.der present before crash");

	/* Simulate a crash between x509_data.bin write and cert.der write:
	 * blow away cert.der but keep key + meta + x509_data. */
	zassert_ok(fs_unlink(SLOT0_CERT), "unlink cert.der");
	zassert_equal(file_exists(SLOT0_CERT), 0, "cert.der absent");
	zassert_equal(file_exists(SLOT0_X509), 1, "x509_data.bin still present");

	/* Re-run ca_init — should detect the missing cert and regenerate. */
	zassert_ok(ca_init(), "ca_init after simulated crash");
	zassert_equal(file_exists(SLOT0_CERT), 1, "cert.der regenerated");
	zassert_true(ca_ready(), "ca_ready true after recovery");

	/* The regenerated cert must still parse. */
	uint8_t der[2048];
	size_t der_len = sizeof(der);

	zassert_ok(ca_get_cert(der, &der_len), "read regenerated cert");

	certparse_cert_t crt;

	zassert_ok(certparse_cert(der, der_len, &crt), "regenerated cert parse");
	zassert_true(crt.is_ca, "regenerated cert: is_ca");
}

ZTEST(ca_bootstrap, test_05_init_is_idempotent_when_fully_provisioned)
{
	zassert_ok(ca_provision(0), "ca_provision");

	uint8_t blob[128];
	size_t blob_len =
		build_x509_blob(blob, sizeof(blob), 365, true, 0, 0, "Idempotent CA", NULL, NULL);

	zassert_ok(ca_push_key_x509(0, blob, blob_len), "push_x509");

	/* Subsequent ca_init() calls with key+x509+cert all present must be
	 * no-ops: they should not regenerate, error, or change ca_ready. */
	zassert_ok(ca_init(), "ca_init #2");
	zassert_ok(ca_init(), "ca_init #3");
	zassert_true(ca_ready(), "ca_ready still true after repeated init");
}

ZTEST(ca_bootstrap, test_06_invalid_x509_data_rejected)
{
	zassert_ok(ca_provision(0), "ca_provision");

	/* Empty buffer. */
	zassert_equal(ca_push_key_x509(0, NULL, 0), -EINVAL, "NULL data should be -EINVAL");

	/* Truncated header (less than 6 bytes). */
	uint8_t too_short[3] = {0, 1, 0};

	zassert_equal(ca_push_key_x509(0, too_short, sizeof(too_short)), -EINVAL,
		      "short header should be -EINVAL");

	/* Valid header but CN length runs past end of buffer. */
	uint8_t bad_cn[8] = {0, 100, 1, 0, 0, 0, 20, 'X'};

	zassert_equal(ca_push_key_x509(0, bad_cn, sizeof(bad_cn)), -EINVAL,
		      "CN overrun should be -EINVAL");

	/* Valid header + empty CN — ca.c rejects this. */
	uint8_t empty_cn[12] = {0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0};

	zassert_equal(ca_push_key_x509(0, empty_cn, sizeof(empty_cn)), -EINVAL,
		      "empty CN should be -EINVAL");

	/* Slot 0 must remain unprovisioned at the x509 level. */
	zassert_equal(file_exists(SLOT0_X509), 0, "x509_data must not be written on invalid input");
	zassert_equal(file_exists(SLOT0_CERT), 0, "cert.der must not be written on invalid input");
	zassert_false(ca_ready(), "ca_ready must remain false");
}

ZTEST(ca_bootstrap, test_09_provision_refuses_on_an_unverified_volume)
{
	/*
	 * The state a device is in when its storage partition is misdeclared:
	 * mounted, slot 0 empty, and no way to prove whose volume this is. That
	 * is byte-for-byte how a factory-fresh device looks, which is why the
	 * refusal cannot come from inspecting the slot — it has to come from the
	 * marker. Before 2026-07-23 this call succeeded and the real CA, sitting
	 * at the offset this build was not looking at, was orphaned.
	 */
	zassert_ok(fs_unlink(LFS_MOUNT "/volume.bin"), "remove the marker");
	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_UNMARKED,
		      "volume must read as unmarked once the marker is gone");

	zassert_equal(ca_provision(0), -EPERM,
		      "ca_provision must refuse an unverified, empty volume");
	zassert_false(ca_provisioned(), "and must leave the slot alone");
	zassert_equal(file_exists(SLOT0_KEY), 0, "no key.bin may be written");

	/* Restore the suite's assumption for whatever runs next. */
	zassert_ok(storage_volume_marker_write(), "re-mark the volume");
	zassert_ok(ca_provision(0), "provisionable again once verified");
}

/*
 * Hand the freshly-minted root to the OpenSSL gate.
 *
 * test_02 above proves the root parses and carries the fields ca.c asked for,
 * but it proves that with the same library that wrote it. The root is the one
 * certificate whose self-signature nothing else ever checks — every issued
 * leaf is verified against the root's *public key*, never against the root's
 * own signature — so a malformed signature here would survive the entire
 * suite. Supplying it as both leaf and anchor makes the gate run
 * `verify -check_ss_sig`, which is a third implementation checking exactly
 * that (see scripts/openssl_gate.sh).
 */
ZTEST(ca_bootstrap, test_10_export_for_openssl_gate)
{
	zassert_ok(ca_provision(0), "ca_provision");

	uint8_t blob[128];
	size_t blob_len = build_x509_blob(blob, sizeof(blob),
					  /* validity_days */ 365,
					  /* is_ca         */ true,
					  /* path_len      */ 0,
					  /* key_usage     */ 0,
					  /* cn */ "Test Root CA",
					  /* o  */ "cantil tests",
					  /* c  */ "CA");

	zassert_ok(ca_push_key_x509(0, blob, blob_len), "push_x509");

	uint8_t der[2048];
	size_t der_len = sizeof(der);

	zassert_ok(ca_get_cert(der, &der_len), "ca_get_cert");

	test_artifact_leaf("root", der, der_len);
	test_artifact_ca("root", der, der_len);
}
