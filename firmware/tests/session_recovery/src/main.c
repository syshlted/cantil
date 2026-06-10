/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

/*
 * Strict-mode session-identity recovery (transport + pairing T-03).
 *
 * Built with CONFIG_CANTIL_SESSION_X509_STRICT=y (forced in this app's local
 * Kconfig). Confirms that session_slot_init():
 *   - does NOT enter recovery when the stored cert matches the build constant;
 *   - DOES latch recovery mode when a planted cert's identity fields differ.
 *
 * Because the recovery flag latches for the lifetime of the binary, both
 * assertions live in a single test so ordering is deterministic regardless of
 * how ztest schedules suites.
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/fs/fs.h>
#include <string.h>
#include <errno.h>

#include "session/session_slot.h"
#include "session/session_x509.h"
#include "ca/ca.h"
#include "crypto/crypto.h"
#include "storage/storage.h"

#define LFS_MOUNT     "/lfs"
#define SESSION_DIR   LFS_MOUNT "/session"
#define SESSION_CERT  SESSION_DIR "/cert.der"
#define NOISE_DIR     LFS_MOUNT "/noise"

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

/* First O-value byte offset: 6-byte header, [cn_len][cn], [o_len], O… */
static size_t blob_o_value_off(const uint8_t *blob)
{
	size_t off = 6;
	uint8_t cn_len = blob[off];

	off += 1 + cn_len + 1;
	return off;
}

static void *suite_setup(void)
{
	zassert_ok(storage_init(), "storage_init failed");
	wipe_dir(SESSION_DIR);
	wipe_dir(NOISE_DIR);
	return NULL;
}

ZTEST_SUITE(session_recovery, NULL, suite_setup, NULL, NULL, NULL);

ZTEST(session_recovery, test_strict_recovery_on_mismatch)
{
	/* Sanity: STRICT must actually be compiled in for this app. */
	zassert_true(IS_ENABLED(CONFIG_CANTIL_SESSION_X509_STRICT),
		     "this app must build with STRICT=y");

	/* 1. First boot writes the real (matching) identity. Re-init verifies it
	 *    and must NOT enter recovery. */
	zassert_ok(session_slot_init(), "first-boot init");
	zassert_ok(session_slot_init(), "verify-path init (matching)");
	zassert_false(session_slot_in_recovery(),
		      "matching identity must not trip recovery");

	/* 2. Overwrite cert.der with a cert whose O differs from the constant. */
	uint8_t blob[256];

	zassert_true(cantil_session_x509_constant_len <= sizeof(blob), "blob fits");
	memcpy(blob, cantil_session_x509_constant, cantil_session_x509_constant_len);
	blob[blob_o_value_off(blob)] ^= 0x20;  /* perturb O */

	uint8_t id_priv[64];
	size_t  id_len = sizeof(id_priv);

	zassert_ok(crypto_keygen(id_priv, &id_len), "P-256 keygen");
	zassert_equal(id_len, 32, "P-256 scalar is 32 bytes");

	uint8_t x25519_pub[32] = {0};
	uint8_t cert[2048];
	size_t  cert_len = sizeof(cert);

	zassert_ok(ca_build_session_cert(blob, cantil_session_x509_constant_len,
					 "Cantil", id_priv, x25519_pub,
					 cert, &cert_len),
		   "build mismatching cert");
	zassert_ok(storage_session_cert_write(cert, cert_len), "plant cert.der");

	/* 3. The verify path now sees a mismatch and, under strict mode, latches
	 *    recovery. Boot still returns OK so the device stays responsive to
	 *    DEVICE_STATUS / RESET_DEVICE. */
	zassert_ok(session_slot_init(), "init returns OK (recovery, not error)");
	zassert_true(session_slot_in_recovery(),
		     "strict mismatch must latch recovery mode");
}
