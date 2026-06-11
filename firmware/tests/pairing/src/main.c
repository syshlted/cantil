/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

/*
 * Pairing gate conformance on native_sim (transport + pairing T-16/T-17).
 *
 * Drives pairing.c + client_bond.c + storage.c against the simulated flash
 * partition.  Each test starts from a wiped /clients/ dir via before() so
 * order-independence holds.
 *
 * Method under test: PAIRING_TAP_CONFIRM (Method 2).
 * The gesture layer is stubbed in gesture_stub.c; tests control the outcome
 * via pairing_test_set_gesture_result().
 *
 * Coverage:
 *   1. Known bond → allowed immediately, no gesture prompt.
 *   2. Unknown client, user taps confirm → bonded, returns 0.
 *   3. Unknown client, user taps wrong sequence (DENIED) → -EACCES, not bonded.
 *   4. Unknown client, timeout → -EACCES, not bonded.
 *   5. Unknown client, cap full → -EACCES without any gesture prompt.
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/fs/fs.h>
#include <string.h>
#include <errno.h>

#include "clients/pairing.h"
#include "clients/client_bond.h"
#include "gesture/gesture.h"
#include "storage/storage.h"

#define LFS_MOUNT    "/lfs"
#define CLIENTS_DIR  LFS_MOUNT "/clients"

/* Declared in gesture_stub.c */
void pairing_test_set_gesture_result(cantil_confirm_result_t r);

/* Distinct synthetic Curve25519 pubkeys (first 4 bytes determine storage ID). */
static const uint8_t PUB_A[32] = {
	0xAA, 0x01, 0x02, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
static const uint8_t PUB_B[32] = {
	0xBB, 0x01, 0x02, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
static const uint8_t PUB_C[32] = {
	0xCC, 0x01, 0x02, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* ── helpers ────────────────────────────────────────────────────────────── */

static void rm_rf_dir(const char *path)
{
	struct fs_dir_t dir;
	struct fs_dirent ent;
	char child[128];

	fs_dir_t_init(&dir);
	if (fs_opendir(&dir, path) != 0)
		return;

	while (fs_readdir(&dir, &ent) == 0 && ent.name[0] != '\0') {
		snprintf(child, sizeof(child), "%s/%s", path, ent.name);
		if (ent.type == FS_DIR_ENTRY_DIR)
			rm_rf_dir(child);
		fs_unlink(child);
	}
	fs_closedir(&dir);
	fs_unlink(path);
}

/* ── suite setup / per-test reset ───────────────────────────────────────── */

static void *suite_setup(void)
{
	zassert_ok(storage_init(), "storage_init failed");
	return NULL;
}

static void before(void *unused)
{
	ARG_UNUSED(unused);
	rm_rf_dir(CLIENTS_DIR);
	/* Default gesture result: confirmed. Individual tests override as needed. */
	pairing_test_set_gesture_result(CANTIL_CONFIRM_OK);
}

ZTEST_SUITE(pairing, NULL, suite_setup, before, NULL, NULL);

/* ── test 1: already-bonded client is allowed (no gesture prompt) ─────── */

ZTEST(pairing, test_known_bond_allowed)
{
	/* Pre-bond PUB_A. */
	zassert_ok(client_bond_add(PUB_A, CLIENT_KIND_HOST, 0),
		   "setup: bond_add failed");

	/* pairing_check_and_bond should accept without prompting. */
	zassert_ok(pairing_check_and_bond(PUB_A, NULL), "known client rejected");

	/* Bond count must still be 1 (no duplicate). */
	uint32_t hosts = 0, peers = 0;

	zassert_ok(client_bond_count(&hosts, &peers), "bond_count failed");
	zassert_equal(hosts, 1, "expected 1 host bond, got %u", hosts);
}

/* ── test 2: unknown client, gesture confirmed → bonded ──────────────── */

ZTEST(pairing, test_unknown_client_tap_confirmed)
{
	pairing_test_set_gesture_result(CANTIL_CONFIRM_OK);

	zassert_equal(client_bond_exists(PUB_A), 0, "pre-condition: PUB_A bonded");

	zassert_ok(pairing_check_and_bond(PUB_A, NULL), "tap-confirmed bond failed");

	zassert_equal(client_bond_exists(PUB_A), 1,
		      "bond not persisted after tap-confirm");
}

/* ── test 3: unknown client, gesture denied → rejected, not bonded ────── */

ZTEST(pairing, test_unknown_client_tap_denied)
{
	pairing_test_set_gesture_result(CANTIL_CONFIRM_DENIED);

	int rc = pairing_check_and_bond(PUB_A, NULL);

	zassert_equal(rc, -EACCES,
		      "expected -EACCES on denied gesture, got %d", rc);

	zassert_equal(client_bond_exists(PUB_A), 0,
		      "PUB_A was bonded despite denial");
}

/* ── test 4: unknown client, gesture timeout → rejected, not bonded ───── */

ZTEST(pairing, test_unknown_client_tap_timeout)
{
	pairing_test_set_gesture_result(CANTIL_CONFIRM_TIMEOUT);

	int rc = pairing_check_and_bond(PUB_A, NULL);

	zassert_equal(rc, -EACCES,
		      "expected -EACCES on gesture timeout, got %d", rc);

	zassert_equal(client_bond_exists(PUB_A), 0,
		      "PUB_A was bonded despite timeout");
}

/* ── test 5: cap full → unknown client rejected without gesture ────────── */

ZTEST(pairing, test_cap_full_rejected)
{
	/* Fill to CONFIG_CANTIL_MAX_CLIENT_BONDS (=2 in prj.conf). */
	zassert_ok(client_bond_add(PUB_A, CLIENT_KIND_HOST, 0), "bond A failed");
	zassert_ok(client_bond_add(PUB_B, CLIENT_KIND_HOST, 0), "bond B failed");

	/* Third unknown client must be rejected without prompting. */
	int rc = pairing_check_and_bond(PUB_C, NULL);

	zassert_equal(rc, -EACCES,
		      "expected -EACCES when cap full, got %d", rc);

	zassert_equal(client_bond_exists(PUB_C), 0,
		      "PUB_C was bonded despite cap");
}
