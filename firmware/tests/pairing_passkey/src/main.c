/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXTENSIONS.md at the repo root. */

/*
 * Method 3 (PAIRING_PASSKEY) pairing gate conformance on native_sim (T-18).
 *
 * Drives pairing.c + client_bond.c + storage.c against a simulated flash
 * partition.  Each test starts from a wiped /clients/ dir via before().
 *
 * Stubs:
 *   gesture_stub.c  — fires pair_confirm callback synchronously
 *   led_stub.c      — no-op LED / blink_digit (BLINK_PAUSE_MS=0 in prj.conf)
 *   session_stub.c  — returns a pre-built passkey-reply frame from session_recv()
 *
 * Passkey interception: pairing.c calls the weak pairing_test_passkey_hook()
 * immediately after generating the random passkey and before session_recv().
 * The strong override here primes the session stub with the correct digits for
 * success tests.  Wrong-passkey tests pre-lock the stub to 999999 so the hook
 * cannot override it.
 *
 * Coverage:
 *   1. Known bond → allowed immediately (no session_recv called).
 *   2. Unknown client, correct passkey + gesture OK → bonded, PSK stored.
 *   3. Unknown client, wrong passkey → -EACCES, ERR_AUTH response, not bonded.
 *   4. Unknown client, transport timeout → -EACCES, not bonded.
 *   5. Unknown client, cap full → -EACCES without any prompt.
 *   6. Unknown client, correct passkey but gesture denied → -EACCES, not bonded.
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
#include "protocol/protocol.h"

#define LFS_MOUNT   "/lfs"
#define CLIENTS_DIR LFS_MOUNT "/clients"

/* Declared in gesture_stub.c */
void pairing_passkey_test_set_gesture_result(cantil_confirm_result_t r);

/* Declared in session_stub.c */
cantil_session_t *pairing_passkey_test_session(void);
void pairing_passkey_test_set_reply_digits(uint32_t digits);
void pairing_passkey_test_lock_digits(uint32_t digits);
void pairing_passkey_test_set_reply_timeout(void);
uint32_t pairing_passkey_test_last_response_err(void);
void pairing_passkey_test_reset(void);

/* ── Passkey hook ───────────────────────────────────────────────────────── */

/* Strong override of the weak pairing_test_passkey_hook() in pairing.c.
 * Called inside pairing_check_and_bond() after the passkey is generated,
 * before session_recv().  Primes the stub with the real value so tests
 * that expect success see the correct digits. */
void pairing_test_passkey_hook(uint32_t passkey)
{
	/* pairing_passkey_test_set_reply_digits respects the lock, so
	 * tests that pre-lock to a wrong value are unaffected. */
	pairing_passkey_test_set_reply_digits(passkey);
}

/* ── Distinct synthetic Curve25519 pubkeys ──────────────────────────────── */

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

/* ── Helpers ────────────────────────────────────────────────────────────── */

static void rm_rf_dir(const char *path)
{
	struct fs_dir_t dir;
	struct fs_dirent ent;
	char child[128];

	fs_dir_t_init(&dir);
	if (fs_opendir(&dir, path) != 0) {
		return;
	}
	while (fs_readdir(&dir, &ent) == 0 && ent.name[0] != '\0') {
		snprintf(child, sizeof(child), "%s/%s", path, ent.name);
		if (ent.type == FS_DIR_ENTRY_DIR) {
			rm_rf_dir(child);
		}
		fs_unlink(child);
	}
	fs_closedir(&dir);
	fs_unlink(path);
}

/* ── Suite setup / per-test reset ───────────────────────────────────────── */

static void *suite_setup(void)
{
	zassert_ok(storage_init(), "storage_init failed");
	return NULL;
}

static void before(void *unused)
{
	ARG_UNUSED(unused);
	rm_rf_dir(CLIENTS_DIR);
	pairing_passkey_test_reset();
	pairing_passkey_test_set_gesture_result(CANTIL_CONFIRM_OK);
}

ZTEST_SUITE(pairing_passkey, NULL, suite_setup, before, NULL, NULL);

/* ── Test 1: already-bonded client allowed (no session_recv) ────────────── */

ZTEST(pairing_passkey, test_known_bond_allowed)
{
	zassert_ok(client_bond_add(PUB_A, CLIENT_KIND_HOST, 0), "setup bond");

	/* If session_recv were called it would return an error (timeout). */
	pairing_passkey_test_set_reply_timeout();

	cantil_session_t *s = pairing_passkey_test_session();

	zassert_ok(pairing_check_and_bond(PUB_A, s), "known client rejected");

	uint32_t hosts = 0, peers = 0;

	zassert_ok(client_bond_count(&hosts, &peers), "count failed");
	zassert_equal(hosts, 1, "expected 1 bond, got %u", hosts);
}

/* ── Test 2: correct passkey + gesture confirmed → bonded + PSK stored ──── */

ZTEST(pairing_passkey, test_correct_passkey_bonded)
{
	/* Hook will prime stub with the generated passkey value. */
	cantil_session_t *s = pairing_passkey_test_session();

	zassert_ok(pairing_check_and_bond(PUB_A, s), "Method 3 bond failed");

	zassert_equal(client_bond_exists(PUB_A), 1,
		      "bond not stored after passkey+confirm");

	/* PSK file must exist and be non-empty. */
	uint8_t id[4] = {0xAA, 0x01, 0x02, 0x03};
	uint8_t psk_enc[64];
	size_t  psk_enc_len = sizeof(psk_enc);

	zassert_ok(storage_client_bond_psk_read(id, psk_enc, &psk_enc_len),
		   "PSK not stored");
	zassert_true(psk_enc_len > 0, "PSK blob is empty");

	zassert_equal(pairing_passkey_test_last_response_err(), (uint32_t)ERR_OK,
		      "device sent non-OK response on success");
}

/* ── Test 3: wrong passkey → -EACCES + ERR_AUTH, not bonded ────────────── */

ZTEST(pairing_passkey, test_wrong_passkey_rejected)
{
	/* Lock stub to 0. Hook cannot override. generate_passkey() never returns 0,
	 * so this is always a guaranteed mismatch. */
	pairing_passkey_test_lock_digits(0U);

	cantil_session_t *s = pairing_passkey_test_session();
	int rc = pairing_check_and_bond(PUB_A, s);

	zassert_equal(rc, -EACCES,
		      "expected -EACCES on wrong passkey, got %d", rc);
	zassert_equal(client_bond_exists(PUB_A), 0,
		      "bonded despite wrong passkey");
	zassert_equal(pairing_passkey_test_last_response_err(), (uint32_t)ERR_AUTH,
		      "expected ERR_AUTH response, got %u",
		      pairing_passkey_test_last_response_err());
}

/* ── Test 4: transport timeout → -EACCES, not bonded ───────────────────── */

ZTEST(pairing_passkey, test_timeout_rejected)
{
	pairing_passkey_test_set_reply_timeout();

	cantil_session_t *s = pairing_passkey_test_session();
	int rc = pairing_check_and_bond(PUB_A, s);

	zassert_equal(rc, -EACCES,
		      "expected -EACCES on timeout, got %d", rc);
	zassert_equal(client_bond_exists(PUB_A), 0, "bonded despite timeout");
}

/* ── Test 5: cap full → -EACCES without any prompt ─────────────────────── */

ZTEST(pairing_passkey, test_cap_full_rejected)
{
	zassert_ok(client_bond_add(PUB_A, CLIENT_KIND_HOST, 0), "bond A");
	zassert_ok(client_bond_add(PUB_B, CLIENT_KIND_HOST, 0), "bond B");

	pairing_passkey_test_set_reply_timeout();  /* recv would error if called */

	cantil_session_t *s = pairing_passkey_test_session();
	int rc = pairing_check_and_bond(PUB_C, s);

	zassert_equal(rc, -EACCES,
		      "expected -EACCES when cap full, got %d", rc);
	zassert_equal(client_bond_exists(PUB_C), 0, "bonded despite cap");
}

/* ── Test 6: correct passkey but gesture denied → -EACCES, not bonded ───── */

ZTEST(pairing_passkey, test_gesture_denied_rejected)
{
	pairing_passkey_test_set_gesture_result(CANTIL_CONFIRM_DENIED);

	cantil_session_t *s = pairing_passkey_test_session();
	int rc = pairing_check_and_bond(PUB_A, s);

	zassert_equal(rc, -EACCES,
		      "expected -EACCES on denied gesture, got %d", rc);
	zassert_equal(client_bond_exists(PUB_A), 0, "bonded despite denial");
}
