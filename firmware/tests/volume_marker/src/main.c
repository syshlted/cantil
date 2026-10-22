/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

/*
 * Volume identity marker conformance on native_sim.
 *
 * The marker exists because of a failure that code inspection did not catch
 * and only destructive hardware testing found (2026-07-22): a misdeclared
 * storage partition mounted cleanly over live data, presented as an empty
 * volume, and induced ca_init() to mint a replacement root CA. No format was
 * involved, so the auto-format guard could not see it.
 *
 * These tests cover the verification logic that closes that hole:
 *
 *   1. A freshly formatted volume reports UNMARKED, not VALID — absence of a
 *      marker must never be read as approval.
 *   2. A written marker verifies VALID and round-trips its fields.
 *   3. The marker cannot be silently replaced. One that can be rewritten to
 *      agree with whatever partition is mounted asserts nothing.
 *   4. Each corruption route is detected separately: torn/short write, bad
 *      CRC, foreign magic, future layout version, wrong partition offset,
 *      wrong partition size, and a different die.
 *   5. A secure wipe preserves the marker. The keys are gone; the claim
 *      "this volume belongs to this die at this offset" is still true, and
 *      dropping it would make a wiped device indistinguishable from one with
 *      a misdeclared partition.
 *   6. The states restrain something. Detection without enforcement is what
 *      shipped on 2026-07-23: a mismatched volume was logged and then used
 *      exactly as if it had verified. Tests 17-21 cover the two gates
 *      (storage_volume_trusted / storage_volume_may_mint) and the refusals
 *      they drive.
 *
 * The offset/size cases are the ones that map directly onto the hardware
 * incident, so they assert MISMATCH rather than merely "not VALID".
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/fs/fs.h>
#include <zephyr/sys/crc.h>
#include <string.h>
#include <errno.h>

#include "storage/storage.h"
#include "crypto/crypto.h"

#define LFS_MOUNT   "/lfs"
#define MARKER_PATH LFS_MOUNT "/volume.bin"

/* Mirrors boards/native_sim.overlay's storage_partition. Hard-coded on
 * purpose: if the overlay changes, these tests should fail loudly rather than
 * quietly re-derive and keep passing. */
#define EXPECT_OFFSET 0x00180000
#define EXPECT_SIZE   0x00080000

/* ── helpers ──────────────────────────────────────────────────────────── */

static int marker_read_raw(struct storage_volume_marker *m)
{
	struct fs_file_t f;
	int ret;

	fs_file_t_init(&f);
	ret = fs_open(&f, MARKER_PATH, FS_O_READ);
	if (ret) {
		return ret;
	}

	ssize_t n = fs_read(&f, m, sizeof(*m));

	fs_close(&f);
	if (n < 0) {
		return (int)n;
	}
	return (n == (ssize_t)sizeof(*m)) ? 0 : -EIO;
}

/* Write raw bytes over the marker, bypassing storage_volume_marker_write()'s
 * refusal to replace — that refusal is what test 3 checks, and every
 * corruption test needs to get underneath it. */
static void marker_write_raw(const void *buf, size_t len)
{
	struct fs_file_t f;

	fs_file_t_init(&f);
	zassert_ok(fs_open(&f, MARKER_PATH, FS_O_WRITE | FS_O_CREATE | FS_O_TRUNC),
		   "open marker for raw write");
	zassert_equal(fs_write(&f, buf, len), (ssize_t)len, "raw marker write");
	zassert_ok(fs_close(&f), "close marker");
}

static void marker_recrc(struct storage_volume_marker *m)
{
	m->crc32 = crc32_ieee((const uint8_t *)m, offsetof(struct storage_volume_marker, crc32));
}

/* Read the good marker, hand it to the caller to damage, write it back. */
static void marker_mutate(void (*damage)(struct storage_volume_marker *))
{
	struct storage_volume_marker m;

	zassert_ok(marker_read_raw(&m), "read marker before mutating");
	damage(&m);
	marker_write_raw(&m, sizeof(m));
}

/* ── suite scaffolding ────────────────────────────────────────────────── */

static void *suite_setup(void)
{
	zassert_ok(storage_init(), "storage_init failed");
	return NULL;
}

/*
 * Every test begins from "mounted, no marker". Tests that want one write it
 * themselves, so nothing depends on execution order.
 */
static void test_before(void *fixture)
{
	ARG_UNUSED(fixture);
	(void)fs_unlink(MARKER_PATH);
	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_UNMARKED,
		      "expected a clean unmarked volume before each test");
}

/*
 * Restore a good marker after every test. native_sim keeps its flash in a
 * single flash.bin at the repo root, shared by every suite and by every later
 * run, and most of the tests here deliberately write a marker that contradicts
 * the build. Before enforcement that residue was inert; now a suite that ended
 * on a damaged marker would put every subsequent suite into degraded mode and
 * fail it — which is the enforcement working, at the wrong target.
 */
static void test_after(void *fixture)
{
	ARG_UNUSED(fixture);
	(void)fs_unlink(MARKER_PATH);
	zassert_ok(storage_volume_marker_write(), "restore a good marker");
}

ZTEST_SUITE(volume_marker, NULL, suite_setup, test_before, test_after, NULL);

/* ── tests ────────────────────────────────────────────────────────────── */

ZTEST(volume_marker, test_01_fresh_volume_is_unmarked)
{
	/* The central negative: a volume with no marker must never verify. */
	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_UNMARKED,
		      "a volume with no marker must not verify as valid");
	zassert_equal(storage_volume_state(), STORAGE_VOLUME_UNMARKED,
		      "cached state should track the verify result");
}

ZTEST(volume_marker, test_02_write_then_verify)
{
	zassert_ok(storage_volume_marker_write(), "marker write");
	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_VALID,
		      "freshly written marker must verify");
}

ZTEST(volume_marker, test_03_fields_match_this_build_and_die)
{
	struct storage_volume_marker m;
	uint8_t id[8];

	zassert_ok(storage_volume_marker_write(), "marker write");
	zassert_ok(marker_read_raw(&m), "read back marker");

	zassert_equal(m.magic, CANTIL_VOLUME_MAGIC, "magic");
	zassert_equal(m.version, CANTIL_VOLUME_VERSION, "version");
	zassert_equal(m.reserved, 0, "reserved must be zeroed for future use");
	zassert_equal(m.partition_offset, EXPECT_OFFSET, "partition offset");
	zassert_equal(m.partition_size, EXPECT_SIZE, "partition size");

	crypto_device_id(id);
	zassert_mem_equal(m.device_id, id, sizeof(id), "device id");

	uint32_t crc =
		crc32_ieee((const uint8_t *)&m, offsetof(struct storage_volume_marker, crc32));
	zassert_equal(m.crc32, crc, "stored CRC must cover the record");
}

ZTEST(volume_marker, test_04_marker_is_inline_sized)
{
	/* Keeps the marker inside a littlefs metadata pair, so it carries the
	 * same 2x redundancy as the key blobs. A marker lost to a single bad
	 * block would strand a perfectly good volume. */
	zassert_true(sizeof(struct storage_volume_marker) <= CANTIL_KEY_BLOB_LEN,
		     "marker (%zu B) must stay within the littlefs inline "
		     "threshold to keep its redundancy",
		     sizeof(struct storage_volume_marker));
}

ZTEST(volume_marker, test_05_write_refuses_to_replace)
{
	zassert_ok(storage_volume_marker_write(), "first write");
	zassert_equal(storage_volume_marker_write(), -EEXIST, "replacing a marker must be refused");
}

ZTEST(volume_marker, test_06_replace_attempt_leaves_original_intact)
{
	struct storage_volume_marker before, after;

	zassert_ok(storage_volume_marker_write(), "first write");
	zassert_ok(marker_read_raw(&before), "read original");

	(void)storage_volume_marker_write();

	zassert_ok(marker_read_raw(&after), "read after refused write");
	zassert_mem_equal(&before, &after, sizeof(before),
			  "refused write must not have modified the marker");
	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_VALID,
		      "marker must still verify after a refused replace");
}

ZTEST(volume_marker, test_07_short_marker_rejected)
{
	struct storage_volume_marker m;

	zassert_ok(storage_volume_marker_write(), "marker write");
	zassert_ok(marker_read_raw(&m), "read marker");

	/* A torn write — power lost mid-update. */
	marker_write_raw(&m, sizeof(m) - 4);

	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_MISMATCH,
		      "a truncated marker must not verify");
}

static void damage_crc(struct storage_volume_marker *m)
{
	m->crc32 ^= 0xFFFFFFFFU;
}

ZTEST(volume_marker, test_08_bad_crc_rejected)
{
	zassert_ok(storage_volume_marker_write(), "marker write");
	marker_mutate(damage_crc);

	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_MISMATCH,
		      "a marker failing its CRC must not verify");
}

static void damage_magic(struct storage_volume_marker *m)
{
	m->magic = 0xDEADBEEFU;
	marker_recrc(m);
}

ZTEST(volume_marker, test_09_foreign_magic_rejected)
{
	zassert_ok(storage_volume_marker_write(), "marker write");
	marker_mutate(damage_magic);

	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_MISMATCH,
		      "a file that is not a Cantil marker must not verify");
}

static void damage_version(struct storage_volume_marker *m)
{
	m->version = CANTIL_VOLUME_VERSION + 1;
	marker_recrc(m);
}

ZTEST(volume_marker, test_10_future_version_rejected)
{
	/* Refuse rather than guess: fields may have moved, and acting on a
	 * misread marker is worse than having none. */
	zassert_ok(storage_volume_marker_write(), "marker write");
	marker_mutate(damage_version);

	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_MISMATCH,
		      "a newer layout than this firmware understands must not "
		      "verify");
}

static void damage_offset(struct storage_volume_marker *m)
{
	m->partition_offset = EXPECT_OFFSET + 0x1000;
	marker_recrc(m);
}

ZTEST(volume_marker, test_11_wrong_offset_rejected)
{
	/*
	 * The hardware incident, in miniature. A filesystem reached at the
	 * wrong offset mounts and looks merely empty; only the recorded offset
	 * distinguishes it from a blank device.
	 */
	zassert_ok(storage_volume_marker_write(), "marker write");
	marker_mutate(damage_offset);

	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_MISMATCH,
		      "a marker created for a different offset must not verify");
}

static void damage_size(struct storage_volume_marker *m)
{
	m->partition_size = EXPECT_SIZE / 2;
	marker_recrc(m);
}

ZTEST(volume_marker, test_12_wrong_size_rejected)
{
	zassert_ok(storage_volume_marker_write(), "marker write");
	marker_mutate(damage_size);

	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_MISMATCH,
		      "a marker created for a different partition size must "
		      "not verify");
}

static void damage_device_id(struct storage_volume_marker *m)
{
	m->device_id[0] ^= 0xFF;
	marker_recrc(m);
}

ZTEST(volume_marker, test_13_foreign_device_rejected)
{
	/* A flash image cloned onto another die. The AEAD-encrypted secrets
	 * would not decrypt here anyway; the marker names the cause instead of
	 * leaving a pile of GCM failures to interpret. */
	zassert_ok(storage_volume_marker_write(), "marker write");
	marker_mutate(damage_device_id);

	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_MISMATCH,
		      "a volume belonging to another die must not verify");
}

ZTEST(volume_marker, test_14_secure_wipe_preserves_marker)
{
	struct storage_volume_marker before, after;

	zassert_ok(storage_volume_marker_write(), "marker write");
	zassert_ok(marker_read_raw(&before), "read marker before wipe");

	zassert_ok(storage_secure_wipe(), "secure wipe");

	zassert_ok(marker_read_raw(&after), "marker must survive a wipe");
	zassert_mem_equal(&before, &after, sizeof(before), "wipe must not alter the marker");
	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_VALID,
		      "a wiped device still owns its volume");
}

ZTEST(volume_marker, test_15_state_strings)
{
	/* These strings reach operators through logs and DEVICE_STATUS during
	 * exactly the situations where the device may hold the only copy of a
	 * CA key, so they must be distinct and present. */
	const char *v = storage_volume_state_str(STORAGE_VOLUME_VALID);
	const char *u = storage_volume_state_str(STORAGE_VOLUME_UNMARKED);
	const char *m = storage_volume_state_str(STORAGE_VOLUME_MISMATCH);

	zassert_true(strlen(v) > 0 && strlen(u) > 0 && strlen(m) > 0,
		     "state strings must be non-empty");
	zassert_true(strcmp(v, u) != 0 && strcmp(u, m) != 0 && strcmp(v, m) != 0,
		     "state strings must be distinguishable");
}

ZTEST(volume_marker, test_16_storage_init_is_idempotent)
{
	/*
	 * fs_mount() returns -EBUSY on a second mount, and storage_init() used
	 * to treat any mount failure as grounds to format. A second call would
	 * therefore have erased a live volume. Verify it is now a no-op — and
	 * that the volume is still there afterwards.
	 */
	zassert_ok(storage_volume_marker_write(), "marker write");
	zassert_ok(storage_init(), "second storage_init must succeed");
	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_VALID,
		      "a second storage_init must not have formatted the volume");
}

/* ── enforcement ──────────────────────────────────────────────────────────
 *
 * Everything above establishes that the marker can tell the three states
 * apart. These check that the states actually restrain anything — up to
 * 2026-07-23 a mismatched volume was detected, logged, and then used exactly
 * as if it had verified.
 */

ZTEST(volume_marker, test_17_valid_volume_permits_everything)
{
	zassert_ok(storage_volume_marker_write(), "marker write");
	zassert_true(storage_volume_trusted(), "valid volume must be trusted");
	zassert_true(storage_volume_may_mint(), "valid volume must permit minting");
}

ZTEST(volume_marker, test_18_unmarked_and_empty_refuses_minting)
{
	/*
	 * The exact fingerprint of a misdeclared partition: mounts, no marker,
	 * nothing on it. Indistinguishable from a genuinely blank device, which
	 * is why minting is refused rather than merely warned about — a blank
	 * device is prepared by the factory image, which leaves a marker.
	 */
	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_UNMARKED,
		      "test_before leaves the volume unmarked");
	zassert_false(storage_volume_may_mint(), "an unmarked, empty volume must refuse new keys");

	/* Still trusted: nothing contradicts this build, so reads and firmware
	 * update stay available. Refusing those would strand the device. */
	zassert_true(storage_volume_trusted(), "unmarked is ambiguous, not wrong — do not degrade");
}

ZTEST(volume_marker, test_19_unmarked_with_a_ca_key_may_mint)
{
	/*
	 * Every device provisioned before markers existed lands here. Allowing
	 * it is safe because this combination cannot be the misdeclared case
	 * (which presents empty) and because nothing destructive is reachable:
	 * ca_provision() refuses to overwrite slot 0 regardless.
	 */
	uint8_t blob[CANTIL_KEY_BLOB_LEN];

	memset(blob, 0x5A, sizeof(blob));
	zassert_ok(storage_key_write(0, blob, sizeof(blob)), "write slot 0 key");

	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_UNMARKED, "still unmarked");
	zassert_true(storage_volume_may_mint(),
		     "a pre-marker provisioned device must keep working");

	zassert_ok(storage_slot_delete(0), "clean up slot 0");
	zassert_false(storage_volume_may_mint(), "and must close again once the evidence is gone");
}

ZTEST(volume_marker, test_20_mismatch_degrades_and_refuses_wipe)
{
	zassert_ok(storage_volume_marker_write(), "marker write");
	marker_mutate(damage_offset);
	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_MISMATCH,
		      "wrong offset must be a mismatch");

	zassert_false(storage_volume_trusted(), "mismatch must degrade");
	zassert_false(storage_volume_may_mint(), "mismatch must refuse minting");

	/*
	 * A wipe here would erase a volume we cannot identify while leaving the
	 * keys the operator meant to destroy intact at the offset this build is
	 * not looking at. Refusing is the honest answer; UPDATE_FIRMWARE remains
	 * the way out.
	 */
	zassert_equal(storage_secure_wipe(), -EPERM,
		      "secure wipe must refuse an unidentified volume");
}

ZTEST(volume_marker, test_21_mismatch_survives_a_refused_wipe)
{
	/*
	 * The refusal has to be total, not partial. storage_secure_wipe()
	 * overwrites key blobs before it unlinks anything, so a guard placed
	 * after the first write would still have destroyed a key.
	 */
	uint8_t blob[CANTIL_KEY_BLOB_LEN], back[CANTIL_KEY_BLOB_LEN];
	size_t back_len = sizeof(back);

	memset(blob, 0x3C, sizeof(blob));
	zassert_ok(storage_key_write(0, blob, sizeof(blob)), "write slot 0 key");

	zassert_ok(storage_volume_marker_write(), "marker write");
	marker_mutate(damage_device_id);
	zassert_equal(storage_volume_verify(), STORAGE_VOLUME_MISMATCH,
		      "foreign die must be a mismatch");

	zassert_equal(storage_secure_wipe(), -EPERM, "wipe must refuse");

	zassert_ok(storage_key_read(0, back, &back_len), "slot 0 must still exist");
	zassert_equal(back_len, sizeof(blob), "key length changed");
	zassert_mem_equal(back, blob, sizeof(blob), "key blob was overwritten");

	zassert_ok(storage_slot_delete(0), "clean up slot 0");
}
