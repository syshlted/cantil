/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

/*
 * Client bond store conformance on native_sim (transport + pairing T-15).
 *
 * Drives client_bond.c + storage.c against the simulated flash partition.
 * Each test starts from a wiped /clients/ dir via test_before(), so
 * order-independence holds.
 *
 * Coverage:
 *   1.  Add host bond → exists = 1, kind = HOST.
 *   2.  Add peer-device bond → exists = 1, kind = PEER_DEVICE.
 *   3.  Remove a bond → exists = 0.
 *   4.  Count host vs peer independently.
 *   5.  Set friendly name → read back matches.
 *   6.  list_cbor produces a CBOR array with correct entry count and fields.
 *   7.  Host cap: adding beyond CONFIG_CANTIL_MAX_CLIENT_BONDS (=2) → -ENOSPC.
 *   8.  Peer cap: adding beyond CONFIG_CANTIL_MAX_PEER_BONDS (=2) → -ENOSPC.
 *   9.  Duplicate add → -EEXIST.
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/fs/fs.h>
#include <string.h>
#include <errno.h>

#include "clients/client_bond.h"
#include "storage/storage.h"
#include "cantil_cbor.h"

#define LFS_MOUNT    "/lfs"
#define CLIENTS_DIR  LFS_MOUNT "/clients"

/* Distinct synthetic pubkeys for tests (only first 4 bytes matter for path). */
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

/* ── helpers ──────────────────────────────────────────────────────────── */

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

/* ── suite setup/teardown ────────────────────────────────────────────────── */

static void *suite_setup(void)
{
	zassert_ok(storage_init(), "storage_init failed");
	return NULL;
}

ZTEST_SUITE(client_bond, NULL, suite_setup, NULL, NULL, NULL);

static void test_before(void)
{
	rm_rf_dir(CLIENTS_DIR);
}

/* Test 1: add a host bond and verify it exists with correct kind. */
ZTEST(client_bond, test_01_add_host)
{
	test_before();

	int rc = client_bond_add(PUB_A, CLIENT_KIND_HOST, 0);
	zassert_ok(rc, "add host bond: %d", rc);
	zassert_equal(client_bond_exists(PUB_A), 1, "bond should exist");

	client_meta_t meta;
	rc = client_bond_meta_read(PUB_A, &meta);
	zassert_ok(rc, "meta_read: %d", rc);
	zassert_equal(meta.kind, CLIENT_KIND_HOST, "kind should be HOST");
	zassert_equal(meta.version, CLIENT_META_VERSION, "version");
}

/* Test 2: add a peer-device bond. */
ZTEST(client_bond, test_02_add_peer)
{
	test_before();

	int rc = client_bond_add(PUB_B, CLIENT_KIND_PEER_DEVICE, 12345);
	zassert_ok(rc, "add peer bond: %d", rc);
	zassert_equal(client_bond_exists(PUB_B), 1, "bond should exist");

	client_meta_t meta;
	rc = client_bond_meta_read(PUB_B, &meta);
	zassert_ok(rc, "meta_read: %d", rc);
	zassert_equal(meta.kind, CLIENT_KIND_PEER_DEVICE, "kind should be PEER");
	/* created_at stored BE and read back correctly */
	uint32_t ts = __builtin_bswap32(meta.created_at_be);
	zassert_equal(ts, 12345U, "created_at mismatch");
}

/* Test 3: remove a bond. */
ZTEST(client_bond, test_03_remove)
{
	test_before();

	zassert_ok(client_bond_add(PUB_A, CLIENT_KIND_HOST, 0), "add");
	zassert_equal(client_bond_exists(PUB_A), 1, "should exist before remove");

	zassert_ok(client_bond_remove(PUB_A), "remove");
	zassert_equal(client_bond_exists(PUB_A), 0, "should not exist after remove");

	/* Removing again is OK (idempotent). */
	zassert_ok(client_bond_remove(PUB_A), "remove again");
}

/* Test 4: count host vs peer independently. */
ZTEST(client_bond, test_04_count)
{
	test_before();

	zassert_ok(client_bond_add(PUB_A, CLIENT_KIND_HOST, 0), "add host A");
	zassert_ok(client_bond_add(PUB_B, CLIENT_KIND_PEER_DEVICE, 0), "add peer B");

	uint32_t hosts = 0, peers = 0;
	zassert_ok(client_bond_count(&hosts, &peers), "count");
	zassert_equal(hosts, 1U, "host count");
	zassert_equal(peers, 1U, "peer count");
}

/* Test 5: set_name + read back. */
ZTEST(client_bond, test_05_set_name)
{
	test_before();

	zassert_ok(client_bond_add(PUB_A, CLIENT_KIND_HOST, 0), "add");

	zassert_ok(client_bond_set_name(PUB_A, "My Laptop"), "set_name");

	client_meta_t meta;
	zassert_ok(client_bond_meta_read(PUB_A, &meta), "meta_read");
	zassert_str_equal(meta.friendly_name, "My Laptop", "name mismatch");
}

/* Test 6: list_cbor produces a CBOR array with the right count and fields. */
ZTEST(client_bond, test_06_list_cbor)
{
	test_before();

	zassert_ok(client_bond_add(PUB_A, CLIENT_KIND_HOST, 9999), "add A");
	zassert_ok(client_bond_add(PUB_B, CLIENT_KIND_PEER_DEVICE, 1111), "add B");
	zassert_ok(client_bond_set_name(PUB_A, "Alpha"), "set name A");

	uint8_t cbor[512];
	size_t len = sizeof(cbor);
	zassert_ok(client_bond_list_cbor(cbor, &len), "list_cbor");
	zassert_true(len > 4, "empty output");

	/* First byte: CBOR array of 2 items. */
	size_t off = 0;
	uint8_t mt; uint64_t v;
	zassert_ok(cantil_cbor_read_head(cbor, len, &off, &mt, &v), "read array head");
	zassert_equal(mt, CANTIL_CBOR_MT_ARRAY, "should be array");
	zassert_equal((uint32_t)v, 2U, "should have 2 entries");

	/* Each entry is a map of 4 items: k, n, p, t. */
	for (int i = 0; i < 2; i++) {
		zassert_ok(cantil_cbor_read_head(cbor, len, &off, &mt, &v),
			   "read map head [%d]", i);
		zassert_equal(mt, CANTIL_CBOR_MT_MAP, "should be map [%d]", i);
		zassert_equal((uint32_t)v, 4U, "map should have 4 items [%d]", i);

		for (int k = 0; k < 4; k++) {
			const uint8_t *key; size_t klen;
			zassert_ok(cantil_cbor_read_tstr(cbor, len, &off, &key, &klen),
				   "read key [%d][%d]", i, k);
			zassert_equal(klen, 1U, "key len [%d][%d]", i, k);
			char kc = (char)key[0];

			if (kc == 'p') {
				const uint8_t *bval; size_t blen;
				zassert_ok(cantil_cbor_read_bstr(cbor, len, &off, &bval, &blen),
					   "read pubkey bstr [%d]", i);
				zassert_equal(blen, 32U, "pubkey len [%d]", i);
			} else if (kc == 't') {
				const uint8_t *tval; size_t tlen;
				zassert_ok(cantil_cbor_read_tstr(cbor, len, &off, &tval, &tlen),
					   "read name tstr [%d]", i);
			} else {
				uint32_t u;
				zassert_ok(cantil_cbor_read_uint32(cbor, len, &off, &u),
					   "read uint [%d][%d]", i, k);
			}
		}
	}
	/* No trailing bytes. */
	zassert_equal(off, len, "CBOR length should match consumed offset");
}

/* Test 7: host bond cap (CONFIG_CANTIL_MAX_CLIENT_BONDS = 2 in prj.conf). */
ZTEST(client_bond, test_07_host_cap)
{
	test_before();

	zassert_ok(client_bond_add(PUB_A, CLIENT_KIND_HOST, 0), "add host 1");
	zassert_ok(client_bond_add(PUB_B, CLIENT_KIND_HOST, 0), "add host 2");

	/* Third host bond should fail with -ENOSPC. */
	int rc = client_bond_add(PUB_C, CLIENT_KIND_HOST, 0);
	zassert_equal(rc, -ENOSPC, "expected -ENOSPC, got %d", rc);
}

/* Test 8: peer bond cap (CONFIG_CANTIL_MAX_PEER_BONDS = 2 in prj.conf). */
ZTEST(client_bond, test_08_peer_cap)
{
	test_before();

	zassert_ok(client_bond_add(PUB_A, CLIENT_KIND_PEER_DEVICE, 0), "add peer 1");
	zassert_ok(client_bond_add(PUB_B, CLIENT_KIND_PEER_DEVICE, 0), "add peer 2");

	int rc = client_bond_add(PUB_C, CLIENT_KIND_PEER_DEVICE, 0);
	zassert_equal(rc, -ENOSPC, "expected -ENOSPC, got %d", rc);
}

/* Test 9: duplicate add returns -EEXIST. */
ZTEST(client_bond, test_09_duplicate)
{
	test_before();

	zassert_ok(client_bond_add(PUB_A, CLIENT_KIND_HOST, 0), "add first");

	int rc = client_bond_add(PUB_A, CLIENT_KIND_HOST, 0);
	zassert_equal(rc, -EEXIST, "expected -EEXIST, got %d", rc);
}

