/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

#include <zephyr/kernel.h>
#include <zephyr/fs/fs.h>
#include <zephyr/sys/crc.h>
#include <zephyr/logging/log.h>
#include <string.h>
#include <errno.h>

#include "volume_marker.h"
#include "storage_partition.h"
#include "crypto/device_id.h"

LOG_MODULE_REGISTER(volume_marker, LOG_LEVEL_INF);

#define VOLUME_MARKER_PATH MOUNT_POINT "/volume.bin"

/* Bytes covered by the CRC: everything up to but excluding the crc32 field. */
#define VOLUME_MARKER_CRC_LEN (offsetof(struct storage_volume_marker, crc32))

static enum storage_volume_state volume_state = STORAGE_VOLUME_UNMARKED;

const char *storage_volume_state_str(enum storage_volume_state st)
{
	switch (st) {
	case STORAGE_VOLUME_VALID:
		return "valid";
	case STORAGE_VOLUME_UNMARKED:
		return "unmarked";
	case STORAGE_VOLUME_MISMATCH:
		return "mismatch";
	default:
		return "unknown";
	}
}

enum storage_volume_state storage_volume_state(void)
{
	return volume_state;
}

static void marker_fill(struct storage_volume_marker *m)
{
	memset(m, 0, sizeof(*m));
	m->magic = CANTIL_VOLUME_MAGIC;
	m->version = CANTIL_VOLUME_VERSION;
	m->partition_offset = (uint32_t)LFS_PARTITION_OFF;
	m->partition_size = (uint32_t)LFS_PARTITION_SIZE;
	crypto_device_id(m->device_id);
	m->crc32 = crc32_ieee((const uint8_t *)m, VOLUME_MARKER_CRC_LEN);
}

static int marker_read(struct storage_volume_marker *m, size_t *len)
{
	struct fs_file_t f;
	int ret;

	fs_file_t_init(&f);
	ret = fs_open(&f, VOLUME_MARKER_PATH, FS_O_READ);
	if (ret) {
		return ret;
	}

	ssize_t n = fs_read(&f, m, sizeof(*m));

	fs_close(&f);
	if (n < 0) {
		return (int)n;
	}
	*len = (size_t)n;
	return 0;
}

/*
 * Read the marker and compare it against what this build expects. Every
 * mismatch is logged individually rather than collapsed into one line: when
 * this fires, the operator is looking at a device that may hold the only copy
 * of a CA key, and "which field disagreed" is the whole diagnosis.
 */
static enum storage_volume_state marker_check(void)
{
	struct storage_volume_marker got;
	struct storage_volume_marker want;
	size_t len = 0;

	int ret = marker_read(&got, &len);

	if (ret == -ENOENT) {
		return STORAGE_VOLUME_UNMARKED;
	}
	if (ret) {
		LOG_ERR("read failed (%d)", ret);
		return STORAGE_VOLUME_MISMATCH;
	}
	if (len != sizeof(got)) {
		LOG_ERR("%zu bytes, expected %zu", len, sizeof(got));
		return STORAGE_VOLUME_MISMATCH;
	}

	uint32_t crc = crc32_ieee((const uint8_t *)&got, VOLUME_MARKER_CRC_LEN);

	if (crc != got.crc32) {
		LOG_ERR("CRC %08x, expected %08x", (unsigned int)got.crc32, (unsigned int)crc);
		return STORAGE_VOLUME_MISMATCH;
	}

	marker_fill(&want);

	if (got.magic != want.magic) {
		LOG_ERR("magic %08x is not a Cantil volume", (unsigned int)got.magic);
		return STORAGE_VOLUME_MISMATCH;
	}
	/*
	 * A newer layout than this firmware understands. Refuse rather than
	 * guess: the fields may have moved, and acting on a misread marker is
	 * worse than having none.
	 */
	if (got.version > want.version) {
		LOG_ERR("layout v%u, firmware understands v%u", (unsigned int)got.version,
			(unsigned int)want.version);
		return STORAGE_VOLUME_MISMATCH;
	}

	bool ok = true;

	if (got.partition_offset != want.partition_offset) {
		LOG_ERR("created at offset 0x%08x, this build mounts 0x%08x",
			(unsigned int)got.partition_offset, (unsigned int)want.partition_offset);
		ok = false;
	}
	if (got.partition_size != want.partition_size) {
		LOG_ERR("created with size 0x%08x, this build declares 0x%08x",
			(unsigned int)got.partition_size, (unsigned int)want.partition_size);
		ok = false;
	}
	if (memcmp(got.device_id, want.device_id, sizeof(want.device_id)) != 0) {
		/* A flash image cloned onto a different die. The AEAD-encrypted
		 * secrets would not decrypt here anyway; this just names the
		 * cause instead of leaving a pile of GCM failures. */
		LOG_ERR("volume belongs to a different device");
		ok = false;
	}

	return ok ? STORAGE_VOLUME_VALID : STORAGE_VOLUME_MISMATCH;
}

enum storage_volume_state storage_volume_verify(void)
{
	volume_state = marker_check();
	return volume_state;
}

int storage_volume_marker_write(void)
{
	struct storage_volume_marker m;
	struct fs_dirent ent;
	struct fs_file_t f;

	/* Never overwrite. A marker that can be rewritten to match whatever
	 * partition happens to be mounted asserts nothing at all. */
	if (fs_stat(VOLUME_MARKER_PATH, &ent) == 0) {
		LOG_ERR("already present, refusing to replace");
		return -EEXIST;
	}

	marker_fill(&m);

	fs_file_t_init(&f);
	int ret = fs_open(&f, VOLUME_MARKER_PATH, FS_O_WRITE | FS_O_CREATE | FS_O_TRUNC);

	if (ret) {
		LOG_ERR("open for write failed (%d)", ret);
		return ret;
	}

	ssize_t n = fs_write(&f, &m, sizeof(m));

	fs_close(&f);

	if (n != (ssize_t)sizeof(m)) {
		LOG_ERR("short write (%zd of %zu)", n, sizeof(m));
		return -EIO;
	}

	LOG_INF("written: offset 0x%08x size 0x%08x", (unsigned int)m.partition_offset,
		(unsigned int)m.partition_size);
	volume_state = STORAGE_VOLUME_VALID;
	return 0;
}
