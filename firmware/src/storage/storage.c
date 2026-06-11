#include <zephyr/kernel.h>
#include <zephyr/fs/fs.h>
#include <zephyr/fs/littlefs.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/logging/log.h>
#include <stdio.h>
#include <string.h>

#include "storage.h"
#include "crypto/crypto.h"

LOG_MODULE_REGISTER(storage, LOG_LEVEL_INF);

#define MOUNT_POINT    "/lfs"
#define PATH_MAX_LEN   128
/* NCS PM aliases storage_partition → littlefs_storage (see flash_map_pm.h) */
#define LFS_PARTITION  FIXED_PARTITION_ID(storage_partition)
#define NOISE_PRIV_ENC_LEN  (12 + 32 + 16)  /* nonce + ciphertext + tag */

FS_LITTLEFS_DECLARE_DEFAULT_CONFIG(lfs_data);
static struct fs_mount_t cantil_lfs_mount = {
	.type        = FS_LITTLEFS,
	.mnt_point   = MOUNT_POINT,
	.fs_data     = &lfs_data,
	.storage_dev = (void *)LFS_PARTITION,
};

/* Create all directories in path up to (not including) the final component. */
static int mkdir_p(const char *path)
{
	char tmp[PATH_MAX_LEN];
	int ret;

	strncpy(tmp, path, sizeof(tmp) - 1);
	tmp[sizeof(tmp) - 1] = '\0';

	for (char *p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			ret = fs_mkdir(tmp);
			if (ret && ret != -EEXIST) {
				return ret;
			}
			*p = '/';
		}
	}
	return 0;
}

static int write_file(const char *path, const uint8_t *data, size_t len)
{
	struct fs_file_t f;
	int ret;

	ret = mkdir_p(path);
	if (ret) {
		LOG_ERR("write_file: mkdir_p %s -> %d", path, ret);
		return ret;
	}

	fs_file_t_init(&f);
	ret = fs_open(&f, path, FS_O_WRITE | FS_O_CREATE | FS_O_TRUNC);
	if (ret) {
		LOG_ERR("write_file: fs_open %s -> %d", path, ret);
		return ret;
	}

	ssize_t written = fs_write(&f, data, len);

	fs_close(&f);
	if (written != (ssize_t)len) {
		LOG_ERR("write_file: short write %s wrote=%zd want=%zu",
			path, written, len);
		return -EIO;
	}
	return 0;
}

static int read_file(const char *path, uint8_t *buf, size_t *len)
{
	struct fs_file_t f;
	int ret;

	fs_file_t_init(&f);
	ret = fs_open(&f, path, FS_O_READ);
	if (ret) {
		return ret;
	}

	ssize_t n = fs_read(&f, buf, *len);

	fs_close(&f);
	if (n < 0) {
		return (int)n;
	}
	*len = (size_t)n;
	return 0;
}

int storage_init(void)
{
	int ret = fs_mount(&cantil_lfs_mount);

	if (ret == -ENODEV) {
		LOG_ERR("storage device not found");
		return ret;
	}

	if (ret) {
		/* First boot or corrupted filesystem — format and retry */
		LOG_WRN("fs_mount failed (%d), formatting LittleFS partition", ret);
		ret = fs_mkfs(FS_LITTLEFS, (uintptr_t)LFS_PARTITION, NULL, 0);
		if (ret) {
			LOG_ERR("fs_mkfs failed: %d", ret);
			return ret;
		}
		ret = fs_mount(&cantil_lfs_mount);
		if (ret) {
			LOG_ERR("fs_mount after format failed: %d", ret);
			return ret;
		}
	}

	LOG_INF("LittleFS mounted at %s", MOUNT_POINT);
	return 0;
}

int storage_key_write(uint32_t slot, const uint8_t *blob, size_t len)
{
	char path[PATH_MAX_LEN];

	snprintf(path, sizeof(path), MOUNT_POINT "/keys/%u/key.bin", slot);
	return write_file(path, blob, len);
}

int storage_key_read(uint32_t slot, uint8_t *blob, size_t *len)
{
	char path[PATH_MAX_LEN];

	snprintf(path, sizeof(path), MOUNT_POINT "/keys/%u/key.bin", slot);
	return read_file(path, blob, len);
}

int storage_slot_cert_write(uint32_t slot, const uint8_t *der, size_t len)
{
	char path[PATH_MAX_LEN];

	snprintf(path, sizeof(path), MOUNT_POINT "/keys/%u/cert.der", slot);
	return write_file(path, der, len);
}

int storage_slot_cert_read(uint32_t slot, uint8_t *der, size_t *len)
{
	char path[PATH_MAX_LEN];

	snprintf(path, sizeof(path), MOUNT_POINT "/keys/%u/cert.der", slot);
	return read_file(path, der, len);
}

int storage_slot_cert_exists(uint32_t slot)
{
	char path[PATH_MAX_LEN];
	struct fs_dirent ent;

	snprintf(path, sizeof(path), MOUNT_POINT "/keys/%u/cert.der", slot);
	int ret = fs_stat(path, &ent);

	if (ret == 0) {
		return 1;
	}
	if (ret == -ENOENT) {
		return 0;
	}
	return ret;
}

int storage_slot_chain_write(uint32_t slot, const uint8_t *der, size_t len)
{
	char path[PATH_MAX_LEN];

	snprintf(path, sizeof(path), MOUNT_POINT "/keys/%u/chain.der", slot);
	return write_file(path, der, len);
}

int storage_slot_chain_read(uint32_t slot, uint8_t *der, size_t *len)
{
	char path[PATH_MAX_LEN];

	snprintf(path, sizeof(path), MOUNT_POINT "/keys/%u/chain.der", slot);
	return read_file(path, der, len);
}

int storage_slot_chain_exists(uint32_t slot)
{
	char path[PATH_MAX_LEN];
	struct fs_dirent ent;

	snprintf(path, sizeof(path), MOUNT_POINT "/keys/%u/chain.der", slot);
	int ret = fs_stat(path, &ent);

	if (ret == 0)        return 1;
	if (ret == -ENOENT)  return 0;
	return ret;
}

int storage_slot_chain_delete(uint32_t slot)
{
	char path[PATH_MAX_LEN];

	snprintf(path, sizeof(path), MOUNT_POINT "/keys/%u/chain.der", slot);
	int rc = fs_unlink(path);

	if (rc == 0 || rc == -ENOENT) return 0;
	return rc;
}

int storage_slot_key_exists(uint32_t slot)
{
	char path[PATH_MAX_LEN];
	struct fs_dirent ent;

	snprintf(path, sizeof(path), MOUNT_POINT "/keys/%u/key.bin", slot);
	int ret = fs_stat(path, &ent);

	if (ret == 0)        return 1;
	if (ret == -ENOENT)  return 0;
	return ret;
}

int storage_slot_csr_exists(uint32_t slot)
{
	char path[PATH_MAX_LEN];
	struct fs_dirent ent;

	snprintf(path, sizeof(path), MOUNT_POINT "/keys/%u/csr.der", slot);
	int ret = fs_stat(path, &ent);

	if (ret == 0)        return 1;
	if (ret == -ENOENT)  return 0;
	return ret;
}

/* Forward declarations (rm_rf is defined later in this file). */
static int rm_rf(const char *path);

int storage_slot_delete(uint32_t slot)
{
	char path[PATH_MAX_LEN];

	/* Overwrite the key blob with garbage before unlinking. The FICR-
	 * derived storage key is intrinsic to the SoC, so destroying the
	 * ciphertext on flash makes the plaintext key unrecoverable. */
	uint8_t garbage[NOISE_PRIV_ENC_LEN];
	memset(garbage, 0xA5, sizeof(garbage));
	snprintf(path, sizeof(path), MOUNT_POINT "/keys/%u/key.bin", slot);
	(void)write_file(path, garbage, sizeof(garbage));
	memset(garbage, 0, sizeof(garbage));

	snprintf(path, sizeof(path), MOUNT_POINT "/keys/%u", slot);
	int rc = rm_rf(path);
	if (rc == -ENOENT) return 0;
	return rc;
}

int storage_slot_meta_write(uint32_t slot, const uint8_t *blob, size_t len)
{
	char path[PATH_MAX_LEN];

	snprintf(path, sizeof(path), MOUNT_POINT "/keys/%u/meta.bin", slot);
	return write_file(path, blob, len);
}

int storage_slot_meta_read(uint32_t slot, uint8_t *blob, size_t *len)
{
	char path[PATH_MAX_LEN];

	snprintf(path, sizeof(path), MOUNT_POINT "/keys/%u/meta.bin", slot);
	return read_file(path, blob, len);
}

int storage_slot_x509_write(uint32_t slot, const uint8_t *blob, size_t len)
{
	char path[PATH_MAX_LEN];

	snprintf(path, sizeof(path), MOUNT_POINT "/keys/%u/x509_data.bin", slot);
	return write_file(path, blob, len);
}

int storage_slot_x509_read(uint32_t slot, uint8_t *blob, size_t *len)
{
	char path[PATH_MAX_LEN];

	snprintf(path, sizeof(path), MOUNT_POINT "/keys/%u/x509_data.bin", slot);
	return read_file(path, blob, len);
}

int storage_slot_csr_write(uint32_t slot, const uint8_t *der, size_t len)
{
	char path[PATH_MAX_LEN];

	snprintf(path, sizeof(path), MOUNT_POINT "/keys/%u/csr.der", slot);
	return write_file(path, der, len);
}

int storage_slot_csr_read(uint32_t slot, uint8_t *der, size_t *len)
{
	char path[PATH_MAX_LEN];

	snprintf(path, sizeof(path), MOUNT_POINT "/keys/%u/csr.der", slot);
	return read_file(path, der, len);
}

int storage_issued_cert_write(const uint8_t *serial, size_t serial_len,
			      const uint8_t *der, size_t der_len)
{
	char hex[PATH_MAX_LEN];
	char path[PATH_MAX_LEN];

	if (serial_len * 2 + 1 > sizeof(hex)) {
		return -EINVAL;
	}
	for (size_t i = 0; i < serial_len; i++) {
		snprintf(&hex[i * 2], 3, "%02x", serial[i]);
	}
	snprintf(path, sizeof(path), MOUNT_POINT "/certs/%s/cert.der", hex);
	return write_file(path, der, der_len);
}

int storage_issued_cert_read(const uint8_t *serial, size_t serial_len,
			     uint8_t *der, size_t *der_len)
{
	char hex[PATH_MAX_LEN];
	char path[PATH_MAX_LEN];

	if (serial_len * 2 + 1 > sizeof(hex)) {
		return -EINVAL;
	}
	for (size_t i = 0; i < serial_len; i++) {
		snprintf(&hex[i * 2], 3, "%02x", serial[i]);
	}
	snprintf(path, sizeof(path), MOUNT_POINT "/certs/%s/cert.der", hex);
	return read_file(path, der, der_len);
}

static int hex_path(const uint8_t *serial, size_t serial_len,
		    const char *suffix, char *out, size_t out_cap)
{
	char hex[PATH_MAX_LEN];

	if (serial_len * 2 + 1 > sizeof(hex)) {
		return -EINVAL;
	}
	for (size_t i = 0; i < serial_len; i++) {
		snprintf(&hex[i * 2], 3, "%02x", serial[i]);
	}
	int n = snprintf(out, out_cap, MOUNT_POINT "/certs/%s/%s", hex, suffix);
	return (n < 0 || (size_t)n >= out_cap) ? -ENAMETOOLONG : 0;
}

int storage_issued_meta_write(const uint8_t *serial, size_t serial_len,
			      const uint8_t *blob, size_t blob_len)
{
	char path[PATH_MAX_LEN];
	int rc = hex_path(serial, serial_len, "meta.bin", path, sizeof(path));

	if (rc) {
		return rc;
	}
	return write_file(path, blob, blob_len);
}

int storage_issued_meta_read(const uint8_t *serial, size_t serial_len,
			     uint8_t *blob, size_t *blob_len)
{
	char path[PATH_MAX_LEN];
	int rc = hex_path(serial, serial_len, "meta.bin", path, sizeof(path));

	if (rc) {
		return rc;
	}
	return read_file(path, blob, blob_len);
}

int storage_issued_cert_exists(const uint8_t *serial, size_t serial_len)
{
	char path[PATH_MAX_LEN];
	int rc = hex_path(serial, serial_len, "cert.der", path, sizeof(path));

	if (rc) {
		return rc;
	}
	struct fs_dirent ent;
	rc = fs_stat(path, &ent);
	if (rc == 0)        return 1;
	if (rc == -ENOENT)  return 0;
	return rc;
}

static int hex_nibble(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
	return -1;
}

int storage_issued_certs_iter(storage_issued_iter_cb cb, void *user)
{
	struct fs_dir_t dir;
	struct fs_dirent ent;

	fs_dir_t_init(&dir);
	int rc = fs_opendir(&dir, MOUNT_POINT "/certs");

	if (rc == -ENOENT) return 0;
	if (rc) return rc;

	int cb_rc = 0;
	while (fs_readdir(&dir, &ent) == 0 && ent.name[0] != '\0') {
		if (ent.type != FS_DIR_ENTRY_DIR) continue;

		size_t nlen = strlen(ent.name);
		if (nlen == 0 || (nlen & 1) || nlen / 2 > 20) continue;

		uint8_t serial[20];
		size_t serial_len = nlen / 2;
		int ok = 1;

		for (size_t i = 0; i < serial_len && ok; i++) {
			int hi = hex_nibble(ent.name[i * 2]);
			int lo = hex_nibble(ent.name[i * 2 + 1]);
			if (hi < 0 || lo < 0) { ok = 0; break; }
			serial[i] = (uint8_t)((hi << 4) | lo);
		}
		if (!ok) continue;

		cb_rc = cb(serial, serial_len, user);
		if (cb_rc) break;
	}
	fs_closedir(&dir);
	return cb_rc;
}

int storage_slot_crl_number_read(uint32_t slot, uint32_t *out)
{
	char path[PATH_MAX_LEN];
	uint8_t buf[4];
	size_t  buf_len = sizeof(buf);

	snprintf(path, sizeof(path),
		 MOUNT_POINT "/keys/%u/crl_number.bin", slot);
	int rc = read_file(path, buf, &buf_len);

	if (rc) return rc;
	if (buf_len != 4) return -EINVAL;
	*out = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
	       ((uint32_t)buf[2] <<  8) |  (uint32_t)buf[3];
	return 0;
}

int storage_slot_crl_number_write(uint32_t slot, uint32_t value)
{
	char path[PATH_MAX_LEN];
	uint8_t buf[4] = {
		(uint8_t)(value >> 24), (uint8_t)(value >> 16),
		(uint8_t)(value >>  8), (uint8_t)(value),
	};

	snprintf(path, sizeof(path),
		 MOUNT_POINT "/keys/%u/crl_number.bin", slot);
	return write_file(path, buf, sizeof(buf));
}

int storage_config_write(const uint8_t *data, size_t len)
{
	return write_file(MOUNT_POINT "/config.bin", data, len);
}

int storage_config_read(uint8_t *data, size_t *len)
{
	return read_file(MOUNT_POINT "/config.bin", data, len);
}

static int rm_rf(const char *path)
{
	struct fs_dir_t dir;
	struct fs_dirent ent;
	char child[PATH_MAX_LEN];
	int ret;

	fs_dir_t_init(&dir);
	ret = fs_opendir(&dir, path);
	if (ret == -ENOENT) {
		return 0;
	}
	if (ret) {
		return ret;
	}

	while (fs_readdir(&dir, &ent) == 0 && ent.name[0] != '\0') {
		snprintf(child, sizeof(child), "%s/%s", path, ent.name);
		if (ent.type == FS_DIR_ENTRY_DIR) {
			rm_rf(child);
			fs_unlink(child);
		} else {
			fs_unlink(child);
		}
	}
	fs_closedir(&dir);
	return fs_unlink(path);
}

int storage_unlock_seq_write(const uint8_t *seq, size_t len)
{
	return write_file(MOUNT_POINT "/config_unlock_seq.bin", seq, len);
}

int storage_unlock_seq_read(uint8_t *seq, size_t *len)
{
	return read_file(MOUNT_POINT "/config_unlock_seq.bin", seq, len);
}

int storage_unlock_attempts_write(uint32_t count)
{
	/* Little-endian 4 bytes. Host code that ever needs to read this file
	 * directly can decode trivially; we don't share it over the wire. */
	uint8_t buf[4] = {
		(uint8_t)(count & 0xff),
		(uint8_t)((count >> 8) & 0xff),
		(uint8_t)((count >> 16) & 0xff),
		(uint8_t)((count >> 24) & 0xff),
	};
	return write_file(MOUNT_POINT "/config_unlock_attempts.bin",
			  buf, sizeof(buf));
}

int storage_unlock_attempts_read(uint32_t *out)
{
	uint8_t buf[4];
	size_t len = sizeof(buf);
	int rc = read_file(MOUNT_POINT "/config_unlock_attempts.bin",
			   buf, &len);
	if (rc) {
		return rc;
	}
	if (len != sizeof(buf)) {
		return -EINVAL;
	}
	*out = (uint32_t)buf[0]
	     | ((uint32_t)buf[1] << 8)
	     | ((uint32_t)buf[2] << 16)
	     | ((uint32_t)buf[3] << 24);
	return 0;
}

int storage_secure_wipe(void)
{
	LOG_WRN("secure wipe: starting");

	/* Overwrite slot 0 key blob with random data before unlinking.
	 * The FICR-derived storage key is intrinsic — destroying the
	 * ciphertext makes the private key unrecoverable. */
	uint8_t garbage[NOISE_PRIV_ENC_LEN];

	memset(garbage, 0xA5, sizeof(garbage));
	(void)write_file(MOUNT_POINT "/keys/0/key.bin", garbage, sizeof(garbage));
	/* Same rationale for the session slot's two encrypted scalars. */
	(void)write_file(MOUNT_POINT "/session/key.bin", garbage, sizeof(garbage));
	(void)write_file(MOUNT_POINT "/session/id_key.bin", garbage, sizeof(garbage));
	memset(garbage, 0, sizeof(garbage));

	rm_rf(MOUNT_POINT "/keys");
	rm_rf(MOUNT_POINT "/certs");
	rm_rf(MOUNT_POINT "/noise");
	rm_rf(MOUNT_POINT "/session");
	rm_rf(MOUNT_POINT "/clients");
	fs_unlink(MOUNT_POINT "/config.bin");
	fs_unlink(MOUNT_POINT "/config_unlock_seq.bin");
	fs_unlink(MOUNT_POINT "/config_unlock_attempts.bin");

	LOG_WRN("secure wipe: complete");
	return 0;
}

int storage_count_slots_used(uint32_t *out)
{
	uint32_t count = 0;
	char path[PATH_MAX_LEN];
	struct fs_dirent ent;

	for (uint32_t i = 0; i < CONFIG_CANTIL_MAX_KEY_SLOTS; i++) {
		snprintf(path, sizeof(path),
			 MOUNT_POINT "/keys/%u/key.bin", i);
		if (fs_stat(path, &ent) == 0) {
			count++;
		}
	}
	*out = count;
	return 0;
}

int storage_count_issued_certs(uint32_t *out)
{
	struct fs_dir_t dir;
	struct fs_dirent ent;
	uint32_t count = 0;

	fs_dir_t_init(&dir);
	int ret = fs_opendir(&dir, MOUNT_POINT "/certs");

	if (ret == -ENOENT) {
		*out = 0;
		return 0;
	}
	if (ret) {
		return ret;
	}

	while (fs_readdir(&dir, &ent) == 0 && ent.name[0] != '\0') {
		if (ent.type == FS_DIR_ENTRY_DIR) {
			count++;
		}
	}
	fs_closedir(&dir);
	*out = count;
	return 0;
}

int storage_free_kb(uint32_t *out)
{
	struct fs_statvfs st;
	int ret = fs_statvfs(MOUNT_POINT, &st);

	if (ret) {
		return ret;
	}
	uint64_t free_bytes = (uint64_t)st.f_bfree * (uint64_t)st.f_frsize;
	*out = (uint32_t)(free_bytes / 1024U);
	return 0;
}

/*
 * Noise static keypair: private key stored encrypted (AES-256-GCM with
 * FICR-derived storage key), public key stored plaintext alongside it.
 *
 * Layout of /noise/key.bin:
 *   [12-byte GCM nonce][32-byte encrypted private key][16-byte GCM tag]
 *   = 60 bytes total (produced by crypto_encrypt_blob)
 */

int storage_noise_keypair_write(const uint8_t priv[32], const uint8_t pub[32])
{
	uint8_t storage_key[32];
	int ret = crypto_storage_key_derive(storage_key);

	if (ret) {
		LOG_ERR("noise_kp_write: storage_key_derive=%d", ret);
		return ret;
	}

	uint8_t enc_buf[NOISE_PRIV_ENC_LEN];
	size_t enc_len = sizeof(enc_buf);

	ret = crypto_encrypt_blob(storage_key, priv, 32, enc_buf, &enc_len);
	memset(storage_key, 0, 32);
	if (ret) {
		LOG_ERR("noise_kp_write: encrypt_blob=%d", ret);
		return ret;
	}

	ret = write_file(MOUNT_POINT "/noise/key.bin", enc_buf, enc_len);
	if (ret) {
		LOG_ERR("noise_kp_write: write key.bin=%d", ret);
		return ret;
	}
	ret = write_file(MOUNT_POINT "/noise/pub.bin", pub, 32);
	if (ret) {
		LOG_ERR("noise_kp_write: write pub.bin=%d", ret);
	}
	return ret;
}

/* ── session slot (/session/) — transport identity, T-02 ─────────────────── */

int storage_session_key_write(const uint8_t *blob, size_t len)
{
	return write_file(MOUNT_POINT "/session/key.bin", blob, len);
}

int storage_session_key_read(uint8_t *blob, size_t *len)
{
	return read_file(MOUNT_POINT "/session/key.bin", blob, len);
}

int storage_session_id_key_write(const uint8_t *blob, size_t len)
{
	return write_file(MOUNT_POINT "/session/id_key.bin", blob, len);
}

int storage_session_id_key_read(uint8_t *blob, size_t *len)
{
	return read_file(MOUNT_POINT "/session/id_key.bin", blob, len);
}

int storage_session_meta_write(const uint8_t *blob, size_t len)
{
	return write_file(MOUNT_POINT "/session/meta.bin", blob, len);
}

int storage_session_meta_read(uint8_t *blob, size_t *len)
{
	return read_file(MOUNT_POINT "/session/meta.bin", blob, len);
}

int storage_session_cert_write(const uint8_t *der, size_t len)
{
	return write_file(MOUNT_POINT "/session/cert.der", der, len);
}

int storage_session_cert_read(uint8_t *der, size_t *len)
{
	return read_file(MOUNT_POINT "/session/cert.der", der, len);
}

int storage_session_cert_exists(void)
{
	struct fs_dirent ent;
	int ret = fs_stat(MOUNT_POINT "/session/cert.der", &ent);

	if (ret == 0) {
		return 1;
	}
	if (ret == -ENOENT) {
		return 0;
	}
	return ret;
}

int storage_session_csr_write(const uint8_t *der, size_t len)
{
	return write_file(MOUNT_POINT "/session/csr.der", der, len);
}

int storage_session_csr_read(uint8_t *der, size_t *len)
{
	return read_file(MOUNT_POINT "/session/csr.der", der, len);
}

int storage_session_chain_write(const uint8_t *der, size_t len)
{
	return write_file(MOUNT_POINT "/session/chain.der", der, len);
}

int storage_session_chain_read(uint8_t *der, size_t *len)
{
	return read_file(MOUNT_POINT "/session/chain.der", der, len);
}

int storage_session_chain_exists(void)
{
	struct fs_dirent ent;
	int ret = fs_stat(MOUNT_POINT "/session/chain.der", &ent);

	if (ret == 0) {
		return 1;
	}
	if (ret == -ENOENT) {
		return 0;
	}
	return ret;
}

int storage_session_chain_delete(void)
{
	int ret = fs_unlink(MOUNT_POINT "/session/chain.der");

	return (ret == -ENOENT) ? 0 : ret;
}

int storage_noise_keypair_read(uint8_t priv[32], uint8_t pub[32])
{
	size_t pub_len = 32;
	int ret = read_file(MOUNT_POINT "/noise/pub.bin", pub, &pub_len);

	if (ret) {
		return ret;  /* -ENOENT on first boot */
	}

	uint8_t enc_buf[NOISE_PRIV_ENC_LEN];
	size_t enc_len = sizeof(enc_buf);

	ret = read_file(MOUNT_POINT "/noise/key.bin", enc_buf, &enc_len);
	if (ret) {
		return ret;
	}

	uint8_t storage_key[32];

	ret = crypto_storage_key_derive(storage_key);
	if (ret) {
		return ret;
	}

	size_t pt_len = 32;

	ret = crypto_decrypt_blob(storage_key, enc_buf, enc_len, priv, &pt_len);
	memset(storage_key, 0, 32);
	return ret;
}

/* ---------------------------------------------------------------------------
 * Client bond store (/clients/<hex8>/)
 *
 * Each bonded peer is stored under a subdirectory named by the first 4 bytes
 * of their Curve25519 static pubkey, hex-encoded (8 lowercase chars).  The
 * full 32-byte pubkey lives in pubkey.bin so the directory name can be
 * re-derived at read-time and collisions resolved by the caller.
 * ---------------------------------------------------------------------------*/

static void client_hex_path(const uint8_t id[4], const char *file,
			     char *out, size_t out_len)
{
	snprintf(out, out_len,
		 MOUNT_POINT "/clients/%02x%02x%02x%02x/%s",
		 id[0], id[1], id[2], id[3], file);
}

int storage_client_bond_pubkey_write(const uint8_t id[4], const uint8_t pub[32])
{
	char path[PATH_MAX_LEN];

	client_hex_path(id, "pubkey.bin", path, sizeof(path));
	return write_file(path, pub, 32);
}

int storage_client_bond_pubkey_read(const uint8_t id[4], uint8_t pub[32])
{
	char path[PATH_MAX_LEN];
	size_t len = 32;

	client_hex_path(id, "pubkey.bin", path, sizeof(path));
	return read_file(path, pub, &len);
}

int storage_client_bond_meta_write(const uint8_t id[4], const uint8_t *blob,
				   size_t len)
{
	char path[PATH_MAX_LEN];

	client_hex_path(id, "meta.bin", path, sizeof(path));
	return write_file(path, blob, len);
}

int storage_client_bond_meta_read(const uint8_t id[4], uint8_t *blob,
				  size_t *len)
{
	char path[PATH_MAX_LEN];

	client_hex_path(id, "meta.bin", path, sizeof(path));
	return read_file(path, blob, len);
}

int storage_client_bond_psk_write(const uint8_t id[4], const uint8_t *blob,
				  size_t len)
{
	char path[PATH_MAX_LEN];

	client_hex_path(id, "psk.bin", path, sizeof(path));
	return write_file(path, blob, len);
}

int storage_client_bond_psk_read(const uint8_t id[4], uint8_t *blob,
				 size_t *len)
{
	char path[PATH_MAX_LEN];

	client_hex_path(id, "psk.bin", path, sizeof(path));
	return read_file(path, blob, len);
}

int storage_client_bond_psk_exists(const uint8_t id[4])
{
	char path[PATH_MAX_LEN];
	struct fs_dirent ent;

	client_hex_path(id, "psk.bin", path, sizeof(path));
	int rc = fs_stat(path, &ent);
	if (rc == 0)       return 1;
	if (rc == -ENOENT) return 0;
	return rc;
}

int storage_client_bond_cert_write(const uint8_t id[4], const uint8_t *der,
				   size_t len)
{
	char path[PATH_MAX_LEN];

	client_hex_path(id, "cert.der", path, sizeof(path));
	return write_file(path, der, len);
}

int storage_client_bond_cert_read(const uint8_t id[4], uint8_t *der,
				  size_t *len)
{
	char path[PATH_MAX_LEN];

	client_hex_path(id, "cert.der", path, sizeof(path));
	return read_file(path, der, len);
}

int storage_client_bond_cert_exists(const uint8_t id[4])
{
	char path[PATH_MAX_LEN];
	struct fs_dirent ent;

	client_hex_path(id, "cert.der", path, sizeof(path));
	int rc = fs_stat(path, &ent);
	if (rc == 0)       return 1;
	if (rc == -ENOENT) return 0;
	return rc;
}

int storage_client_bond_exists(const uint8_t id[4])
{
	char path[PATH_MAX_LEN];
	struct fs_dirent ent;

	/* pubkey.bin is the authoritative presence marker for a bond. */
	client_hex_path(id, "pubkey.bin", path, sizeof(path));
	int rc = fs_stat(path, &ent);
	if (rc == 0)       return 1;
	if (rc == -ENOENT) return 0;
	return rc;
}

int storage_client_bond_delete(const uint8_t id[4])
{
	char dir[PATH_MAX_LEN];

	snprintf(dir, sizeof(dir),
		 MOUNT_POINT "/clients/%02x%02x%02x%02x",
		 id[0], id[1], id[2], id[3]);
	int rc = rm_rf(dir);
	if (rc == -ENOENT) return 0;
	return rc;
}

int storage_client_bonds_iter(storage_client_bond_iter_cb cb, void *user)
{
	struct fs_dir_t dir;
	struct fs_dirent ent;

	fs_dir_t_init(&dir);
	int rc = fs_opendir(&dir, MOUNT_POINT "/clients");

	if (rc == -ENOENT) return 0;
	if (rc) return rc;

	int cb_rc = 0;

	while (fs_readdir(&dir, &ent) == 0 && ent.name[0] != '\0') {
		if (ent.type != FS_DIR_ENTRY_DIR) continue;
		if (strlen(ent.name) != 8) continue;

		uint8_t id[4];
		int ok = 1;

		for (int i = 0; i < 4 && ok; i++) {
			int hi = hex_nibble(ent.name[i * 2]);
			int lo = hex_nibble(ent.name[i * 2 + 1]);
			if (hi < 0 || lo < 0) { ok = 0; break; }
			id[i] = (uint8_t)((hi << 4) | lo);
		}
		if (!ok) continue;

		cb_rc = cb(id, user);
		if (cb_rc) break;
	}
	fs_closedir(&dir);
	return cb_rc;
}

int storage_count_client_bonds(uint32_t *out)
{
	uint32_t count = 0;
	struct fs_dir_t dir;
	struct fs_dirent ent;

	fs_dir_t_init(&dir);
	int rc = fs_opendir(&dir, MOUNT_POINT "/clients");

	if (rc == -ENOENT) { *out = 0; return 0; }
	if (rc) return rc;

	while (fs_readdir(&dir, &ent) == 0 && ent.name[0] != '\0') {
		if (ent.type == FS_DIR_ENTRY_DIR && strlen(ent.name) == 8)
			count++;
	}
	fs_closedir(&dir);
	*out = count;
	return 0;
}

/* ── Firmware update pending sentinel (/lfs/fw_pending) ──────────────────── */

#define FW_PENDING_PATH  MOUNT_POINT "/fw_pending"

int storage_fw_pending_set(void)
{
	struct fs_file_t f;

	fs_file_t_init(&f);
	int ret = fs_open(&f, FW_PENDING_PATH,
			  FS_O_WRITE | FS_O_CREATE | FS_O_TRUNC);
	if (ret) {
		LOG_ERR("fw_pending: open %d", ret);
		return ret;
	}
	fs_close(&f);
	return 0;
}

int storage_fw_pending_clear(void)
{
	int ret = fs_unlink(FW_PENDING_PATH);

	if (ret && ret != -ENOENT) {
		LOG_ERR("fw_pending: unlink %d", ret);
		return ret;
	}
	return 0;
}

int storage_fw_pending_check(void)
{
	struct fs_dirent ent;
	int ret = fs_stat(FW_PENDING_PATH, &ent);

	if (ret == -ENOENT) return 0;
	if (ret) return ret;
	return 1;
}
