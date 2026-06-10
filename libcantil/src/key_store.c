#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sodium.h>
#include "key_store.h"

#define SESSION_CN_MAX 128

static char store_dir[512];
static char device_dir[600];   /* selected per-device subdir, or "" */

/* ── Path helpers ────────────────────────────────────────────────────────── */

static void build_path(char *out, size_t out_size, const char *filename)
{
    snprintf(out, out_size, "%s/%s", store_dir, filename);
}

static void build_device_path(char *out, size_t sz, const char *filename)
{
    snprintf(out, sz, "%s/%s", device_dir, filename);
}

/* ── fp16 helper ─────────────────────────────────────────────────────────── */

/* Compute fp16 = SHA-256(pub)[0:8] as 16 lowercase hex chars + NUL */
static void fp16_of_pub(const uint8_t pub[32], char out[17])
{
    uint8_t hash[32];
    crypto_hash_sha256(hash, pub, 32);
    for (int i = 0; i < 8; i++)
        snprintf(out + i * 2, 3, "%02x", hash[i]);
    out[16] = '\0';
}

/* ── Flat-layout migration ───────────────────────────────────────────────── */

/*
 * If the old flat layout is present (device_pub.bin in store_dir), migrate it
 * to the per-device subdir.  Best-effort: missing files are silently skipped.
 * Sets device_dir on success.
 */
static void try_migrate_flat_layout(void)
{
    char old_pub[512];
    build_path(old_pub, sizeof(old_pub), "device_pub.bin");
    if (access(old_pub, F_OK) != 0)
        return;   /* nothing to migrate */

    /* Read the pubkey to compute fp16. */
    uint8_t pub[32];
    int fd = open(old_pub, O_RDONLY);
    if (fd < 0) return;
    ssize_t n = read(fd, pub, 32);
    close(fd);
    if (n != 32) return;

    char fp16[17];
    fp16_of_pub(pub, fp16);

    /* Create devices/<fp16>/ subdir. */
    char dev_sub[600];
    snprintf(dev_sub, sizeof(dev_sub), "%s/devices/%s", store_dir, fp16);
    mkdir(dev_sub, 0700);   /* ignore error — may already exist */

    /* Rename device_pub.bin, session_fp.bin, session_cn.bin (best-effort). */
    static const char *names[] = {
        "device_pub.bin", "session_fp.bin", "session_cn.bin", NULL
    };
    for (int i = 0; names[i]; i++) {
        char src[600], dst[700];
        build_path(src, sizeof(src), names[i]);
        snprintf(dst, sizeof(dst), "%s/%s", dev_sub, names[i]);
        if (access(src, F_OK) == 0)
            rename(src, dst);   /* same filesystem — safe */
    }

    snprintf(device_dir, sizeof(device_dir), "%s", dev_sub);
}

/* ── Init ────────────────────────────────────────────────────────────────── */

int key_store_init(void)
{
    const char *xdg = getenv("XDG_CONFIG_HOME");
    if (xdg && xdg[0]) {
        snprintf(store_dir, sizeof(store_dir), "%s/cantil", xdg);
    } else {
        const char *home = getenv("HOME");
        if (!home || !home[0])
            return -ENOENT;
        snprintf(store_dir, sizeof(store_dir), "%s/.config/cantil", home);
    }

    /* mkdir -p store_dir */
    char parent[512];
    snprintf(parent, sizeof(parent), "%s", store_dir);
    char *slash = strrchr(parent, '/');
    if (slash && slash != parent) {
        *slash = '\0';
        mkdir(parent, 0755);
    }
    if (mkdir(store_dir, 0700) < 0 && errno != EEXIST)
        return -errno;

    /* Ensure devices/ subdir exists. */
    char dev_base[600];
    snprintf(dev_base, sizeof(dev_base), "%s/devices", store_dir);
    mkdir(dev_base, 0700);   /* ignore EEXIST */

    /* Migrate any old flat layout to per-device subdir. */
    try_migrate_flat_layout();

    return 0;
}

int key_store_init_device(const uint8_t pub[32])
{
    char fp16[17];
    fp16_of_pub(pub, fp16);

    char dev_sub[600];
    snprintf(dev_sub, sizeof(dev_sub), "%s/devices/%s", store_dir, fp16);
    if (mkdir(dev_sub, 0700) < 0 && errno != EEXIST)
        return -errno;

    snprintf(device_dir, sizeof(device_dir), "%s", dev_sub);
    return 0;
}

int key_store_select_device(const uint8_t pub[32])
{
    char fp16[17];
    fp16_of_pub(pub, fp16);

    char dev_sub[600];
    snprintf(dev_sub, sizeof(dev_sub), "%s/devices/%s", store_dir, fp16);
    if (access(dev_sub, F_OK) != 0)
        return -ENOENT;

    snprintf(device_dir, sizeof(device_dir), "%s", dev_sub);
    return 0;
}

/* ── Low-level I/O helpers ───────────────────────────────────────────────── */

static int read_key_file(const char *path, uint8_t *buf, size_t len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -errno;

    ssize_t n = read(fd, buf, len);
    close(fd);
    if (n < 0)               return -errno;
    if ((size_t)n != len)    return -EIO;
    return 0;
}

static int write_key_file(const char *path, const uint8_t *buf, size_t len,
                           mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) return -errno;

    ssize_t n = write(fd, buf, len);
    close(fd);
    if (n < 0)               return -errno;
    if ((size_t)n != len)    return -EIO;
    return 0;
}

/* ── Client keypair (global) ─────────────────────────────────────────────── */

int key_store_load_client_keypair(uint8_t priv[32], uint8_t pub[32])
{
    char priv_path[512], pub_path[512];
    build_path(priv_path, sizeof(priv_path), "client_priv.bin");
    build_path(pub_path,  sizeof(pub_path),  "client_pub.bin");

    int ret = read_key_file(priv_path, priv, 32);
    if (ret) return ret;
    return read_key_file(pub_path, pub, 32);
}

int key_store_save_client_keypair(const uint8_t priv[32], const uint8_t pub[32])
{
    char priv_path[512], pub_path[512];
    build_path(priv_path, sizeof(priv_path), "client_priv.bin");
    build_path(pub_path,  sizeof(pub_path),  "client_pub.bin");

    int ret = write_key_file(priv_path, priv, 32, 0600);
    if (ret) return ret;
    return write_key_file(pub_path, pub, 32, 0644);
}

/* ── Per-device pubkey ───────────────────────────────────────────────────── */

int key_store_load_device_pubkey(uint8_t pub[32])
{
    char path[700];
    build_device_path(path, sizeof(path), "device_pub.bin");
    return read_key_file(path, pub, 32);
}

int key_store_save_device_pubkey(const uint8_t pub[32])
{
    char path[700];
    build_device_path(path, sizeof(path), "device_pub.bin");
    return write_key_file(path, pub, 32, 0644);
}

int key_store_has_device_pubkey(void)
{
    char path[700];
    build_device_path(path, sizeof(path), "device_pub.bin");
    return (access(path, F_OK) == 0) ? 1 : 0;
}

/* ── Per-device session fingerprint ─────────────────────────────────────── */

int key_store_save_session_fp(const uint8_t fp[32])
{
    char path[700];
    build_device_path(path, sizeof(path), "session_fp.bin");
    return write_key_file(path, fp, 32, 0644);
}

int key_store_load_session_fp(uint8_t fp[32])
{
    char path[700];
    build_device_path(path, sizeof(path), "session_fp.bin");
    return read_key_file(path, fp, 32);
}

/* ── Per-device session CN ───────────────────────────────────────────────── */

int key_store_save_session_cn(const char *cn)
{
    char path[700];
    build_device_path(path, sizeof(path), "session_cn.bin");
    size_t len = strlen(cn);
    if (len >= SESSION_CN_MAX)
        return -EINVAL;
    return write_key_file(path, (const uint8_t *)cn, len, 0644);
}

int key_store_load_session_cn(char *buf, size_t buflen)
{
    char path[700];
    build_device_path(path, sizeof(path), "session_cn.bin");

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -errno;

    ssize_t n = read(fd, buf, buflen - 1);
    close(fd);
    if (n < 0)  return -errno;
    if (n == 0) return -ENOENT;

    buf[n] = '\0';
    return 0;
}

/* ── Client certificate (Method 4, global) ───────────────────────────────── */

static int read_file_alloc(const char *path, uint8_t **out, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -errno;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -EIO; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -EIO; }
    rewind(f);

    if (sz == 0) { fclose(f); return -ENOENT; }

    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return -ENOMEM; }

    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return -EIO; }

    *out = buf;
    *out_len = (size_t)sz;
    return 0;
}

int key_store_save_client_cert(const uint8_t *cert_der, size_t cert_len)
{
    char path[700];
    build_path(path, sizeof(path), "client_cert.der");
    return write_key_file(path, cert_der, cert_len, 0644);
}

int key_store_load_client_cert(uint8_t **out, size_t *out_len)
{
    char path[700];
    build_path(path, sizeof(path), "client_cert.der");
    return read_file_alloc(path, out, out_len);
}

int key_store_has_client_cert(void)
{
    char path[700];
    build_path(path, sizeof(path), "client_cert.der");
    return (access(path, F_OK) == 0) ? 1 : 0;
}

int key_store_save_client_chain(const uint8_t *chain_der, size_t chain_len)
{
    char path[700];
    build_path(path, sizeof(path), "client_chain.der");
    return write_key_file(path, chain_der, chain_len, 0644);
}

int key_store_load_client_chain(uint8_t **out, size_t *out_len)
{
    char path[700];
    build_path(path, sizeof(path), "client_chain.der");
    return read_file_alloc(path, out, out_len);
}
