/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

/*
 * Client-side trust policy (Phase C, T-10/T-11/T-12).
 *
 * Trust store CRUD and policy evaluation.
 *   Tier 1: no check (T-11).
 *   Tier 2: SHA-256 leaf fingerprint, optional subject DN match (T-11/T-12).
 *   Tier 3: chain validation against an allowlisted CA (T-12).
 *   Tier 4: Tier 3 + CN pin (T-13).
 */

#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <dirent.h>

#include <sodium.h>

#include "trust.h"
#include "internal.h"
#include "x509.h"

/*
 * All X.509 work goes through x509.h, the swappable reader seam added in step
 * 5 of docs/roadmap/wolfssl-migration.md — OpenSSL (default) or wolfSSL, chosen
 * with -DCANTIL_HOST_CRYPTO. Nothing below names a certificate library, so a
 * new backend is one file and one CMake branch.
 *
 * The Cantil certificate profile (P-256/SHA-256) and the deliberate skipping
 * of validity dates (the device has no RTC) moved into the backends, since
 * each library expresses them differently — a manual leaf check in OpenSSL, an
 * explicit OID check in wolfSSL.
 */

/* ── Trust store ────────────────────────────────────────────────────────── */

#define STORE_INIT_CAP 4

cantil_trust_store_t *cantil_trust_store_new(void)
{
    cantil_trust_store_t *store = calloc(1, sizeof(*store));
    if (!store)
        return NULL;

    store->cert_der  = malloc(STORE_INIT_CAP * sizeof(uint8_t *));
    store->cert_len  = malloc(STORE_INIT_CAP * sizeof(size_t));
    if (!store->cert_der || !store->cert_len) {
        free(store->cert_der);
        free(store->cert_len);
        free(store);
        return NULL;
    }
    store->capacity = STORE_INIT_CAP;
    return store;
}

int cantil_trust_add_ca(cantil_trust_store_t *store,
                        const uint8_t *cert_der, size_t len)
{
    if (!store || !cert_der || len == 0)
        return -EINVAL;

    /* Grow the arrays if needed. */
    if (store->count == store->capacity) {
        size_t new_cap = store->capacity * 2;
        uint8_t **nd = realloc(store->cert_der, new_cap * sizeof(uint8_t *));
        size_t   *nl = realloc(store->cert_len,  new_cap * sizeof(size_t));
        if (!nd || !nl) {
            free(nd ? nd : store->cert_der);
            free(nl ? nl : store->cert_len);
            return -ENOMEM;
        }
        store->cert_der  = nd;
        store->cert_len  = nl;
        store->capacity  = new_cap;
    }

    uint8_t *copy = malloc(len);
    if (!copy)
        return -ENOMEM;
    memcpy(copy, cert_der, len);

    store->cert_der[store->count] = copy;
    store->cert_len[store->count] = len;
    store->count++;
    return 0;
}

int cantil_trust_load_dir(cantil_trust_store_t *store, const char *path)
{
    if (!store || !path)
        return -EINVAL;

    DIR *d = opendir(path);
    if (!d)
        return -errno;

    int loaded = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        /* Only load *.der files. */
        const char *name = ent->d_name;
        size_t nlen = strlen(name);
        if (nlen < 5 || strcmp(name + nlen - 4, ".der") != 0)
            continue;

        /* Build full path. */
        size_t plen = strlen(path);
        char *fpath = malloc(plen + 1 + nlen + 1);
        if (!fpath)
            continue;
        memcpy(fpath, path, plen);
        fpath[plen] = '/';
        memcpy(fpath + plen + 1, name, nlen + 1);

        FILE *f = fopen(fpath, "rb");
        free(fpath);
        if (!f)
            continue;

        /* Read the whole file. */
        if (fseek(f, 0, SEEK_END) != 0) {
            fclose(f);
            continue;
        }
        long fsz = ftell(f);
        rewind(f);
        if (fsz <= 0 || fsz > 65536) {  /* sanity cap: 64 KiB per cert */
            fclose(f);
            continue;
        }

        uint8_t *buf = malloc((size_t)fsz);
        if (!buf) {
            fclose(f);
            continue;
        }
        size_t got = fread(buf, 1, (size_t)fsz, f);
        fclose(f);
        if (got != (size_t)fsz) {
            free(buf);
            continue;
        }

        if (cantil_trust_add_ca(store, buf, got) == 0)
            loaded++;
        free(buf);
    }
    closedir(d);
    return loaded;
}

void cantil_trust_store_free(cantil_trust_store_t *store)
{
    if (!store)
        return;
    for (size_t i = 0; i < store->count; i++)
        free(store->cert_der[i]);
    free(store->cert_der);
    free(store->cert_len);
    free(store);
}

/* ── Policy evaluation ──────────────────────────────────────────────────── */

/*
 * Tier 2 helper: compare the leaf cert's raw Subject DER against the pinned
 * value in the policy. Returns CANTIL_OK on match, CANTIL_ERR_TRUST on mismatch,
 * CANTIL_ERR_TRUST if the cert cannot be parsed.
 */
static cantil_err_t tier2_check_subject(const cantil_trust_policy_t *policy,
                                        const uint8_t *leaf_der, size_t leaf_len)
{
    if (!policy->expected_subject_der || policy->expected_subject_der_len == 0)
        return CANTIL_OK;   /* optional field not set — skip */

    uint8_t subject[CANTIL_X509_SUBJECT_MAX];
    size_t  subject_len = 0;

    if (cantil_x509_subject_der(leaf_der, leaf_len,
                                subject, sizeof(subject), &subject_len)
            != CANTIL_X509_OK)
        return CANTIL_ERR_TRUST;

    /* Constant-time: the pinned DN is not secret, but comparing it in
     * variable time is a free habit to avoid, and sodium_memcmp is already
     * linked. Length is compared first because sodium_memcmp needs equal
     * lengths. */
    bool match = (subject_len == policy->expected_subject_der_len) &&
                 (sodium_memcmp(subject, policy->expected_subject_der,
                                subject_len) == 0);

    return match ? CANTIL_OK : CANTIL_ERR_TRUST;
}

/*
 * Tier 3: verify that the device cert chain (leaf + any intermediates delivered
 * in msg2) chains to at least one CA in the allowlist.
 *
 * The chain from the session is leaf-first; indices 1..n are intermediates.
 * Each CA in the trust store is tried as the anchor, and a successful verify
 * against any one of them passes Tier 3.
 *
 * Validity dates are not checked and the profile is pinned to P-256/SHA-256;
 * both live in the x509.h backend, since the two libraries express them
 * differently.
 */
static cantil_err_t tier3_chain_validate(const cantil_trust_policy_t *policy,
                                         const struct cantil_session  *s)
{
    if (!policy->trust_store || policy->trust_store->count == 0)
        return CANTIL_ERR_INVALID_ARG;

    const uint8_t *leaf_der;
    size_t         leaf_len;
    if (cantil_session_device_cert(s, 0, &leaf_der, &leaf_len) != 0)
        return CANTIL_ERR_TRUST;

    /* Collect the intermediates (indices 1..n) as plain byte pointers. The
     * session owns the storage and outlives this call, so nothing is copied. */
    size_t count = cantil_session_device_cert_count(s);
    size_t inter_count = 0;
    const uint8_t **inter_ders = NULL;
    size_t         *inter_lens = NULL;

    if (count > 1) {
        inter_ders = calloc(count - 1, sizeof(*inter_ders));
        inter_lens = calloc(count - 1, sizeof(*inter_lens));
        if (!inter_ders || !inter_lens) {
            free(inter_ders);
            free(inter_lens);
            return CANTIL_ERR_TRUST;
        }
        for (size_t i = 1; i < count; i++) {
            const uint8_t *der;
            size_t dlen;
            if (cantil_session_device_cert(s, i, &der, &dlen) != 0)
                continue;
            inter_ders[inter_count] = der;
            inter_lens[inter_count] = dlen;
            inter_count++;
        }
    }

    cantil_err_t result = CANTIL_ERR_TRUST;
    const cantil_trust_store_t *store = policy->trust_store;

    for (size_t i = 0; i < store->count && result != CANTIL_OK; i++) {
        if (cantil_x509_verify_chain(leaf_der, leaf_len,
                                     inter_ders, inter_lens, inter_count,
                                     store->cert_der[i], store->cert_len[i])
                == CANTIL_X509_OK)
            result = CANTIL_OK;
    }

    free(inter_ders);
    free(inter_lens);
    return result;
}

/*
 * Extract the CN from a certificate's subject DN into a NUL-terminated buffer.
 * Returns CANTIL_OK on success, CANTIL_ERR_TRUST if the cert is unreadable or
 * has no CN, CANTIL_ERR_INVALID_ARG if buf is too small.
 */
static cantil_err_t extract_cn(const uint8_t *cert_der, size_t cert_len,
                               char *buf, size_t buflen)
{
    switch (cantil_x509_subject_cn(cert_der, cert_len, buf, buflen)) {
    case CANTIL_X509_OK:        return CANTIL_OK;
    case CANTIL_X509_ERR_SPACE: return CANTIL_ERR_INVALID_ARG;
    default:                    return CANTIL_ERR_TRUST;
    }
}

/*
 * Tier 4: Tier 3 chain validation + CN pin. The leaf cert's CN must
 * case-sensitively equal policy->expected_cn.
 */
static cantil_err_t tier4_cn_validate(const cantil_trust_policy_t *policy,
                                      const struct cantil_session  *s)
{
    cantil_err_t rc = tier3_chain_validate(policy, s);
    if (rc != CANTIL_OK)
        return rc;

    if (!policy->expected_cn)
        return CANTIL_ERR_INVALID_ARG;

    const uint8_t *leaf_der;
    size_t         leaf_len;
    if (cantil_session_device_cert(s, 0, &leaf_der, &leaf_len) != 0)
        return CANTIL_ERR_TRUST;

    char cn_buf[128];
    cantil_err_t result = extract_cn(leaf_der, leaf_len, cn_buf, sizeof(cn_buf));
    if (result == CANTIL_OK && strcmp(cn_buf, policy->expected_cn) != 0)
        result = CANTIL_ERR_TRUST;

    return result;
}

/*
 * Extract the CN from the session's leaf cert (index 0) into a caller-supplied
 * buffer. Useful for TOFU upgrade: connect with Tier 3, record the CN, then
 * persist it and use CANTIL_TRUST_CA_PLUS_CN_PIN on subsequent sessions.
 *
 * buf must be at least 65 bytes (max CN per Cantil cert profile is 64 + NUL).
 * Returns CANTIL_OK on success, CANTIL_ERR_TRUST if no cert or no CN,
 * CANTIL_ERR_INVALID_ARG if buf is too small.
 */
cantil_err_t cantil_session_get_leaf_cn(const cantil_session_t *s,
                                        char *buf, size_t buflen)
{
    if (!s || !buf || buflen == 0)
        return CANTIL_ERR_INVALID_ARG;

    const uint8_t *leaf_der;
    size_t         leaf_len;
    if (cantil_session_device_cert(s, 0, &leaf_der, &leaf_len) != 0)
        return CANTIL_ERR_TRUST;

    return extract_cn(leaf_der, leaf_len, buf, buflen);
}

cantil_err_t cantil_trust_check_policy(const cantil_trust_policy_t *policy,
                                       const struct cantil_session  *s)
{
    if (!policy || policy->mode == CANTIL_TRUST_NONE)
        return CANTIL_OK;

    switch (policy->mode) {

    case CANTIL_TRUST_PINNED_SELF_SIGNED: {
        /* Tier 2: SHA-256 fingerprint of the leaf cert DER. */
        if (!policy->expected_fingerprint)
            return CANTIL_ERR_INVALID_ARG;

        const uint8_t *leaf;
        size_t leaf_len;
        if (cantil_session_device_cert(s, 0, &leaf, &leaf_len) != 0)
            return CANTIL_ERR_TRUST;   /* no cert in chain */

        uint8_t fp[crypto_hash_sha256_BYTES];
        crypto_hash_sha256(fp, leaf, leaf_len);

        if (sodium_memcmp(fp, policy->expected_fingerprint,
                          crypto_hash_sha256_BYTES) != 0)
            return CANTIL_ERR_TRUST;

        /* Optional subject DN pin (T-12). */
        return tier2_check_subject(policy, leaf, leaf_len);
    }

    case CANTIL_TRUST_CA_ALLOWLIST:
        return tier3_chain_validate(policy, s);

    case CANTIL_TRUST_CA_PLUS_CN_PIN:
        return tier4_cn_validate(policy, s);

    default:
        return CANTIL_ERR_INVALID_ARG;
    }
}
