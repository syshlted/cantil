/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

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
#include <mbedtls/oid.h>
#include <mbedtls/x509_crt.h>

#include "trust.h"
#include "internal.h"

/*
 * Certificate profile: P-256 keys, SHA-256 signatures only.
 * Matches the Cantil session cert profile (firmware ca.c).
 */
static const mbedtls_x509_crt_profile cantil_crt_profile = {
    .allowed_mds    = MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256),
    .allowed_pks    = MBEDTLS_X509_ID_FLAG(MBEDTLS_PK_ECDSA),
    .allowed_curves = MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP256R1),
    .rsa_min_bitlen = 0,
};

/*
 * Verify callback: clear time-based verdicts. The device cert may have a
 * synthetic validity window (no RTC on device); only signatures and trust
 * are checked, matching the firmware's chain_vrfy_cb in ca.c.
 */
static int chain_vrfy_cb(void *ctx, mbedtls_x509_crt *crt, int depth,
                         uint32_t *flags)
{
    (void)ctx; (void)crt; (void)depth;
    *flags &= ~(uint32_t)(MBEDTLS_X509_BADCERT_EXPIRED |
                          MBEDTLS_X509_BADCERT_FUTURE);
    return 0;
}

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

    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse_der(&crt, leaf_der, leaf_len) != 0) {
        mbedtls_x509_crt_free(&crt);
        return CANTIL_ERR_TRUST;
    }

    bool match = (crt.subject_raw.len == policy->expected_subject_der_len) &&
                 (memcmp(crt.subject_raw.p,
                         policy->expected_subject_der,
                         crt.subject_raw.len) == 0);

    mbedtls_x509_crt_free(&crt);
    return match ? CANTIL_OK : CANTIL_ERR_TRUST;
}

/*
 * Tier 3: verify that the device cert chain (leaf + any intermediates delivered
 * in msg2) chains to at least one CA in the allowlist.
 *
 * The chain from the session is leaf-first. Intermediates (indices 1..n) are
 * linked as leaf.next so mbedtls can walk them. Each CA in the trust store is
 * tried as the trust anchor; a successful verify against any one CA passes Tier 3.
 *
 * Time-based flags (EXPIRED / FUTURE) are cleared by chain_vrfy_cb because the
 * device cert may have a synthetic validity window (no RTC on device).
 */
static cantil_err_t tier3_chain_validate(const cantil_trust_policy_t *policy,
                                         const struct cantil_session  *s)
{
    if (!policy->trust_store || policy->trust_store->count == 0)
        return CANTIL_ERR_INVALID_ARG;

    /* Parse the leaf cert (index 0). */
    const uint8_t *leaf_der;
    size_t         leaf_len;
    if (cantil_session_device_cert(s, 0, &leaf_der, &leaf_len) != 0)
        return CANTIL_ERR_TRUST;

    mbedtls_x509_crt leaf;
    mbedtls_x509_crt_init(&leaf);
    if (mbedtls_x509_crt_parse_der(&leaf, leaf_der, leaf_len) != 0) {
        mbedtls_x509_crt_free(&leaf);
        return CANTIL_ERR_TRUST;
    }

    /* Parse any intermediate certs (indices 1..n) and link as leaf->next. */
    size_t count = cantil_session_device_cert_count(s);
    mbedtls_x509_crt intermediates;
    mbedtls_x509_crt_init(&intermediates);
    bool has_intermediates = false;

    for (size_t i = 1; i < count; i++) {
        const uint8_t *der;
        size_t dlen;
        if (cantil_session_device_cert(s, i, &der, &dlen) != 0)
            continue;
        if (mbedtls_x509_crt_parse_der(&intermediates, der, dlen) == 0)
            has_intermediates = true;
    }

    if (has_intermediates)
        leaf.next = &intermediates;

    /* Try each CA in the allowlist as the trust anchor. */
    cantil_err_t result = CANTIL_ERR_TRUST;
    const cantil_trust_store_t *store = policy->trust_store;

    for (size_t i = 0; i < store->count && result != CANTIL_OK; i++) {
        mbedtls_x509_crt ca_cert;
        mbedtls_x509_crt_init(&ca_cert);

        if (mbedtls_x509_crt_parse_der(&ca_cert,
                                        store->cert_der[i],
                                        store->cert_len[i]) != 0) {
            mbedtls_x509_crt_free(&ca_cert);
            continue;
        }

        uint32_t flags = 0;
        int rc = mbedtls_x509_crt_verify_with_profile(
                &leaf, &ca_cert, NULL,
                &cantil_crt_profile,
                NULL,   /* no CN check here; that is Tier 4 (T-13) */
                &flags, chain_vrfy_cb, NULL);

        mbedtls_x509_crt_free(&ca_cert);

        if (rc == 0 && flags == 0)
            result = CANTIL_OK;
    }

    leaf.next = NULL;   /* sever before freeing either list */
    mbedtls_x509_crt_free(&intermediates);
    mbedtls_x509_crt_free(&leaf);
    return result;
}

/*
 * Extract the CN from a parsed mbedtls cert's subject DN into a NUL-terminated
 * buffer. Returns CANTIL_OK on success, CANTIL_ERR_TRUST if no CN is present,
 * CANTIL_ERR_INVALID_ARG if buf is too small.
 */
static cantil_err_t extract_cn_from_crt(const mbedtls_x509_crt *crt,
                                        char *buf, size_t buflen)
{
    const mbedtls_x509_name *name = &crt->subject;
    while (name) {
        if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &name->oid) == 0) {
            if (name->val.len + 1 > buflen)
                return CANTIL_ERR_INVALID_ARG;
            memcpy(buf, name->val.p, name->val.len);
            buf[name->val.len] = '\0';
            return CANTIL_OK;
        }
        name = name->next;
    }
    return CANTIL_ERR_TRUST;  /* no CN in subject */
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

    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse_der(&crt, leaf_der, leaf_len) != 0) {
        mbedtls_x509_crt_free(&crt);
        return CANTIL_ERR_TRUST;
    }

    char cn_buf[128];
    cantil_err_t result = extract_cn_from_crt(&crt, cn_buf, sizeof(cn_buf));
    if (result == CANTIL_OK && strcmp(cn_buf, policy->expected_cn) != 0)
        result = CANTIL_ERR_TRUST;

    mbedtls_x509_crt_free(&crt);
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

    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse_der(&crt, leaf_der, leaf_len) != 0) {
        mbedtls_x509_crt_free(&crt);
        return CANTIL_ERR_TRUST;
    }

    cantil_err_t rc = extract_cn_from_crt(&crt, buf, buflen);
    mbedtls_x509_crt_free(&crt);
    return rc;
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
