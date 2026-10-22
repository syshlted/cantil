/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

/*
 * x509.h — OpenSSL implementation (CANTIL_HOST_CRYPTO=openssl, the default).
 *
 * The firmware is wolfCrypt-only (Phase 2 of docs/roadmap/wolfssl-migration.md);
 * the host client is deliberately a separate choice, because the client and the
 * device never share a build and the wire is backend-independent DER. OpenSSL is
 * the host default because it is the certificate library a Linux host is most
 * likely to already have, and because it is the *same third implementation* the
 * test fixtures and the firmware's OpenSSL gate are generated from — so this
 * backend matching the golden values in tests/test_x509.c is very nearly by
 * construction rather than luck.
 *
 * Two structural notes, both mirrors of the traps the wolfSSL backend hit:
 *
 *   - Subject DN is returned as the full DER TLV. i2d_X509_NAME() re-encodes the
 *     Name element tag-and-length included, which is exactly the seam's
 *     definition — unlike wolfSSL's subjectRaw, which points past the header.
 *   - There is no profile struct. OpenSSL's X509_verify_cert() will happily
 *     verify an RSA or non-P-256 chain, so the P-256/SHA-256/ECDSA restriction
 *     is enforced here by inspecting the leaf before trusting the verdict — the
 *     same job x509_wolfssl.c does with an OID check and x509_mbedtls.c gets for
 *     free from mbedtls_x509_crt_profile.
 *
 * Unlike wolfSSL, OpenSSL *does* have an untrusted-chain-material concept:
 * intermediates go into a separate STACK_OF(X509) passed to
 * X509_STORE_CTX_init(), and only the caller's anchor is added to the store.
 * Nothing in the untrusted stack can become a trust anchor, so the self-signed
 * "intermediate" attack the wolfSSL backend had to defend against by hand does
 * not arise here — the model is the same as mbedTLS's separate-argument one.
 */

#include <string.h>
#include <stdbool.h>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/obj_mac.h>
#include <openssl/asn1.h>

#include "x509.h"

const char *cantil_x509_backend_name(void)
{
    return "openssl";
}

/* ── parsing helper ─────────────────────────────────────────────────────── */

/*
 * Decode one DER certificate. d2i_X509 advances the pointer it is given, so a
 * local copy is used; a NULL result is any malformed input. Caller must
 * X509_free() a non-NULL return.
 */
static X509 *decode(const uint8_t *der, size_t len)
{
    if (!der || len == 0)
        return NULL;
    const unsigned char *p = der;
    return d2i_X509(NULL, &p, (long)len);
}

/*
 * Cantil profile check on the leaf: an ECDSA-with-SHA-256 signature over a
 * P-256 public key. OpenSSL has no profile struct, so this stands in for
 * mbedTLS's cantil_crt_profile / wolfSSL's profile_ok. A certificate outside it
 * is one the device could not have issued.
 *
 * Enforced on the leaf only, matching x509_wolfssl.c: the fixtures issue every
 * CA in-profile, and the guarantee the seam owes is that a non-P-256 *leaf*
 * never returns OK.
 */
static bool leaf_profile_ok(X509 *leaf)
{
    if (X509_get_signature_nid(leaf) != NID_ecdsa_with_SHA256)
        return false;

    EVP_PKEY *pk = X509_get0_pubkey(leaf);   /* borrowed, do not free */
    if (!pk || EVP_PKEY_get_base_id(pk) != EVP_PKEY_EC)
        return false;

    char grp[80];
    size_t glen = 0;
    if (EVP_PKEY_get_utf8_string_param(pk, OSSL_PKEY_PARAM_GROUP_NAME,
                                       grp, sizeof grp, &glen) != 1)
        return false;

    /* OpenSSL reports P-256 as its short name "prime256v1"; accept the
     * canonical "P-256" too so this does not become brittle to that choice. */
    return strcmp(grp, "prime256v1") == 0 || strcmp(grp, "P-256") == 0;
}

/* ── the seam ───────────────────────────────────────────────────────────── */

int cantil_x509_subject_der(const uint8_t *cert_der, size_t cert_len,
                            uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!cert_der || !out || !out_len || cert_len == 0)
        return CANTIL_X509_ERR_PARSE;

    X509 *crt = decode(cert_der, cert_len);
    if (!crt)
        return CANTIL_X509_ERR_PARSE;

    /*
     * i2d_X509_NAME() serialises the subject Name as a complete DER element —
     * the SEQUENCE tag and length, then the RDNs. That is the full TLV the seam
     * specifies, so no header reconstruction is needed (contrast x509_wolfssl.c).
     * The leaf was itself produced by OpenSSL, so this re-encoding reproduces
     * its original subject bytes exactly.
     */
    X509_NAME *name = X509_get_subject_name(crt);   /* borrowed */
    unsigned char *tmp = NULL;
    int nlen = name ? i2d_X509_NAME(name, &tmp) : -1;

    int ret;
    if (nlen <= 0) {
        ret = CANTIL_X509_ERR_PARSE;
    } else if ((size_t)nlen > out_cap) {
        ret = CANTIL_X509_ERR_SPACE;
    } else {
        memcpy(out, tmp, (size_t)nlen);
        *out_len = (size_t)nlen;
        ret = CANTIL_X509_OK;
    }

    OPENSSL_free(tmp);
    X509_free(crt);
    return ret;
}

int cantil_x509_subject_cn(const uint8_t *cert_der, size_t cert_len,
                           char *out, size_t out_cap)
{
    if (!cert_der || !out || out_cap == 0 || cert_len == 0)
        return CANTIL_X509_ERR_PARSE;

    X509 *crt = decode(cert_der, cert_len);
    if (!crt)
        return CANTIL_X509_ERR_PARSE;

    X509_NAME *name = X509_get_subject_name(crt);
    int idx = name ? X509_NAME_get_index_by_NID(name, NID_commonName, -1) : -1;
    if (idx < 0) {
        X509_free(crt);
        return CANTIL_X509_ERR_ABSENT;
    }

    /*
     * Copy the raw ASN.1 string content, exactly as the mbedTLS and wolfSSL
     * backends copy n->val / subjectCN: Cantil CNs are PrintableString /
     * UTF8String, so the content bytes are the text. Measuring the entry here
     * (rather than trusting X509_NAME_get_text_by_NID to report a length) is
     * what lets ERR_SPACE be exact instead of a silent truncation.
     */
    X509_NAME_ENTRY *e = X509_NAME_get_entry(name, idx);
    ASN1_STRING *s = X509_NAME_ENTRY_get_data(e);
    int slen = ASN1_STRING_length(s);
    const unsigned char *sdata = ASN1_STRING_get0_data(s);

    int ret;
    if (slen < 0 || (size_t)slen + 1 > out_cap) {
        ret = CANTIL_X509_ERR_SPACE;
    } else {
        memcpy(out, sdata, (size_t)slen);
        out[slen] = '\0';
        ret = CANTIL_X509_OK;
    }

    X509_free(crt);
    return ret;
}

int cantil_x509_verify_chain(const uint8_t *leaf_der, size_t leaf_len,
                             const uint8_t *const inter_ders[],
                             const size_t inter_lens[],
                             size_t inter_count,
                             const uint8_t *ca_der, size_t ca_len)
{
    if (!leaf_der || leaf_len == 0 || !ca_der || ca_len == 0)
        return CANTIL_X509_ERR_PARSE;

    X509           *leaf      = NULL;
    X509           *ca        = NULL;
    STACK_OF(X509) *untrusted = NULL;
    X509_STORE     *store     = NULL;
    X509_STORE_CTX *ctx       = NULL;
    int ret = CANTIL_X509_ERR_CHAIN;

    leaf = decode(leaf_der, leaf_len);
    if (!leaf) { ret = CANTIL_X509_ERR_PARSE; goto out; }

    ca = decode(ca_der, ca_len);
    if (!ca) { ret = CANTIL_X509_ERR_PARSE; goto out; }

    /* Refuse anything outside Cantil's P-256/SHA-256 profile before spending a
     * verification on it — an in-policy refusal, surfaced as ERR_CHAIN. */
    if (!leaf_profile_ok(leaf)) { ret = CANTIL_X509_ERR_CHAIN; goto out; }

    /*
     * Intermediates are untrusted chain material, never anchors. An unparseable
     * one is skipped, not fatal: the device may ship a chain element this client
     * cannot use, and the chain can still verify without it (mirrors both other
     * backends).
     */
    untrusted = sk_X509_new_null();
    if (!untrusted) { ret = CANTIL_X509_ERR_INTERNAL; goto out; }
    for (size_t i = 0; i < inter_count; i++) {
        if (!inter_ders[i] || inter_lens[i] == 0)
            continue;
        X509 *ic = decode(inter_ders[i], inter_lens[i]);
        if (ic && sk_X509_push(untrusted, ic) <= 0)
            X509_free(ic);
    }

    /* Only the caller's anchor is trusted. */
    store = X509_STORE_new();
    if (!store || X509_STORE_add_cert(store, ca) != 1) {
        ret = CANTIL_X509_ERR_INTERNAL;
        goto out;
    }

    ctx = X509_STORE_CTX_new();
    if (!ctx || X509_STORE_CTX_init(ctx, store, leaf, untrusted) != 1) {
        ret = CANTIL_X509_ERR_INTERNAL;
        goto out;
    }

    /*
     * Do NOT check validity dates. The device has no RTC and issues a synthetic
     * window; enforcing dates would reject every real Cantil certificate. This
     * is the OpenSSL equivalent of the mbedTLS backend's chain_vrfy_cb clearing
     * BADCERT_EXPIRED/FUTURE and the wolfSSL backend's date-tolerant callback.
     */
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_NO_CHECK_TIME);

    if (X509_verify_cert(ctx) == 1)
        ret = CANTIL_X509_OK;   /* else stays ERR_CHAIN */

out:
    if (ctx)   X509_STORE_CTX_free(ctx);
    if (store) X509_STORE_free(store);
    if (untrusted) sk_X509_pop_free(untrusted, X509_free);
    if (ca)    X509_free(ca);
    if (leaf)  X509_free(leaf);
    return ret;
}
