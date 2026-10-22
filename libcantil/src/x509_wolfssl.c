/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

/*
 * x509.h — wolfSSL implementation (CANTIL_HOST_CRYPTO=wolfssl).
 *
 * Step 5 of docs/roadmap/wolfssl-migration.md. Matches the library the
 * firmware uses, so a client built this way shares a DER implementation with
 * the device that issued the certificates.
 *
 * Needs a host wolfSSL, which Fedora does not package —
 * scripts/setup_wolfssl_host.sh builds one from the same revision
 * firmware/west.yml pins.
 *
 * Two structural differences from the mbedTLS backend:
 *
 *   - Reading a certificate uses wolfCrypt's DecodedCert directly, but
 *     *verifying a chain* needs wolfSSL's CertManager, which lives above
 *     wolfCrypt. There is no WOLFCRYPT_ONLY chain walker, which is why the
 *     host build is not WOLFCRYPT_ONLY while the firmware's is.
 *   - There is no profile struct. mbedTLS takes an mbedtls_x509_crt_profile;
 *     wolfSSL has no equivalent, so the P-256/SHA-256 restriction is enforced
 *     here by inspecting each certificate's algorithm OIDs before trusting the
 *     CertManager's verdict.
 */

#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "x509.h"

const char *cantil_x509_backend_name(void)
{
    return "wolfssl";
}

/* ── parsing helpers ────────────────────────────────────────────────────── */

/*
 * Parse into a DecodedCert without verifying (NO_VERIFY): the caller either
 * only wants a field, or is about to verify the whole chain properly through
 * the CertManager. Caller must wc_FreeDecodedCert on success.
 */
static int decode(const uint8_t *der, size_t len, DecodedCert *dc)
{
    wc_InitDecodedCert(dc, der, (word32)len, NULL);
    if (wc_ParseCert(dc, CERT_TYPE, NO_VERIFY, NULL) != 0) {
        wc_FreeDecodedCert(dc);
        return CANTIL_X509_ERR_PARSE;
    }
    return CANTIL_X509_OK;
}

/*
 * Cantil profile check: SHA-256/ECDSA signature over a P-256 key. wolfSSL has
 * no profile struct, so this stands in for mbedTLS's cantil_crt_profile. A
 * certificate outside the profile is one the device could not have issued.
 */
static bool profile_ok(const DecodedCert *dc)
{
    return dc->signatureOID == CTC_SHA256wECDSA &&
           dc->keyOID       == ECDSAk &&
           dc->pkCurveOID   == ECC_SECP256R1_OID;
}

/* ── the seam ───────────────────────────────────────────────────────────── */

int cantil_x509_subject_der(const uint8_t *cert_der, size_t cert_len,
                            uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!cert_der || !out || !out_len || cert_len == 0)
        return CANTIL_X509_ERR_PARSE;

    DecodedCert dc;
    int ret = decode(cert_der, cert_len, &dc);
    if (ret != CANTIL_X509_OK)
        return ret;

    if (!dc.subjectRaw || dc.subjectRawLen <= 0) {
        wc_FreeDecodedCert(&dc);
        return CANTIL_X509_ERR_ABSENT;
    }

    /*
     * THE COMPATIBILITY TRAP, and the reason this is not a one-line memcpy.
     *
     * wolfSSL sets subjectRaw *after* GetASN_Sequence has consumed the tag and
     * length, so it points at the SEQUENCE contents and subjectRawLen counts
     * only those. mbedTLS's subject_raw spans the whole TLV. The seam
     * specifies the full TLV (see x509.h), because that is what mbedTLS-built
     * clients already pinned — so reconstruct the header wolfSSL skipped.
     *
     * The header is one tag byte plus DER's length encoding: short form for
     * lengths under 128, else 0x80|n followed by n big-endian length bytes.
     * A DN is a few hundred bytes, so n is 1 or 2 in practice; 3 and 4 are
     * handled anyway rather than left as a lurking bound.
     */
    size_t content_len = (size_t)dc.subjectRawLen;
    size_t hdr;
    if (content_len < 0x80)          hdr = 2;
    else if (content_len <= 0xFF)    hdr = 3;
    else if (content_len <= 0xFFFF)  hdr = 4;
    else                             hdr = 5;

    const uint8_t *tlv = dc.subjectRaw - hdr;

    /* Never walk off the front of the caller's buffer, and confirm the
     * reconstruction actually lands on a SEQUENCE tag — if wolfSSL ever
     * changes what subjectRaw points at, this fails loudly instead of
     * silently pinning the wrong bytes. */
    if (tlv < cert_der || tlv[0] != (ASN_CONSTRUCTED | ASN_SEQUENCE)) {
        wc_FreeDecodedCert(&dc);
        return CANTIL_X509_ERR_PARSE;
    }

    size_t total = hdr + content_len;
    if (total > out_cap) {
        wc_FreeDecodedCert(&dc);
        return CANTIL_X509_ERR_SPACE;
    }

    memcpy(out, tlv, total);
    *out_len = total;
    wc_FreeDecodedCert(&dc);
    return CANTIL_X509_OK;
}

int cantil_x509_subject_cn(const uint8_t *cert_der, size_t cert_len,
                           char *out, size_t out_cap)
{
    if (!cert_der || !out || out_cap == 0 || cert_len == 0)
        return CANTIL_X509_ERR_PARSE;

    DecodedCert dc;
    int ret = decode(cert_der, cert_len, &dc);
    if (ret != CANTIL_X509_OK)
        return ret;

    if (!dc.subjectCN || dc.subjectCNLen <= 0) {
        wc_FreeDecodedCert(&dc);
        return CANTIL_X509_ERR_ABSENT;
    }

    size_t cnlen = (size_t)dc.subjectCNLen;
    if (cnlen + 1 > out_cap) {
        wc_FreeDecodedCert(&dc);
        return CANTIL_X509_ERR_SPACE;
    }

    memcpy(out, dc.subjectCN, cnlen);
    out[cnlen] = '\0';
    wc_FreeDecodedCert(&dc);
    return CANTIL_X509_OK;
}

/*
 * CertManager verify callback. Accept a chain that failed *only* on validity
 * dates — the device has no RTC and issues a synthetic window, exactly as the
 * mbedTLS backend's chain_vrfy_cb clears BADCERT_EXPIRED / BADCERT_FUTURE.
 *
 * Deliberately narrow: it overrides two specific error codes and nothing else,
 * rather than returning 1 unconditionally, which would turn every verification
 * failure into a pass.
 */
static int date_tolerant_verify(int preverify, WOLFSSL_X509_STORE_CTX *store)
{
    if (preverify)
        return 1;

    int err = wolfSSL_X509_STORE_CTX_get_error(store);
    if (err == ASN_BEFORE_DATE_E || err == ASN_AFTER_DATE_E)
        return 1;
    return 0;
}

int cantil_x509_verify_chain(const uint8_t *leaf_der, size_t leaf_len,
                             const uint8_t *const inter_ders[],
                             const size_t inter_lens[],
                             size_t inter_count,
                             const uint8_t *ca_der, size_t ca_len)
{
    if (!leaf_der || leaf_len == 0 || !ca_der || ca_len == 0)
        return CANTIL_X509_ERR_PARSE;

    /* Profile-check the leaf up front. wolfSSL will happily verify a chain
     * using an algorithm Cantil never issues; mbedTLS would have rejected it
     * via the profile, so reject it here to keep the two backends agreeing. */
    DecodedCert leaf;
    int ret = decode(leaf_der, leaf_len, &leaf);
    if (ret != CANTIL_X509_OK)
        return ret;
    bool ok = profile_ok(&leaf);
    wc_FreeDecodedCert(&leaf);
    if (!ok)
        return CANTIL_X509_ERR_CHAIN;

    WOLFSSL_CERT_MANAGER *cm = wolfSSL_CertManagerNew();
    if (!cm)
        return CANTIL_X509_ERR_INTERNAL;

    wolfSSL_CertManagerSetVerify(cm, date_tolerant_verify);

    ret = CANTIL_X509_ERR_CHAIN;

    /*
     * Only the caller's anchor is loaded as a CA. This is the whole security
     * argument of this function, and it is not obvious:
     *
     * wolfSSL has no "untrusted chain material" concept. mbedTLS takes the
     * intermediates as a separate argument and treats them as untrusted certs
     * to be verified; wolfSSL's only way to make a certificate available to
     * the walker is wolfSSL_CertManagerLoadCABuffer, which makes it a TRUST
     * ANCHOR. Loading the device-supplied intermediates up front therefore
     * trusts them unconditionally — a peer could send a self-signed cert as
     * its "intermediate" and have its leaf accepted against any anchor at all.
     * The first draft of this file did exactly that, and
     * test_chain_wrong_anchor caught it: an unrelated root returned OK.
     *
     * So intermediates are promoted one at a time, and only after they have
     * themselves verified against what is already trusted. That reproduces
     * mbedTLS's semantics: nothing becomes an anchor without a path back to
     * the caller's CA.
     *
     * WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY because loading date-checks too, and the
     * verify callback above does not cover the load path.
     */
    if (wolfSSL_CertManagerLoadCABuffer_ex(cm, ca_der, (long)ca_len,
                                           WOLFSSL_FILETYPE_ASN1, 0,
                                           WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY)
            != WOLFSSL_SUCCESS) {
        ret = CANTIL_X509_ERR_PARSE;
        goto out;
    }

    /*
     * Incremental path building. Each round promotes every intermediate that
     * now verifies, then tries the leaf again. Bounded by inter_count + 1
     * rounds: a chain of n intermediates needs at most n promotions, and the
     * loop exits as soon as a round promotes nothing.
     *
     * An intermediate that never verifies is simply never promoted — the same
     * outcome as the mbedTLS backend skipping one it cannot parse.
     */
    bool *promoted = NULL;
    if (inter_count > 0) {
        promoted = calloc(inter_count, sizeof(*promoted));
        if (!promoted) {
            ret = CANTIL_X509_ERR_INTERNAL;
            goto out;
        }
    }

    for (size_t round = 0; round <= inter_count; round++) {
        if (wolfSSL_CertManagerVerifyBuffer(cm, leaf_der, (long)leaf_len,
                                            WOLFSSL_FILETYPE_ASN1)
                == WOLFSSL_SUCCESS) {
            ret = CANTIL_X509_OK;
            break;
        }

        bool progress = false;
        for (size_t i = 0; i < inter_count; i++) {
            if (promoted[i] || !inter_ders[i] || inter_lens[i] == 0)
                continue;

            /* Verify against the currently-trusted set before trusting it. */
            if (wolfSSL_CertManagerVerifyBuffer(cm, inter_ders[i],
                                                (long)inter_lens[i],
                                                WOLFSSL_FILETYPE_ASN1)
                    != WOLFSSL_SUCCESS)
                continue;

            if (wolfSSL_CertManagerLoadCABuffer_ex(
                        cm, inter_ders[i], (long)inter_lens[i],
                        WOLFSSL_FILETYPE_ASN1, 0,
                        WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY) == WOLFSSL_SUCCESS) {
                promoted[i] = true;
                progress = true;
            }
        }

        if (!progress)
            break;
    }

    free(promoted);

out:
    wolfSSL_CertManagerFree(cm);
    return ret;
}
