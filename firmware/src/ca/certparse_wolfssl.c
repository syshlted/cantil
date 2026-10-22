/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

/*
 * certparse.h — wolfCrypt implementation (WOLFSSL backend).
 *
 * Step 6a of docs/roadmap/wolfssl-migration.md. Reading fields out of a
 * certificate is straightforward — wolfCrypt's DecodedCert exposes everything
 * ca.c wants. Verifying a *chain* is not, and is most of this file.
 *
 * Why the chain walker is written here rather than called:
 *
 *   The firmware is WOLFCRYPT_ONLY. wolfSSL's chain walker lives in the TLS
 *   layer that flag excludes (src/ssl_certman.c is #include'd into ssl.c and
 *   needs a TLS method), and pulling that in would add a TLS state machine —
 *   internal.c, tls.c, tls13.c — to a device that has no network interface.
 *   wolfCrypt does expose the one primitive that matters,
 *   wc_CheckCertSigPubKey (guarded by WOLFSSL_SMALL_CERT_VERIFY): verify a
 *   certificate's signature against a supplied public key. Path building on
 *   top of it is ours.
 *
 * The rule that makes it safe is the same one the host seam learned the hard
 * way (libcantil/src/x509_wolfssl.c): ONLY THE ANCHOR IS TRUSTED A PRIORI. An
 * intermediate arrives from whoever is talking to us, so it is used only after
 * it has itself verified against something already trusted. Trusting the
 * supplied intermediates up front — the obvious implementation — lets a peer
 * present a self-signed certificate as its "intermediate" and have its leaf
 * accepted against any anchor at all.
 */

#include <string.h>
#include <errno.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "ca/certparse.h"
#include "ca/oids.h"

/*
 * Its own log module rather than LOG_MODULE_DECLARE(ca): this file is built by
 * the certparse_wolfssl test suite, which does not link ca.c, so declaring a
 * module registered there would leave log_const_ca undefined at link time.
 */
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(certparse, LOG_LEVEL_INF);

/* Cantil chains are shallow: a leaf, at most a couple of sub-CAs, an anchor.
 * The bound stops a malicious blob from making us loop. */
#define CERTPARSE_MAX_INTER 8

/* ── field extraction ───────────────────────────────────────────────────── */

static void dn_set(char *dst, size_t cap, const char *src, int srclen, bool *overflow)
{
	size_t len = (srclen > 0) ? (size_t)srclen : 0;

	if (len >= cap) {
		*overflow = true;
		len = cap - 1;
	}
	memcpy(dst, src, len);
	dst[len] = '\0';
}

/*
 * wolfCrypt decodes the subject into fixed accessors rather than a list, so the
 * six RDNs come straight off DecodedCert. Anything else is dropped, matching
 * the mbedTLS backend and the fact that Cantil issues only these six.
 */
static void fill_dn(const DecodedCert *dc, certgen_dn_t *dn, bool *overflow)
{
	memset(dn, 0, sizeof(*dn));
	if (dc->subjectCN) {
		dn_set(dn->cn, sizeof(dn->cn), dc->subjectCN, dc->subjectCNLen, overflow);
	}
	if (dc->subjectO) {
		dn_set(dn->o, sizeof(dn->o), dc->subjectO, dc->subjectOLen, overflow);
	}
	if (dc->subjectOU) {
		dn_set(dn->ou, sizeof(dn->ou), dc->subjectOU, dc->subjectOULen, overflow);
	}
	if (dc->subjectC) {
		dn_set(dn->c, sizeof(dn->c), dc->subjectC, dc->subjectCLen, overflow);
	}
	if (dc->subjectST) {
		dn_set(dn->st, sizeof(dn->st), dc->subjectST, dc->subjectSTLen, overflow);
	}
	if (dc->subjectL) {
		dn_set(dn->l, sizeof(dn->l), dc->subjectL, dc->subjectLLen, overflow);
	}
}

static const uint8_t *find_bytes(const uint8_t *hay, size_t hay_len, const uint8_t *needle,
				 size_t needle_len)
{
	if (needle_len == 0 || hay_len < needle_len) {
		return NULL;
	}
	for (size_t i = 0; i + needle_len <= hay_len; i++) {
		if (memcmp(hay + i, needle, needle_len) == 0) {
			return hay + i;
		}
	}
	return NULL;
}

/*
 * Scan the raw extensions blob for the X25519 binding, exactly as the mbedTLS
 * backend does. A byte scan rather than a proper extension walk because both
 * backends must agree on what counts as present, and this is what shipped.
 */
static bool extract_x25519(const DecodedCert *dc, uint8_t out[32])
{
	const uint8_t *ext = dc->extensions;
	size_t ext_len = (dc->extensionsSz > 0) ? (size_t)dc->extensionsSz : 0;

	if (ext == NULL || ext_len == 0) {
		return false;
	}

	const uint8_t *oid = find_bytes(ext, ext_len, OID_SESSION_X25519, OID_SESSION_X25519_LEN);

	if (oid == NULL) {
		return false;
	}

	const uint8_t *after = oid + OID_SESSION_X25519_LEN;
	const uint8_t *end = ext + ext_len;
	const uint8_t os_hdr[] = {0x04, 0x20};
	const uint8_t *os = find_bytes(after, (size_t)(end - after), os_hdr, sizeof(os_hdr));

	if (os == NULL || os + 2 + 32 > end) {
		return false;
	}
	memcpy(out, os + 2, 32);
	return true;
}

/*
 * DecodedCert.publicKey is the whole SubjectPublicKeyInfo, not the point. The
 * uncompressed P-256 point is the last 65 bytes of it, and it must start with
 * 0x04 — checked rather than assumed, so a key that is not an uncompressed
 * P-256 point reports has_pubkey = false instead of yielding 65 wrong bytes.
 */
static bool extract_pubkey(const DecodedCert *dc, uint8_t out[65])
{
	if (!dc->publicKey || dc->pubKeySize < 65) {
		return false;
	}

	const uint8_t *pt = dc->publicKey + dc->pubKeySize - 65;

	if (pt[0] != 0x04) {
		return false;
	}
	memcpy(out, pt, 65);
	return true;
}

/*
 * notAfter, as year/month/day. wolfCrypt hands back the raw ASN.1 time rather
 * than a parsed struct, so this undoes what certgen_wolfssl.c's encode_time
 * does: UTCTime carries a 2-digit year (RFC 5280: 00-49 => 20xx, 50-99 =>
 * 19xx), GeneralizedTime a 4-digit one.
 *
 * The pointer may or may not include the tag and length depending on wolfSSL's
 * parser path, so sniff for a time tag rather than assuming either. On
 * anything unexpected the fields are left zeroed, which callers read as
 * "unknown" — never as a match.
 */
static void parse_after_date(const DecodedCert *dc, certparse_cert_t *out)
{
	const uint8_t *d = dc->afterDate;
	int len = dc->afterDateLen;

	if (!d || len < 2) {
		return;
	}

	uint8_t tag = d[0];

	if (tag == ASN_UTC_TIME || tag == ASN_GENERALIZED_TIME) {
		len = d[1];
		d += 2;
	} else {
		/* Already the value; infer the format from its length.
		 * "YYMMDDHHMMSSZ" is 13, "YYYYMMDDHHMMSSZ" is 15. */
		tag = (len >= 15) ? ASN_GENERALIZED_TIME : ASN_UTC_TIME;
	}

	int need = (tag == ASN_GENERALIZED_TIME) ? 8 : 6;

	if (len < need) {
		return;
	}
	for (int i = 0; i < need; i++) {
		if (d[i] < '0' || d[i] > '9') {
			return;
		}
	}

	int y, idx;

	if (tag == ASN_GENERALIZED_TIME) {
		y = (d[0] - '0') * 1000 + (d[1] - '0') * 100 + (d[2] - '0') * 10 + (d[3] - '0');
		idx = 4;
	} else {
		int yy = (d[0] - '0') * 10 + (d[1] - '0');

		y = (yy < 50) ? 2000 + yy : 1900 + yy;
		idx = 2;
	}

	out->na_year = (uint16_t)y;
	out->na_mon = (uint8_t)((d[idx] - '0') * 10 + (d[idx + 1] - '0'));
	out->na_day = (uint8_t)((d[idx + 2] - '0') * 10 + (d[idx + 3] - '0'));
}

/*
 * Reconstruct the subject DN as a complete TLV.
 *
 * wolfSSL sets subjectRaw *after* the SEQUENCE tag and length are consumed, so
 * it points at the contents; mbedTLS's subject_raw spans the whole element, and
 * that is what the seam specifies because the CRL encoder copies these bytes
 * into the issuer field verbatim. Emitting contents-only would produce a CRL
 * whose issuer Name is missing its header.
 *
 * Same reconstruction as libcantil/src/x509_wolfssl.c, including the check that
 * the recovered header really is a SEQUENCE tag — so a future wolfSSL change
 * fails loudly rather than silently corrupting a CRL.
 */
static void fill_subject_der(const DecodedCert *dc, const uint8_t *der, certparse_cert_t *out)
{
	if (!dc->subjectRaw || dc->subjectRawLen <= 0) {
		return;
	}

	size_t content_len = (size_t)dc->subjectRawLen;
	size_t hdr;

	if (content_len < 0x80) {
		hdr = 2;
	} else if (content_len <= 0xFF) {
		hdr = 3;
	} else if (content_len <= 0xFFFF) {
		hdr = 4;
	} else {
		hdr = 5;
	}

	const uint8_t *tlv = dc->subjectRaw - hdr;
	size_t total = hdr + content_len;

	if (tlv < der || total > CERTPARSE_SUBJECT_MAX ||
	    tlv[0] != (ASN_CONSTRUCTED | ASN_SEQUENCE)) {
		return;
	}

	memcpy(out->subject_der, tlv, total);
	out->subject_der_len = total;
}

/* Parse without verifying — the caller either wants fields, or is about to
 * verify the chain properly below. */
static int decode(const uint8_t *der, size_t len, DecodedCert *dc)
{
	wc_InitDecodedCert(dc, der, (word32)len, NULL);
	if (wc_ParseCert(dc, CERT_TYPE, NO_VERIFY, NULL) != 0) {
		wc_FreeDecodedCert(dc);
		return -EINVAL;
	}
	return 0;
}

int certparse_cert(const uint8_t *der, size_t len, certparse_cert_t *out)
{
	if (!der || !out || len == 0) {
		return -EINVAL;
	}

	DecodedCert dc;
	int rc = decode(der, len, &dc);

	if (rc) {
		return rc;
	}

	memset(out, 0, sizeof(*out));

	if (dc.serialSz > 0 && (size_t)dc.serialSz <= CERTPARSE_SERIAL_MAX) {
		memcpy(out->serial, dc.serial, (size_t)dc.serialSz);
		out->serial_len = (size_t)dc.serialSz;
	}

	fill_dn(&dc, &out->subject, &out->dn_overflow);
	fill_subject_der(&dc, der, out);

	/* wolfCrypt precomputes this; it is the same byte-for-byte DN
	 * comparison the mbedTLS backend does on issuer_raw vs subject_raw. */
	out->self_signed = (dc.selfSigned != 0);
	out->is_ca = (dc.isCA != 0);

	/* wolfSSL calls the KeyUsage extension `extKeyUsage` (ext = extension);
	 * `extExtKeyUsage` is Extended Key Usage, which Cantil does not issue.
	 * The bit values match RFC 5280 and mbedTLS, so this transfers directly. */
	out->key_usage = dc.extKeyUsageSet ? (uint16_t)dc.extKeyUsage : 0;

	parse_after_date(&dc, out);

	out->has_pubkey = extract_pubkey(&dc, out->pubkey);
	out->has_x25519 = extract_x25519(&dc, out->x25519);

	wc_FreeDecodedCert(&dc);
	return 0;
}

int certparse_csr(const uint8_t *der, size_t len, certgen_dn_t *subject, uint8_t pubkey[65])
{
	if (!der || !subject || !pubkey || len == 0) {
		return -EINVAL;
	}

	DecodedCert dc;

	wc_InitDecodedCert(&dc, der, (word32)len, NULL);
	if (wc_ParseCert(&dc, CERTREQ_TYPE, NO_VERIFY, NULL) != 0) {
		wc_FreeDecodedCert(&dc);
		return -EINVAL;
	}

	bool overflow = false;

	fill_dn(&dc, subject, &overflow);

	int rc = 0;

	if (subject->cn[0] == '\0' || !extract_pubkey(&dc, pubkey)) {
		rc = -EINVAL;
	}

	wc_FreeDecodedCert(&dc);
	return rc;
}

/* ── chain verification ─────────────────────────────────────────────────── */

/*
 * One link: is `child` signed by `parent`?
 *
 * Both the name check and the signature check are required. Name chaining
 * alone proves nothing (anyone can put any issuer name in a certificate), and
 * the signature check alone would let an unrelated certificate that happens to
 * verify stand in for the named issuer.
 */
static bool signed_by(const uint8_t *child_der, size_t child_len, const DecodedCert *child,
		      const DecodedCert *parent)
{
	if (child->issuerRawLen != parent->subjectRawLen || child->issuerRawLen <= 0 ||
	    memcmp(child->issuerRaw, parent->subjectRaw, (size_t)child->issuerRawLen) != 0) {
		return false;
	}

	/* A parent must be a CA. mbedTLS enforces this inside
	 * x509_crt_check_parent; here it is explicit. */
	if (!parent->isCA) {
		return false;
	}

	return wc_CheckCertSigPubKey(child_der, (word32)child_len, NULL, parent->publicKey,
				     parent->pubKeySize, parent->keyOID) == 0;
}

int certparse_verify_chain(const uint8_t *leaf_der, size_t leaf_len,
			   const uint8_t *const inter_ders[], const size_t inter_lens[],
			   size_t inter_count, const uint8_t *anchor_der, size_t anchor_len)
{
	if (!leaf_der || leaf_len == 0 || !anchor_der || anchor_len == 0) {
		return -EINVAL;
	}
	if (inter_count > CERTPARSE_MAX_INTER) {
		LOG_WRN("certparse: %zu intermediates exceeds max %d", inter_count,
			CERTPARSE_MAX_INTER);
		return -EINVAL;
	}

	DecodedCert leaf, anchor;
	DecodedCert inter[CERTPARSE_MAX_INTER];
	bool inter_ok[CERTPARSE_MAX_INTER] = {false};      /* parsed */
	bool inter_trusted[CERTPARSE_MAX_INTER] = {false}; /* and verified */
	int rc = -EINVAL;

	if (decode(leaf_der, leaf_len, &leaf)) {
		return -EINVAL;
	}
	if (decode(anchor_der, anchor_len, &anchor)) {
		wc_FreeDecodedCert(&leaf);
		return -EINVAL;
	}

	/* An unparseable intermediate is skipped, not fatal — the peer may ship
	 * a chain element this build cannot read, and the chain can still verify
	 * without it. Matches the mbedTLS backend. */
	for (size_t i = 0; i < inter_count; i++) {
		if (!inter_ders[i] || inter_lens[i] == 0) {
			continue;
		}
		inter_ok[i] = (decode(inter_ders[i], inter_lens[i], &inter[i]) == 0);
	}

	/*
	 * Incremental path building. Each round promotes every intermediate that
	 * now verifies against something already trusted, then retries the leaf.
	 * At most inter_count promotions are possible, and the loop stops as soon
	 * as a round promotes nothing — so it terminates even on a cycle.
	 */
	for (size_t round = 0; round <= inter_count; round++) {
		if (signed_by(leaf_der, leaf_len, &leaf, &anchor)) {
			rc = 0;
			break;
		}

		bool leaf_done = false;

		for (size_t i = 0; i < inter_count && !leaf_done; i++) {
			if (inter_ok[i] && inter_trusted[i] &&
			    signed_by(leaf_der, leaf_len, &leaf, &inter[i])) {
				rc = 0;
				leaf_done = true;
			}
		}
		if (leaf_done) {
			break;
		}

		bool progress = false;

		for (size_t i = 0; i < inter_count; i++) {
			if (!inter_ok[i] || inter_trusted[i]) {
				continue;
			}

			/* Trusted only via the anchor, or via an intermediate
			 * that is itself already trusted. Never on its own
			 * say-so — that is the trust-anchor trap. */
			bool ok = signed_by(inter_ders[i], inter_lens[i], &inter[i], &anchor);

			for (size_t j = 0; j < inter_count && !ok; j++) {
				if (j != i && inter_ok[j] && inter_trusted[j]) {
					ok = signed_by(inter_ders[i], inter_lens[i], &inter[i],
						       &inter[j]);
				}
			}

			if (ok) {
				inter_trusted[i] = true;
				progress = true;
			}
		}

		if (!progress) {
			break;
		}
	}

	for (size_t i = 0; i < inter_count; i++) {
		if (inter_ok[i]) {
			wc_FreeDecodedCert(&inter[i]);
		}
	}
	wc_FreeDecodedCert(&anchor);
	wc_FreeDecodedCert(&leaf);
	return rc;
}
