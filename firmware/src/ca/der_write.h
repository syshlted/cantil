/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

#pragma once

#include <stdint.h>
#include <stddef.h>

/*
 * A minimal backwards DER writer.
 *
 * The CRL encoder in ca.c is hand-rolled because no crypto library ships a CRL
 * writer — mbedTLS does not, and neither does wolfCrypt. So the encoder never
 * needed a *library*; it needed generic DER byte primitives, which it borrowed
 * from mbedtls_asn1_write_*. This is Cantil's own copy of those five, so the
 * CRL encoder depends on no crypto library for its structure and survives the
 * mbedTLS → wolfCrypt migration unchanged (wolfCrypt's ASN.1 writers encode
 * forwards, with a different calling convention, and are the wrong shape for an
 * encoder built to write right-to-left).
 *
 * Convention, matched to mbedtls_asn1_write_* so the port was mechanical:
 * every writer moves *p LEFT (toward start), writing the element so it ends at
 * the old *p, and returns the number of bytes written or a negative
 * CANTIL_DER_ERR_*. `start` is the low bound; a write that would cross it fails
 * rather than underflowing the buffer. Assemble an element by writing its
 * content first, then its length, then its tag.
 */

/* DER identifier octets (X.690), the subset the CRL encoder uses. */
#define CANTIL_ASN1_INTEGER          0x02
#define CANTIL_ASN1_BIT_STRING       0x03
#define CANTIL_ASN1_OCTET_STRING     0x04
#define CANTIL_ASN1_OID              0x06
#define CANTIL_ASN1_SEQUENCE         0x10
#define CANTIL_ASN1_UTC_TIME         0x17
#define CANTIL_ASN1_GENERALIZED_TIME 0x18
#define CANTIL_ASN1_CONSTRUCTED      0x20
#define CANTIL_ASN1_CONTEXT_SPECIFIC 0x80

/* Negative so they never collide with a byte count. Values mirror the mbedtls
 * ASN.1 codes they replaced, purely so a log that printed the old number still
 * reads the same. */
#define CANTIL_DER_ERR_BUF_TOO_SMALL (-0x006C)
#define CANTIL_DER_ERR_INVALID_DATA  (-0x0068)

/*
 * The one *reader* in this file, added by step 6a.
 *
 * Measure the complete TLV that starts at `p`: on success *out_len is the whole
 * element, header included, so `p + *out_len` is the next element. Used to walk
 * a concatenated DER blob of certificates, which is how both ca.c and
 * session.c split a stored chain — the only thing either needed
 * mbedtls_asn1_get_tag for.
 *
 * `tag` is the identifier octet the element must carry (callers pass
 * CANTIL_ASN1_CONSTRUCTED | CANTIL_ASN1_SEQUENCE). Returns 0, or
 * CANTIL_DER_ERR_INVALID_DATA if the tag does not match, the length is
 * malformed, or the element would run past `avail`.
 *
 * It lives in a header named der_write because splitting the file to hold one
 * function would churn the seven test CMakeLists that build it, for no gain.
 */
int cantil_der_tlv_len(const uint8_t *p, size_t avail, uint8_t tag, size_t *out_len);

/* Copy `len` raw bytes so they end at the current *p. */
int cantil_der_raw(uint8_t **p, const uint8_t *start, const uint8_t *buf, size_t len);

/* DER definite length, short or long form. */
int cantil_der_len(uint8_t **p, const uint8_t *start, size_t len);

/* A single identifier octet. */
int cantil_der_tag(uint8_t **p, const uint8_t *start, uint8_t tag);

/* A full INTEGER TLV for a non-negative value, minimal encoding, 0x00-padded
 * when the top bit would otherwise make it negative. */
int cantil_der_int(uint8_t **p, const uint8_t *start, uint32_t val);

/* A full INTEGER TLV from a big-endian magnitude buffer: strips leading zero
 * octets, then 0x00-pads when the top bit would otherwise make it negative.
 * Used for the r and s of an Ecdsa-Sig-Value, which are up to 32 bytes each. */
int cantil_der_mpint(uint8_t **p, const uint8_t *start, const uint8_t *val, size_t len);

/* A full OBJECT IDENTIFIER TLV from pre-encoded OID content bytes. */
int cantil_der_oid(uint8_t **p, const uint8_t *start, const uint8_t *oid, size_t oid_len);

/*
 * Accumulate a writer's result into `g` or bail out. Relies on an in-scope
 * `int ret`, exactly like the mbedtls MBEDTLS_ASN1_CHK_ADD it replaced, so the
 * encoder's `int ret, len = 0;` locals stayed as they were.
 */
#define CANTIL_DER_CHK_ADD(g, f)                                                                   \
	do {                                                                                       \
		if ((ret = (f)) < 0) {                                                             \
			return ret;                                                                \
		}                                                                                  \
		(g) += ret;                                                                        \
	} while (0)
