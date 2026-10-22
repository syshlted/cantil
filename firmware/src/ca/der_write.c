/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

#include <string.h>

#include "ca/der_write.h"

int cantil_der_raw(uint8_t **p, const uint8_t *start, const uint8_t *buf, size_t len)
{
	if (len > (size_t)(*p - start)) {
		return CANTIL_DER_ERR_BUF_TOO_SMALL;
	}
	*p -= len;
	memcpy(*p, buf, len);
	return (int)len;
}

int cantil_der_len(uint8_t **p, const uint8_t *start, size_t len)
{
	/* Short form: one octet for lengths under 0x80. */
	if (len < 0x80) {
		if (*p <= start) {
			return CANTIL_DER_ERR_BUF_TOO_SMALL;
		}
		*--(*p) = (uint8_t)len;
		return 1;
	}

	/* Long form: a leading 0x8N octet giving the count of length octets,
	 * then that many big-endian bytes. The bounds are the same the mbedtls
	 * writer used; a CRL never approaches even the 3-byte case, but 4 length
	 * bytes are covered so a future caller cannot silently truncate. */
	if (len <= 0xFF) {
		if ((size_t)(*p - start) < 2) {
			return CANTIL_DER_ERR_BUF_TOO_SMALL;
		}
		*--(*p) = (uint8_t)len;
		*--(*p) = 0x81;
		return 2;
	}
	if (len <= 0xFFFF) {
		if ((size_t)(*p - start) < 3) {
			return CANTIL_DER_ERR_BUF_TOO_SMALL;
		}
		*--(*p) = (uint8_t)(len & 0xFF);
		*--(*p) = (uint8_t)((len >> 8) & 0xFF);
		*--(*p) = 0x82;
		return 3;
	}
	if (len <= 0xFFFFFF) {
		if ((size_t)(*p - start) < 4) {
			return CANTIL_DER_ERR_BUF_TOO_SMALL;
		}
		*--(*p) = (uint8_t)(len & 0xFF);
		*--(*p) = (uint8_t)((len >> 8) & 0xFF);
		*--(*p) = (uint8_t)((len >> 16) & 0xFF);
		*--(*p) = 0x83;
		return 4;
	}
	if ((size_t)(*p - start) < 5) {
		return CANTIL_DER_ERR_BUF_TOO_SMALL;
	}
	*--(*p) = (uint8_t)(len & 0xFF);
	*--(*p) = (uint8_t)((len >> 8) & 0xFF);
	*--(*p) = (uint8_t)((len >> 16) & 0xFF);
	*--(*p) = (uint8_t)((len >> 24) & 0xFF);
	*--(*p) = 0x84;
	return 5;
}

int cantil_der_tag(uint8_t **p, const uint8_t *start, uint8_t tag)
{
	if (*p <= start) {
		return CANTIL_DER_ERR_BUF_TOO_SMALL;
	}
	*--(*p) = tag;
	return 1;
}

int cantil_der_int(uint8_t **p, const uint8_t *start, uint32_t val)
{
	int len = 0;

	/* Content, least-significant byte first (do/while so 0 emits one
	 * 0x00 octet, matching DER's canonical zero). */
	do {
		if (*p <= start) {
			return CANTIL_DER_ERR_BUF_TOO_SMALL;
		}
		*--(*p) = (uint8_t)(val & 0xFF);
		len++;
		val >>= 8;
	} while (val > 0);

	/* Prepend 0x00 if the top bit is set, so the INTEGER stays positive. */
	if (**p & 0x80) {
		if (*p <= start) {
			return CANTIL_DER_ERR_BUF_TOO_SMALL;
		}
		*--(*p) = 0x00;
		len++;
	}

	int ret;

	CANTIL_DER_CHK_ADD(len, cantil_der_len(p, start, (size_t)len));
	CANTIL_DER_CHK_ADD(len, cantil_der_tag(p, start, CANTIL_ASN1_INTEGER));
	return len;
}

int cantil_der_mpint(uint8_t **p, const uint8_t *start, const uint8_t *val, size_t len)
{
	/* Strip leading zero octets, but keep at least one so a zero value
	 * still encodes as the single 0x00 octet DER requires. */
	while (len > 1 && val[0] == 0x00) {
		val++;
		len--;
	}
	if (len == 0) {
		len = 1; /* treat empty as a zero magnitude */
	}

	int ret, ilen = 0;

	CANTIL_DER_CHK_ADD(ilen, cantil_der_raw(p, start, val, len));

	/* Prepend 0x00 if the top bit is set, so the INTEGER stays positive. */
	if (val[0] & 0x80) {
		CANTIL_DER_CHK_ADD(ilen, cantil_der_tag(p, start, 0x00));
	}

	CANTIL_DER_CHK_ADD(ilen, cantil_der_len(p, start, (size_t)ilen));
	CANTIL_DER_CHK_ADD(ilen, cantil_der_tag(p, start, CANTIL_ASN1_INTEGER));
	return ilen;
}

int cantil_der_oid(uint8_t **p, const uint8_t *start, const uint8_t *oid, size_t oid_len)
{
	int ret, len = 0;

	CANTIL_DER_CHK_ADD(len, cantil_der_raw(p, start, oid, oid_len));
	CANTIL_DER_CHK_ADD(len, cantil_der_len(p, start, oid_len));
	CANTIL_DER_CHK_ADD(len, cantil_der_tag(p, start, CANTIL_ASN1_OID));
	return len;
}

/* ── reader ─────────────────────────────────────────────────────────────── */

int cantil_der_tlv_len(const uint8_t *p, size_t avail, uint8_t tag, size_t *out_len)
{
	if (!p || !out_len || avail < 2 || p[0] != tag) {
		return CANTIL_DER_ERR_INVALID_DATA;
	}

	size_t hdr = 2;
	size_t len = p[1];

	if (len & 0x80) {
		size_t n = len & 0x7F;

		/* Indefinite length (0x80) is not DER, and a length field wider
		 * than size_t cannot be represented. Both are malformed here. */
		if (n == 0 || n > sizeof(size_t) || avail < 2 + n) {
			return CANTIL_DER_ERR_INVALID_DATA;
		}
		len = 0;
		for (size_t i = 0; i < n; i++) {
			len = (len << 8) | p[2 + i];
		}
		hdr = 2 + n;
	}

	/* Guard the addition itself before comparing, so a hostile length that
	 * wraps size_t cannot appear to fit. */
	if (len > avail - hdr) {
		return CANTIL_DER_ERR_INVALID_DATA;
	}

	*out_len = hdr + len;
	return 0;
}
