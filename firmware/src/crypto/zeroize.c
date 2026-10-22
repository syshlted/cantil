/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

#include "crypto/zeroize.h"

/*
 * The volatile pointer is what does the work: writing through a
 * volatile-qualified lvalue is an observable side effect the standard forbids
 * the compiler from eliding, so the store survives dead-store elimination even
 * when the buffer is never read again. This is the same technique
 * mbedtls_platform_zeroize() and OpenSSL's OPENSSL_cleanse() use; it needs no
 * library, no memset_s(), and no compiler barrier intrinsic.
 */
void cantil_zeroize(void *buf, size_t len)
{
	if (buf == NULL || len == 0) {
		return;
	}

	volatile unsigned char *p = (volatile unsigned char *)buf;

	while (len--) {
		*p++ = 0;
	}
}
