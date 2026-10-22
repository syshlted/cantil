/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

#ifndef CANTIL_CA_OIDS_H
#define CANTIL_CA_OIDS_H

/*
 * Cantil's own object identifiers.
 *
 * Extracted from ca.c by step 6a of docs/roadmap/wolfssl-migration.md: the
 * X25519 binding OID is now needed on both sides of the library seam — ca.c
 * passes it to certgen to *write* the extension, and certparse_{mbedtls,
 * wolfssl}.c scan for it to *read* one back. Two copies of an OID that must
 * agree byte for byte is exactly the kind of thing that drifts, so there is
 * one.
 */

#include <stdint.h>

/*
 * 1.3.6.1.4.1.58270.1.1 — Cantil enterprise arc (placeholder PEN 58270),
 * .1.1 = session Noise X25519-key binding.  Non-critical; extnValue is an
 * OCTET STRING wrapping the raw 32-byte little-endian X25519 public key (both
 * certgen backends wrap the value in the OCTET STRING).
 * Replace the arc with a real IANA-assigned PEN before distribution.
 */
static const uint8_t OID_SESSION_X25519[] = {0x2b, 0x06, 0x01, 0x04, 0x01,
					     0x83, 0xc7, 0x1e, 0x01, 0x01};

#define OID_SESSION_X25519_LEN sizeof(OID_SESSION_X25519)

#endif /* CANTIL_CA_OIDS_H */
