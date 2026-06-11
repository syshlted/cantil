/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Bond kind: host-client (USB/BLE from a workstation) vs peer device (another Cantil). */
typedef enum {
	CLIENT_KIND_HOST        = 0,
	CLIENT_KIND_PEER_DEVICE = 1,
} client_kind_t;

/* Wire layout of /clients/<hex8>/meta.bin — 44 bytes, version 1. */
#define CLIENT_META_VERSION  1
#define CLIENT_META_NAME_MAX 32   /* including null terminator */

typedef struct __attribute__((packed)) {
	uint8_t  version;                    /* always CLIENT_META_VERSION */
	uint8_t  kind;                       /* client_kind_t */
	uint8_t  _pad[2];
	uint32_t created_at_be;              /* BE u32 unix timestamp, 0 if unknown */
	uint32_t last_seen_be;               /* BE u32 unix timestamp, 0 if unknown */
	char     friendly_name[CLIENT_META_NAME_MAX]; /* null-terminated, zero-padded */
} client_meta_t;

/* Derive the 4-byte storage ID from a 32-byte Curve25519 pubkey. */
static inline void client_bond_id(const uint8_t pub[32], uint8_t id[4])
{
	id[0] = pub[0]; id[1] = pub[1]; id[2] = pub[2]; id[3] = pub[3];
}

/*
 * Add a new bond for the given 32-byte Curve25519 static pubkey.
 * Returns 0 on success, -ENOSPC if the cap for that kind is already reached,
 * -EEXIST if the pubkey is already bonded (caller can treat as OK), negative
 * errno on storage error.
 */
int client_bond_add(const uint8_t pub[32], client_kind_t kind, uint32_t now_unix);

/*
 * Remove the bond for the given pubkey.  Returns 0 on success (or if no bond
 * existed), negative errno on storage error.
 */
int client_bond_remove(const uint8_t pub[32]);

/* Returns 1 if a bond exists for this pubkey, 0 if not, negative errno on error. */
int client_bond_exists(const uint8_t pub[32]);

/* Read the metadata for a bond. Returns -ENOENT if no bond exists. */
int client_bond_meta_read(const uint8_t pub[32], client_meta_t *meta);

/* Update the friendly name for an existing bond.  name must be ≤ 31 bytes. */
int client_bond_set_name(const uint8_t pub[32], const char *name);

/* Count bonded hosts and peer devices independently. */
int client_bond_count(uint32_t *host_count, uint32_t *peer_count);

/*
 * Encode the full bond list as CBOR into out[0..*len-1].  On return *len is
 * the number of bytes written.  Format:
 *   [ { "k": uint, "n": uint32, "p": bstr(32), "t": tstr } ... ]
 * where k=kind, n=created_at, p=pubkey, t=friendly_name.
 */
int client_bond_list_cbor(uint8_t *out, size_t *len);
