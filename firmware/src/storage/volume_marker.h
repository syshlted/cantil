/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

#pragma once

#include <stdint.h>
#include <stddef.h>

/*
 * ── Volume identity marker ────────────────────────────────────────────────
 *
 * A small record written once, when the volume is created, and verified on
 * every boot. It answers a question the filesystem cannot: "is this the
 * volume this firmware is supposed to be using?"
 *
 * That question is not academic. On 2026-07-22 a misdeclared partition was
 * observed to *mount successfully* over live data on real hardware, present
 * as empty, and induce ca_init() to mint a replacement root CA — no format
 * involved. littlefs relocates metadata pairs for wear levelling and its
 * superblock is itself a metadata pair, so a relocated root pair sitting high
 * in the volume can look like a valid superblock to a mount that starts
 * there. That needs no stale data and no prior mistake; ordinary wear
 * levelling on a healthy device is enough.
 *
 * The offset and size fields are what close it: a filesystem at the wrong
 * offset mounts fine and looks merely empty, but a marker that disagrees with
 * this build's partition definition is unambiguous.
 *
 * Deliberately plaintext with a CRC, not authenticated. It is a safety
 * interlock against misconfiguration, not a security boundary — an attacker
 * who can write flash has already won, and the secrets are individually
 * AEAD-encrypted under a key derived from the FICR ID that this marker only
 * records. The CRC is there to catch a torn write, not forgery.
 *
 * This module deliberately depends on nothing but the filesystem, CRC and
 * device-ID helpers, so the step-1 factory image can write a marker without
 * linking a crypto stack. See docs/roadmap/two-step-provisioning.md.
 */

#define CANTIL_VOLUME_MAGIC   0x4C544E43UL /* "CNTL" little-endian */
#define CANTIL_VOLUME_VERSION 1

/* Packed, 28 bytes — comfortably inside CANTIL_KEY_BLOB_LEN, so the marker is
 * itself an inline file and inherits the metadata pair's 2x redundancy. */
struct storage_volume_marker {
	uint32_t magic;
	uint16_t version;
	uint16_t reserved;         /* zero; keeps device_id 8-byte aligned */
	uint32_t partition_offset; /* FIXED_PARTITION_OFFSET at creation */
	uint32_t partition_size;   /* FIXED_PARTITION_SIZE at creation */
	uint8_t device_id[8];      /* FICR DEVICEID of the creating die */
	uint32_t crc32;            /* crc32_ieee over the preceding 24 bytes */
} __attribute__((packed));

enum storage_volume_state {
	/* Marker present, and every field agrees with this build and die. */
	STORAGE_VOLUME_VALID = 0,
	/*
	 * No marker. Ambiguous by construction — either a volume created
	 * before markers existed, or a partition pointed somewhere wrong.
	 * Nothing on the volume can tell these apart, which is exactly why
	 * adopting a marker is a deliberate, opt-in act.
	 */
	STORAGE_VOLUME_UNMARKED,
	/*
	 * Marker present and disagrees: wrong offset/size, a different die, a
	 * future layout version, or a failed CRC. Unlike UNMARKED this is
	 * never ambiguous and never benign.
	 */
	STORAGE_VOLUME_MISMATCH,
};

/* State determined during storage_init(). Valid only after it returns 0. */
enum storage_volume_state storage_volume_state(void);

/*
 * Re-read the marker and update the cached state. storage_init() calls this
 * once; it is exposed so a device can re-check on demand, and so tests can
 * drive the verification path without remounting.
 */
enum storage_volume_state storage_volume_verify(void);

/* Human-readable form of the above, for logs and DEVICE_STATUS. */
const char *storage_volume_state_str(enum storage_volume_state st);

/*
 * Create the marker for the currently mounted volume. Intended for the step-1
 * factory image, and for the deliberate adoption of a pre-marker volume.
 * Refuses to overwrite an existing marker — replacing one would defeat its
 * entire purpose.
 */
int storage_volume_marker_write(void);
