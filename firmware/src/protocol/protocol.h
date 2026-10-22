/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

#pragma once

#include <stdint.h>
#include "session/session.h"

/* Command codes — must match client library CBOR wire protocol */
typedef enum {
	CMD_SIGN_CSR = 0x01,
	CMD_GET_CA_CERT = 0x02,
	CMD_GET_CA_CHAIN = 0x03,
	CMD_GET_CA_SERIAL = 0x04,
	CMD_GET_CA_CSR = 0x05,
	CMD_PUSH_CA_CERT = 0x06,

	CMD_LIST_CERTS = 0x10,
	CMD_GET_CERT = 0x11,
	CMD_GET_CERT_COUNT = 0x12,
	CMD_REVOKE_CERT = 0x13,
	CMD_AUTO_EXPIRE = 0x14,
	CMD_GET_CRL = 0x15,

	CMD_LIST_KEYS = 0x20,
	CMD_GEN_KEY = 0x21,
	CMD_GEN_KEY_CSR = 0x22,
	CMD_GET_KEY_CSR = 0x23,
	CMD_PUSH_KEY_CERT = 0x24,
	CMD_SIGN_KEY_SLOT = 0x25,
	CMD_PUSH_KEY_X509 = 0x26,
	CMD_DELETE_KEY = 0x27,
	CMD_PROTECT_SLOT = 0x28,
	CMD_UNPROTECT_SLOT = 0x29,
	CMD_SIGN_CSR_SLOT = 0x2A,

	CMD_DEVICE_STATUS = 0x30,
	CMD_SET_UNLOCK_SEQ = 0x31,
	CMD_RESET_DEVICE = 0x32,
	/* 0x33 is CMD_UPDATE_FIRMWARE, declared below with its policy note. */

	/*
	 * Generate the root CA keypair into slot 0. Optional 1-byte key type
	 * (0 or KEY_TYPE_P256); returns BE u32 slot id (always 0).
	 *
	 * Booting no longer mints a CA — an empty slot 0 is indistinguishable
	 * from a provisioned device whose partition was misdeclared, and acting
	 * on that ambiguity is what orphaned unit #1's CA on 2026-07-22. So
	 * this is the only route: unlocked device, authenticated session,
	 * tap-confirmed, and refused outright if slot 0 already holds a key.
	 */
	CMD_PROVISION_CA = 0x34,

	CMD_GET_RANDOM = 0x40,

	CMD_GET_RANDOM_NAMES = 0x50,

	/* Session-slot (transport identity) opcodes — 0x60–0x6F reserved.
	 * T-05: read the session cert / generate a session CSR.
	 * T-06: CA-sign the session cert from an on-device CA slot. */
	CMD_GET_SESSION_CERT = 0x60,
	CMD_GET_SESSION_CSR = 0x61,
	CMD_SIGN_SESSION_FROM_SLOT = 0x62,
	/* T-07: install an externally-signed session cert + issuer chain. */
	CMD_PUSH_SESSION_CERT = 0x63,

	/* Client bond management opcodes — 0x70–0x7F reserved (T-15). */
	CMD_LIST_CLIENTS = 0x70,    /* → CBOR array of bond metadata */
	CMD_UNPAIR_CLIENT = 0x71,   /* 32 B pubkey → none; tap-confirm */
	CMD_SET_CLIENT_NAME = 0x72, /* 32 B pubkey + UTF-8 name → none */

	/* Pairing passkey exchange (T-18, Method 3).
	 * Client sends u32 digits after device blinks the passkey. */
	CMD_PAIRING_PASSKEY_REPLY = 0x73,

	/* Firmware update (0x33) — reboots into the UF2 bootloader. Allowed
	 * from LOCKED state and identity-recovery mode (same policy as
	 * RESET_DEVICE) so a deployed device can always be updated.
	 *
	 * The image-streaming sub-operations (BEGIN/CHUNK/COMMIT) went with the
	 * mcuboot tier on 2026-07-26; the opcode and the ERR_FW_UPDATE_* codes
	 * below are kept reserved, because wolfBoot needs the same wire format.
	 * See docs/roadmap/wolfboot-migration.md. */
	CMD_UPDATE_FIRMWARE = 0x33,
} cantil_cmd_t;

/* Error codes returned in CBOR response "err" field */
typedef enum {
	ERR_OK = 0,
	ERR_DEVICE_LOCKED = 1,
	ERR_INVALID_CMD = 2,
	ERR_INVALID_ARGS = 3,
	ERR_STORAGE = 4,
	ERR_CRYPTO = 5,
	ERR_NOT_FOUND = 6,
	ERR_NO_SLOTS = 7,
	ERR_BUSY = 8,
	ERR_IDENTITY_MISMATCH = 9, /* device is in T-03 identity-recovery mode */
	ERR_AUTH = 10,             /* passkey wrong / PSK challenge failed */
	ERR_PASSKEY_REQUIRED = 11, /* Method 3 device expects PAIRING_PASSKEY_REPLY first */
	/* 12-14 are reserved for image streaming: no tier emits them since the
	 * mcuboot tier was dropped, and the numbers must not be reused — a
	 * deployed client still maps them (libcantil/src/device.c). */
	ERR_FW_UPDATE_BUSY = 12,      /* another firmware update is already in progress */
	ERR_FW_UPDATE_FLASH = 13,     /* flash erase or write error */
	ERR_FW_UPDATE_ARGS = 14,      /* bad offset, size, or sub-op sequence */
	ERR_NOT_PROVISIONED = 15,     /* slot 0 has no CA key — send PROVISION_CA */
	ERR_ALREADY_PROVISIONED = 16, /* slot 0 already has a key; never overwritten */
	/*
	 * The mounted volume is not verifiably this device's. Either the
	 * identity marker contradicts this build (never benign), or there is no
	 * marker and no CA key — which is what a misdeclared partition looks
	 * like and is indistinguishable from a fresh device. Anything that would
	 * create or destroy a secret is refused; DEVICE_STATUS reports which
	 * state it is in (byte 27) and UPDATE_FIRMWARE stays open so a corrected
	 * image can be pushed without erasing anything first.
	 */
	ERR_VOLUME_INVALID = 17,
} cantil_err_t;

/*
 * Read one CBOR request from the session, dispatch to the appropriate
 * handler, and send the CBOR response.  Returns 0 on success, negative
 * errno if the session should be closed.
 */
int protocol_handle_one(cantil_session_t *session);
