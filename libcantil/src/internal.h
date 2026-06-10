#pragma once

#include "../include/cantil.h"
#include <stdint.h>
#include <stddef.h>

/* ── Transport vtable ────────────────────────────────────────────────────── */

struct cantil_transport {
    /*
     * Send exactly len bytes. Returns 0 on success, -errno on error.
     */
    int  (*send)(struct cantil_transport *t, const uint8_t *buf, size_t len);

    /*
     * Read up to max_len bytes into buf. Blocks until at least 1 byte is
     * available or timeout_ms elapses. Returns 0 on success with *received
     * set to the byte count, -ETIMEDOUT if no data arrived, -errno on error.
     */
    int  (*recv)(struct cantil_transport *t, uint8_t *buf, size_t max_len,
                 size_t *received, int timeout_ms);

    void (*close)(struct cantil_transport *t);
};

/* ── Session ─────────────────────────────────────────────────────────────── */

/*
 * Device identity cert chain delivered inside encrypted Noise msg2 (T-04).
 * Leaf-first; stored as concatenated DER with per-cert lengths so a Phase-C
 * trust policy can fingerprint the leaf or walk the chain. A self-signed device
 * sends a single cert; a fully empty payload leaves count == 0.
 */
#define CANTIL_DEVICE_CHAIN_MAX    4096   /* total concatenated DER bytes */
#define CANTIL_DEVICE_CHAIN_CERTS  8      /* max certs in a chain */

struct cantil_session {
    cantil_transport_t *transport;
    uint8_t  tx_key[32];       /* client→device encrypt key (k1 from Split) */
    uint8_t  rx_key[32];       /* device→client decrypt key (k2 from Split) */
    uint64_t tx_nonce;
    uint64_t rx_nonce;
    uint8_t  device_s_pub[32]; /* device static public key, learned in handshake */
    uint8_t  client_s_pub[32]; /* our static public key */
    int      established;

    /* Device identity chain from msg2 (leaf-first). */
    uint8_t  device_chain[CANTIL_DEVICE_CHAIN_MAX];
    size_t   device_chain_total;                       /* bytes used */
    size_t   device_cert_off[CANTIL_DEVICE_CHAIN_CERTS]; /* offset of each cert */
    size_t   device_cert_len[CANTIL_DEVICE_CHAIN_CERTS]; /* length of each cert */
    size_t   device_cert_count;
};

/*
 * Borrow the Nth device identity cert (0 = leaf) delivered on the handshake.
 * Returns 0 with der/len pointing into the session, or -EINVAL / -ENOENT.
 * The full trust-policy API lands in Phase C (T-10+); this is the raw accessor.
 */
int cantil_session_device_cert(const cantil_session_t *s, size_t idx,
                               const uint8_t **der, size_t *len);
size_t cantil_session_device_cert_count(const cantil_session_t *s);

/* ── Internal session I/O (post-handshake encrypted frames) ──────────────── */

int cantil_session_send(cantil_session_t *s, const uint8_t *buf, size_t len);
int cantil_session_recv(cantil_session_t *s, uint8_t *buf, size_t max_len,
                       size_t *received);
/* Like cantil_session_recv but with an explicit response deadline. Used by
 * tap-confirm opcodes, whose response only arrives after the user taps. */
int cantil_session_recv_to(cantil_session_t *s, uint8_t *buf, size_t max_len,
                          size_t *received, int timeout_ms);

/* Response wait for tap-confirm opcodes (PROTECT/UNPROTECT_SLOT,
 * SIGN_SESSION_FROM_SLOT): the device blocks on a physical confirm gesture
 * before replying, so the client must wait longer than the device's
 * CONFIG_CANTIL_CONFIRM_TIMEOUT_SEC window (default 10 s; test builds raise it).
 * 35 s covers a 30 s device window plus margin. */
#define CANTIL_TAP_CONFIRM_TIMEOUT_MS 35000

/* ── Protocol command codes (mirrors firmware protocol.h) ────────────────── */

#define CMD_SIGN_CSR         0x01
#define CMD_GET_CA_CERT      0x02
#define CMD_GET_CA_CHAIN     0x03
#define CMD_GET_CA_SERIAL    0x04
#define CMD_GET_CA_CSR       0x05
#define CMD_PUSH_CA_CERT     0x06

#define CMD_LIST_CERTS       0x10
#define CMD_GET_CERT         0x11
#define CMD_GET_CERT_COUNT   0x12
#define CMD_REVOKE_CERT      0x13
#define CMD_AUTO_EXPIRE      0x14
#define CMD_GET_CRL          0x15

#define CMD_LIST_KEYS        0x20
#define CMD_GEN_KEY          0x21
#define CMD_GEN_KEY_CSR      0x22
#define CMD_GET_KEY_CSR      0x23
#define CMD_PUSH_KEY_CERT    0x24
#define CMD_SIGN_KEY_SLOT    0x25
#define CMD_PUSH_KEY_X509    0x26
#define CMD_DELETE_KEY       0x27
#define CMD_PROTECT_SLOT     0x28
#define CMD_UNPROTECT_SLOT   0x29
#define CMD_SIGN_CSR_SLOT    0x2A

#define CMD_DEVICE_STATUS    0x30
#define CMD_SET_UNLOCK_SEQ   0x31
#define CMD_RESET_DEVICE     0x32

#define CMD_GET_RANDOM       0x40
#define CMD_GET_RANDOM_NAMES 0x50

#define CMD_GET_SESSION_CERT       0x60
#define CMD_GET_SESSION_CSR        0x61
#define CMD_SIGN_SESSION_FROM_SLOT 0x62
#define CMD_PUSH_SESSION_CERT      0x63

/* Client bond management — 0x70–0x7F (T-15) */
#define CMD_LIST_CLIENTS           0x70
#define CMD_UNPAIR_CLIENT          0x71
#define CMD_SET_CLIENT_NAME        0x72

/* Pairing passkey exchange — T-18 */
#define CMD_PAIRING_PASSKEY_REPLY  0x73

/* Firmware update — triggers UF2 reboot on UF2-capable builds */
#define CMD_UPDATE_FIRMWARE        0x33

/* Shared do_request() helper (in device.c) — encodes CBOR, sends, recvs,
 * decodes, verifies seq, maps proto err. */
cantil_err_t cantil_do_request(cantil_session_t *s,
			       uint32_t cmd, uint32_t seq,
			       const uint8_t *req_data, size_t req_data_len,
			       uint8_t *scratch, size_t scratch_sz,
			       const uint8_t **resp_data, size_t *resp_data_len);

/* do_request variant with an explicit response timeout (ms). timeout_ms <= 0
 * uses the default. For tap-confirm opcodes pass CANTIL_TAP_CONFIRM_TIMEOUT_MS. */
cantil_err_t cantil_do_request_to(cantil_session_t *s,
				  uint32_t cmd, uint32_t seq,
				  const uint8_t *req_data, size_t req_data_len,
				  uint8_t *scratch, size_t scratch_sz,
				  const uint8_t **resp_data, size_t *resp_data_len,
				  int timeout_ms);

/* Protocol error codes (mirrors firmware protocol.h) */
#define PROTO_ERR_OK            0
#define PROTO_ERR_DEVICE_LOCKED 1
#define PROTO_ERR_INVALID_CMD   2
#define PROTO_ERR_INVALID_ARGS  3
#define PROTO_ERR_STORAGE       4
#define PROTO_ERR_CRYPTO        5
#define PROTO_ERR_NOT_FOUND     6
#define PROTO_ERR_NO_SLOTS      7
#define PROTO_ERR_BUSY          8
#define PROTO_ERR_IDENTITY_MISMATCH 9
#define PROTO_ERR_AUTH          10
#define PROTO_ERR_PASSKEY_REQUIRED 11
#define PROTO_ERR_FW_UPDATE_BUSY  12
#define PROTO_ERR_FW_UPDATE_FLASH 13
#define PROTO_ERR_FW_UPDATE_ARGS  14
