/**
 * libcantil — client library for the Cantil hardware CA device
 *
 * Manages a Noise_XX encrypted session over USB CDC/ACM or BLE NUS and
 * exposes all device operations: CA management, certificate signing, a
 * general-purpose key slot store, CRL management, and hardware TRNG access.
 *
 * Both transports share identical session and protocol code. Transport
 * selection happens at open time; all API calls above that layer are
 * transport-agnostic.
 *
 * For hardware TRNG utilities (UUID, hex strings, random integers, etc.)
 * see cantil_random.h — that header is independently importable without
 * the rest of libcantil.
 *
 * Typical usage:
 *
 *   cantil_transport_t *t = cantil_transport_open_usb("/dev/ttyACM0");
 *   cantil_session_t   *s = cantil_session_open(t, &my_priv, &dev_pub, 0);
 *
 *   uint8_t *cert; size_t cert_len;
 *   cantil_sign_csr(s, csr_der, csr_len, &cert, &cert_len);
 *   free(cert);
 *
 *   cantil_session_close(s);
 *   cantil_transport_close(t);
 */

#ifndef CANTIL_H
#define CANTIL_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


/* ─── Error codes ────────────────────────────────────────────────────────── */

typedef enum {
    CANTIL_OK                = 0,
    CANTIL_ERR_IO            = -1,
    CANTIL_ERR_NOISE         = -2,   /* handshake or decryption failure       */
    CANTIL_ERR_PROTOCOL      = -3,   /* unexpected CBOR from device           */
    CANTIL_ERR_DEVICE_LOCKED = -4,   /* device is in LOCKED state             */
    CANTIL_ERR_TIMEOUT       = -5,
    CANTIL_ERR_NO_MEMORY     = -6,
    CANTIL_ERR_INVALID_ARG   = -7,
    CANTIL_ERR_NOT_SUPPORTED = -8,   /* firmware too old for this command     */
    CANTIL_ERR_CERT_INVALID  = -9,   /* device rejected pushed cert           */
    CANTIL_ERR_KEY_FULL      = -10,  /* no free key slots on device           */
    CANTIL_ERR_KEY_NOT_FOUND = -11,
    CANTIL_ERR_CERT_NOT_FOUND= -12,
    CANTIL_ERR_BOND_FULL     = -13,  /* BLE bond store full                   */
    CANTIL_ERR_ALREADY_REVOKED = -14,
    CANTIL_ERR_TRUST           = -15,  /* trust policy check failed             */
    CANTIL_ERR_AUTH            = -16,  /* passkey wrong / PSK challenge failed  */
    CANTIL_ERR_PASSKEY_REQUIRED= -17,  /* Method 3 device expects passkey first */
    CANTIL_ERR_FW_UPDATE_BUSY  = -18,  /* another firmware update already in progress */
    CANTIL_ERR_FW_UPDATE_FLASH = -19,  /* device flash erase/write error */
} cantil_err_t;

const char *cantil_strerror(cantil_err_t err);


/* ─── Noise session keypair ──────────────────────────────────────────────── */

#define CANTIL_KEY_LEN 32  /* Curve25519 key length in bytes */

typedef struct { uint8_t bytes[CANTIL_KEY_LEN]; } cantil_key_t;

cantil_err_t cantil_keygen(cantil_key_t *out_priv, cantil_key_t *out_pub);
cantil_err_t cantil_pubkey_from_privkey(const cantil_key_t *priv,
                                      cantil_key_t       *out_pub);


/* ─── USB device discovery ───────────────────────────────────────────────── */

/* Registered via pid.codes: https://pid.codes/1209/00CA/ */
#define CANTIL_USB_VID 0x1209
#define CANTIL_USB_PID 0x00CA

/*
 * One entry per Cantil device currently attached to the host. The firmware
 * exposes two CDC-ACM interfaces per device:
 *   - protocol_port: ACM #0, carries the Noise/CBOR session (pass to
 *                    cantil_transport_open_usb()).
 *   - console_port:  ACM #1, carries the Zephyr shell and log output. May
 *                    be empty if the host hasn't enumerated it yet.
 * serial is the USB iSerial string (FICR-derived, stable across reboots).
 */
typedef struct {
    char     protocol_port[64];   /* e.g. "/dev/ttyACM0" */
    char     console_port[64];    /* e.g. "/dev/ttyACM1" — may be empty */
    char     serial[64];          /* USB iSerial, may be empty */
    uint16_t vid;
    uint16_t pid;
} cantil_usb_device_t;

/*
 * Enumerate Cantil USB devices (matching VID:PID 0x1209:0x00CA) attached
 * to the host. *out is malloc'd as an array of cantil_usb_device_t — caller
 * frees with a single free().
 *
 * Returns the device count on success (0 = no devices found), or a negative
 * cantil_err_t on failure. On any nonzero return, *out is set to NULL.
 *
 * Currently implemented on Linux only (via /sys/bus/usb). Other platforms
 * return CANTIL_ERR_NOT_SUPPORTED.
 */
int cantil_list_usb_devices(cantil_usb_device_t **out);


/* ─── Client trust policy (Phase C, T-10) ───────────────────────────────── */

/*
 * Four client-side trust tiers for validating the device identity chain
 * delivered inside the encrypted Noise msg2 payload.
 *
 * Tier 1 (NONE): Noise still encrypts and mutually authenticates via X25519
 *   static keys; the cert chain is accepted without inspection. Suitable for
 *   `native_sim` testing or TOFU-first pairing.
 *
 * Tier 2 (PINNED_SELF_SIGNED): SHA-256 fingerprint of the leaf cert DER must
 *   equal `expected_fingerprint`. Optional subject DER comparison added in T-12.
 *   Upgrade path: connect once with Tier 1, record the fingerprint, then use
 *   Tier 2 on all subsequent sessions.
 *
 * Tier 3 (CA_ALLOWLIST): The leaf cert must chain to a CA in `trust_store`
 *   (verified by mbedTLS in libcantil). Any cert issued by a trusted CA is
 *   accepted. Revocation: deferred to v2 (document gap at the call site if
 *   revocation matters before then).
 *
 * Tier 4 (CA_PLUS_CN_PIN): Tier 3 + the leaf's CN must equal `expected_cn`.
 *   Defends against a compromised CA minting a rogue device cert.
 */
typedef enum {
    CANTIL_TRUST_NONE,                  /* Tier 1: encrypt only, no cert check  */
    CANTIL_TRUST_PINNED_SELF_SIGNED,    /* Tier 2: SHA-256 fingerprint pin       */
    CANTIL_TRUST_CA_ALLOWLIST,          /* Tier 3: chain to allowlisted root CA  */
    CANTIL_TRUST_CA_PLUS_CN_PIN,        /* Tier 4: Tier 3 + per-device CN match  */
} cantil_trust_mode_t;

/*
 * Opaque trust store — a set of allowlisted CA certificates for Tier 3/4.
 * Allocate with cantil_trust_store_new(), populate with cantil_trust_add_ca()
 * or cantil_trust_load_dir(), and free with cantil_trust_store_free(). The
 * store is read-only after being placed into a cantil_trust_policy_t.
 */
typedef struct cantil_trust_store cantil_trust_store_t;

/*
 * Trust policy passed to cantil_session_open(). Fill only the fields relevant
 * to the chosen mode; unused fields are ignored.
 */
typedef struct {
    cantil_trust_mode_t mode;

    /* Tier 2: expected SHA-256 fingerprint of the leaf cert DER (32 bytes). */
    const uint8_t *expected_fingerprint;

    /*
     * Tier 2 (optional, T-12): expected DER-encoded subject DN bytes. When
     * non-NULL both fingerprint and subject must match. Leave NULL to skip.
     */
    const uint8_t *expected_subject_der;
    size_t         expected_subject_der_len;

    /* Tier 3 + 4: CA allowlist. Must be non-NULL for these tiers. */
    const cantil_trust_store_t *trust_store;

    /* Tier 4: expected CN from the leaf cert (NUL-terminated). */
    const char *expected_cn;
} cantil_trust_policy_t;

/* Trust store lifecycle. */
cantil_trust_store_t *cantil_trust_store_new(void);

/*
 * Add a DER-encoded CA certificate to the trust store. The DER bytes are
 * copied internally; the caller may free cert_der after this returns.
 * Returns 0 on success, -ENOMEM on allocation failure, -EINVAL if cert_der
 * is NULL or len is 0.
 */
int cantil_trust_add_ca(cantil_trust_store_t *store,
                        const uint8_t *cert_der, size_t len);

/*
 * Load all *.der files from `path` into the trust store. Files that cannot
 * be opened or read are silently skipped. Returns the count of successfully
 * loaded certificates, or a negative errno on a fatal error (e.g. directory
 * not accessible at all).
 */
int cantil_trust_load_dir(cantil_trust_store_t *store, const char *path);

void cantil_trust_store_free(cantil_trust_store_t *store);


/* ─── Transport ──────────────────────────────────────────────────────────── */

typedef struct cantil_transport cantil_transport_t;

/* USB CDC/ACM. port: "/dev/ttyACM0", "COM3", etc. */
cantil_transport_t *cantil_transport_open_usb(const char *port);

/*
 * BLE NUS transport (Linux: BlueZ via D-Bus; macOS: CoreBluetooth).
 * Assumes the bond already exists. Noise_XX runs on top — BlueZ sees only
 * ciphertext regardless of whether BLE LESC is active.
 * addr: "AA:BB:CC:DD:EE:FF"
 */
cantil_transport_t *cantil_transport_open_ble(const char *addr);

void cantil_transport_close(cantil_transport_t *t);


/* ─── Client identity certificate (Method 4, T-19) ──────────────────────── */

/*
 * Optional client certificate chain to send as the Noise msg3 payload.
 * Required when connecting to a device configured with PAIRING_CA_ANCHOR
 * (Method 4) or PAIRING_CA_ANCHOR_PLUS_PASSKEY (Method 5).
 *
 * cert_der / cert_len    : the client's leaf cert DER (required).
 * chain_der / chain_len  : optional issuer chain (concatenated DER, certs
 *                          between the leaf and the device's trust anchor).
 *                          NULL / 0 if the leaf is directly signed by the
 *                          device's anchor CA (the common case).
 *
 * Pass NULL to cantil_session_open() for Methods 0–3 (no client cert sent).
 */
typedef struct {
    const uint8_t *cert_der;
    size_t         cert_len;
    const uint8_t *chain_der;   /* optional intermediate chain (concat DER) */
    size_t         chain_len;
} cantil_client_cert_t;


/* ─── Session ────────────────────────────────────────────────────────────── */

typedef struct cantil_session cantil_session_t;

/*
 * Perform Noise_XX handshake and open an authenticated session.
 *
 * client_priv  This client's static Curve25519 private key.
 * policy       Trust policy applied to the device identity chain delivered
 *              in the encrypted Noise msg2 payload. Pass NULL (or a policy
 *              with mode == CANTIL_TRUST_NONE) to skip cert validation and
 *              accept any device — appropriate for TOFU-first pairing.
 *              For pinned connections use CANTIL_TRUST_PINNED_SELF_SIGNED
 *              with the expected_fingerprint from the pairing session.
 * client_cert  Optional client identity certificate chain to send in the
 *              Noise msg3 payload. Required for Method 4/5 devices. Pass
 *              NULL for Methods 0–3 (sends an empty CBOR map {} instead).
 * timeout_ms   0 → default (5000ms).
 *
 * Returns a session on success or NULL on handshake/trust failure.
 */
cantil_session_t *cantil_session_open(cantil_transport_t           *t,
                                      const cantil_key_t           *client_priv,
                                      const cantil_trust_policy_t  *policy,
                                      const cantil_client_cert_t   *client_cert,
                                      uint32_t                      timeout_ms);

cantil_err_t cantil_session_get_device_pubkey(const cantil_session_t *s,
                                            cantil_key_t           *out_pub);

/**
 * Verify a trust policy against the device identity chain delivered in the
 * Noise_XX handshake.  Use this when you opened the session with a NULL
 * policy (Tier 1) and need to enforce a stricter check post-handshake.
 *
 * Returns CANTIL_OK if the policy passes, CANTIL_ERR_TRUST if rejected.
 */
cantil_err_t cantil_session_verify_policy(const cantil_session_t *s,
                                          const cantil_trust_policy_t *policy);

/*
 * Extract the CN from the session's leaf cert into buf (NUL-terminated).
 * buf must be at least 65 bytes (max Cantil CN is 64 chars + NUL).
 * Use this after a Tier 3 session to record the CN for a future Tier 4 policy.
 * Returns CANTIL_OK, CANTIL_ERR_TRUST (no cert or no CN), or
 * CANTIL_ERR_INVALID_ARG (buf too small).
 */
cantil_err_t cantil_session_get_leaf_cn(const cantil_session_t *s,
                                        char *buf, size_t buflen);

void        cantil_session_close(cantil_session_t *s);


/* ─── Device status ──────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  fw_major, fw_minor, fw_patch;
    uint8_t  locked;            /* 1 = LOCKED state; CA ops blocked          */
    uint32_t certs_issued;      /* lifetime total signed by this CA          */
    uint32_t certs_stored;      /* certs currently in store                  */
    uint32_t key_slots_used;    /* occupied key slots (including slot 0, CA) */
    uint32_t key_slots_total;   /* maximum key slots (build-time constant)   */
    uint32_t flash_free_kb;
    uint8_t  ble_bonds;
    uint8_t  has_external_flash;
} cantil_status_t;

cantil_err_t cantil_get_status(cantil_session_t *s, cantil_status_t *out);
/* Variant with explicit timeout — use from 'pair' where the device may wait for tap. */
cantil_err_t cantil_get_status_wait(cantil_session_t *s, cantil_status_t *out,
                                     int timeout_ms);


/* ─── CA management ──────────────────────────────────────────────────────── */

/* Caller frees *out with free() for all functions that allocate. */

cantil_err_t cantil_get_ca_cert(cantil_session_t *s,
                               uint8_t **out, size_t *out_len);

/*
 * Retrieve the full chain for the master CA (slot 0): a concatenation of
 * DER certs, leaf first, walking up via stored chain.der (externally-signed
 * sub-CA path) or on-device issuer_slot metadata. A self-signed slot 0
 * returns a single cert.
 */
cantil_err_t cantil_get_ca_chain(cantil_session_t *s,
                                uint8_t **out, size_t *out_len);

/*
 * Retrieve the chain for an arbitrary key slot. Same semantics as
 * cantil_get_ca_chain but for sub-CA / general-purpose slots.
 */
cantil_err_t cantil_get_key_chain(cantil_session_t *s, uint32_t slot,
                                  uint8_t **out, size_t *out_len);

/* Serial number of the CA certificate as a DER-encoded integer. */
cantil_err_t cantil_get_ca_serial(cantil_session_t *s,
                                 uint8_t *out, size_t out_size,
                                 size_t  *out_len);

/*
 * Retrieve the device's own CA CSR for subordinate CA enrolment.
 * After an upstream CA signs it, push the result with cantil_push_ca_cert().
 */
cantil_err_t cantil_get_ca_csr(cantil_session_t *s,
                               uint8_t **out, size_t *out_len);

/*
 * Push a signed CA certificate (and optional chain above it) into slot 0.
 * If `chain` is non-NULL it is persisted as the slot's chain.der and
 * surfaced by cantil_get_ca_chain; pass NULL/0 for a self-signed CA.
 */
cantil_err_t cantil_push_ca_cert(cantil_session_t *s,
                                const uint8_t *cert,  size_t cert_len,
                                const uint8_t *chain, size_t chain_len);


/* ─── Session transport identity ─────────────────────────────────────────── */

/*
 * Retrieve the device's session (transport identity) certificate DER — the
 * P-256 cert that carries the Noise X25519 static key in a private extension.
 * Useful for out-of-band Tier-2 fingerprint pinning at first contact.
 * Caller frees *out.
 */
cantil_err_t cantil_get_session_cert(cantil_session_t *s,
                                     uint8_t **out, size_t *out_len);

/*
 * Generate and retrieve a PKCS#10 CSR for the session identity, for enrolling
 * the device's transport key under an external CA. The CSR's subject DN matches
 * the session cert and the X25519 static key rides in an extensionRequest.
 * After an upstream CA signs it, push the result with cantil_push_session_cert()
 * (Phase B T-07). Caller frees *out.
 */
cantil_err_t cantil_get_session_csr(cantil_session_t *s,
                                    uint8_t **out, size_t *out_len);

/*
 * CA-sign the device's session (transport identity) cert with an on-device CA
 * slot (Phase B T-06). The device re-signs /session/cert.der so the leaf is
 * issued by `issuer_slot` (a numbered /keys/ CA slot — never the session slot),
 * letting a Tier-3 client validate the device against an allowlisted CA. The
 * X25519 binding extension is preserved. Requires UNLOCKED + a tap-confirm
 * gesture on the device.
 *
 * `force` must be non-zero to re-sign a cert that is already CA-signed;
 * self-signed -> CA-signed is allowed without force. Returns CANTIL_ERR_* on a
 * locked device, tap denial/timeout, missing issuer slot, or missing force.
 */
cantil_err_t cantil_sign_session_from_slot(cantil_session_t *s,
                                           uint32_t issuer_slot, uint8_t force);

/*
 * Install an externally-signed session (transport identity) cert (Phase B
 * T-07). Push the cert an upstream CA produced from cantil_get_session_csr()'s
 * CSR, with `chain` the concatenated DER issuer chain above it (NULL/0 for a
 * self-signed leaf). The device validates before installing: the cert's public
 * key must equal the device's session identity key, the X25519 binding must
 * match, the subject fields must match the device's build identity, and a
 * CA-signed leaf's chain links are verified. Requires UNLOCKED + a tap-confirm
 * gesture on the device.
 *
 * `force` must be non-zero to replace a cert that is already CA-signed.
 * Returns CANTIL_ERR_* on a locked device, tap denial/timeout, a validation
 * failure, or missing force.
 */
cantil_err_t cantil_push_session_cert(cantil_session_t *s,
                                      const uint8_t *cert, size_t cert_len,
                                      const uint8_t *chain, size_t chain_len,
                                      uint8_t force);


/* ─── Client bond management (T-15) ─────────────────────────────────────── */

#define CANTIL_CLIENT_NAME_MAX 32   /* including null terminator */

typedef enum {
    CANTIL_CLIENT_KIND_HOST        = 0,
    CANTIL_CLIENT_KIND_PEER_DEVICE = 1,
} cantil_client_kind_t;

typedef struct {
    uint8_t               pubkey[32];                    /* Curve25519 static pubkey */
    cantil_client_kind_t  kind;
    uint32_t              created_at;                    /* Unix timestamp, 0 if unknown */
    char                  friendly_name[CANTIL_CLIENT_NAME_MAX];
} cantil_client_info_t;

/*
 * Enumerate all bonded clients.  cb is invoked once per bond; return nonzero
 * from cb to stop early (that value is returned from cantil_list_clients).
 */
cantil_err_t cantil_list_clients(cantil_session_t *s,
                                 int (*cb)(const cantil_client_info_t *, void *),
                                 void *userdata);

/*
 * Remove the bond for the given 32-byte Curve25519 pubkey.  The device
 * requires a tap-confirm before replying; the client waits up to
 * CANTIL_TAP_CONFIRM_TIMEOUT_MS.
 */
cantil_err_t cantil_unpair_client(cantil_session_t *s, const uint8_t pubkey[32]);

/*
 * Update the friendly name for a bonded client.  name must be ≤ 31 bytes (not
 * including the null terminator).
 */
cantil_err_t cantil_set_client_name(cantil_session_t *s,
                                    const uint8_t pubkey[32],
                                    const char *name);

/*
 * Send the 6-digit passkey the user read from the device LED to complete a
 * Method 3 (PAIRING_PASSKEY) pairing on an unknown client.
 *
 * Call this as the first command on a new session when the device is in
 * passkey-entry mode (LED shows purple 150/150 blink).  The device validates
 * the digits and — if correct — applies a tap-confirm; the caller then
 * enters the normal command loop.
 *
 * digits: value in range 000001–999999 as shown on the device.
 * Returns CANTIL_OK on success, CANTIL_ERR_AUTH if the digits are wrong or
 * the user denied the tap-confirm, CANTIL_ERR_TIMEOUT on device recv timeout,
 * or another CANTIL_ERR_* on protocol / transport error.
 */
cantil_err_t cantil_pairing_passkey_reply(cantil_session_t *s, uint32_t digits);


/* ─── Certificate signing ────────────────────────────────────────────────── */

/*
 * Sign a CSR with the device's CA key (slot 0).
 * The device decrypts the CA key → signs → zeroes the key from RAM.
 * Caller frees *out_cert.
 */
cantil_err_t cantil_sign_csr(cantil_session_t *s,
                            const uint8_t   *csr,  size_t  csr_len,
                            uint8_t        **out_cert, size_t *out_len);


/* ─── Certificate store ──────────────────────────────────────────────────── */

typedef struct {
    uint8_t  serial[20];
    size_t   serial_len;
    char     subject[256];
    char     issuer[256];
    int64_t  not_before;        /* Unix timestamp */
    int64_t  not_after;         /* Unix timestamp */
    uint32_t key_slot;          /* slot that owns this cert; UINT32_MAX = CA */
    uint8_t  revoked;
    int64_t  revoked_at;        /* Unix timestamp, 0 if not revoked          */
} cantil_cert_info_t;

cantil_err_t cantil_get_cert_count(cantil_session_t *s, uint32_t *out_count);

/*
 * Iterate the cert store. cb returns 0 to continue, nonzero to stop early
 * (that value is returned from cantil_list_certs).
 */
cantil_err_t cantil_list_certs(cantil_session_t *s,
                              int (*cb)(const cantil_cert_info_t *, void *),
                              void *userdata);

/* Retrieve a specific cert DER by its serial number. Caller frees *out. */
cantil_err_t cantil_get_cert(cantil_session_t *s,
                            const uint8_t *serial, size_t serial_len,
                            uint8_t **out, size_t *out_len);

/*
 * Revoke a cert and record `now_unix` as the revocation date. The next
 * cantil_get_crl on this issuer slot will reflect the revocation; the
 * device's per-slot RFC 5280 CRL Number is also bumped, so verifiers can
 * detect CRL rollback.
 *
 * Pass now_unix=0 if the caller has no wall clock. The device's DER
 * encoder substitutes thisUpdate at fetch time, so the produced CRL is
 * still valid, but the revocationDate carries no real-time precision.
 *
 * CRL distribution to relying parties is the caller's responsibility.
 */
cantil_err_t cantil_revoke_cert_at(cantil_session_t *s,
                                   const uint8_t *serial, size_t serial_len,
                                   uint64_t now_unix);

/* Convenience wrapper: cantil_revoke_cert_at with now_unix=0. */
cantil_err_t cantil_revoke_cert(cantil_session_t *s,
                                const uint8_t *serial, size_t serial_len);

/*
 * Check all stored certs against now_unix (Unix timestamp provided by host —
 * device has no RTC). Certs with not_after < now_unix are marked revoked and
 * the CRL is updated. Returns the count of newly expired certificates.
 */
cantil_err_t cantil_auto_expire(cantil_session_t *s,
                               int64_t  now_unix,
                               uint32_t *out_expired_count);

/*
 * Retrieve an RFC 5280 v2 CertificateList (DER) for the given issuer slot,
 * signed by that slot's private key. `now_unix` populates thisUpdate;
 * nextUpdate is computed by the device per its CONFIG_CANTIL_CRL_VALIDITY_SEC
 * window. Caller frees *out.
 *
 * Returns CANTIL_ERR_INVALID_ARG if now_unix is 0 (a CRL with no thisUpdate
 * is not RFC-conformant), CANTIL_ERR_NOT_FOUND if `issuer_slot` has no key
 * or no self-signed cert (the cert provides the issuer Name encoded into
 * the CRL).
 */
cantil_err_t cantil_get_crl(cantil_session_t *s,
                            uint32_t issuer_slot,
                            uint64_t now_unix,
                            uint8_t **out, size_t *out_len);


/* ─── Key slot management ────────────────────────────────────────────────── */

#define CANTIL_KEY_SLOT_CA    0    /* reserved; always the CA key */

typedef enum {
    CANTIL_KEY_TYPE_EC_P256 = 1,
    CANTIL_KEY_TYPE_EC_P384 = 2,
    CANTIL_KEY_TYPE_RSA2048 = 3,  /* future; may return ERR_NOT_SUPPORTED     */
} cantil_key_type_t;

typedef struct {
    uint32_t         slot_id;
    cantil_key_type_t key_type;
    uint8_t          pub_key[65]; /* uncompressed EC point or RSA modulus     */
    size_t           pub_key_len;
    uint8_t          has_csr;
    uint8_t          has_cert;
    int64_t          created_at;  /* Unix timestamp */
    /* populated from cert if has_cert: */
    uint8_t          cert_serial[20];
    size_t           cert_serial_len;
    char             cert_subject[256];
    int64_t          cert_not_before;
    int64_t          cert_not_after;
    uint8_t          cert_revoked;
} cantil_key_slot_info_t;

cantil_err_t cantil_list_keys(cantil_session_t *s,
                             int (*cb)(const cantil_key_slot_info_t *, void *),
                             void *userdata);

/*
 * Generate a new key in the next available slot.
 * Returns the assigned slot ID in *out_slot_id.
 */
cantil_err_t cantil_gen_key(cantil_session_t  *s,
                           cantil_key_type_t  type,
                           uint32_t         *out_slot_id);

/*
 * Delete a key slot (key blob, meta, x509 data, cert, CSR). Refused for
 * slot 0 (CA) and any slot with the protected flag set.
 */
cantil_err_t cantil_delete_key(cantil_session_t *s, uint32_t slot_id);

/*
 * PROTECT_SLOT — set the protection flag on a key slot. Requires a tap-
 * confirm gesture on the device; this call blocks until the user
 * confirms, denies, or the confirm window expires.
 *
 *   protect_issued_certs: if true, all certs previously signed by this
 *                         slot, and any future ones, are marked protected
 *                         (immune to manual REVOKE_CERT; auto-expire still
 *                         applies).
 */
cantil_err_t cantil_protect_slot(cantil_session_t *s, uint32_t slot_id,
                                 uint8_t protect_issued_certs);

/* UNPROTECT_SLOT — clear the slot protection flag. Does NOT un-protect
 * certs that already had ISSUED_FLAG_PROTECTED set; that flag is treated
 * as permanent. Same tap-confirm requirement as PROTECT_SLOT. */
cantil_err_t cantil_unprotect_slot(cantil_session_t *s, uint32_t slot_id);

/*
 * SIGN_CSR_SLOT — generic per-slot CSR signing. Issuer slot must have a
 * private key and stored x509 params (so the issuer DN can be rebuilt).
 * Caller frees *out_cert.
 */
cantil_err_t cantil_sign_csr_slot(cantil_session_t *s,
                                  uint32_t issuer_slot,
                                  const uint8_t *csr, size_t csr_len,
                                  uint8_t **out_cert, size_t *out_len);

/*
 * Generate a CSR for a key slot and store it on the device.
 * subject_dn: RFC 4514 string, e.g. "CN=mykey,O=Acme,C=US"
 * After this call, retrieve the CSR with cantil_get_key_csr().
 */
cantil_err_t cantil_gen_key_csr(cantil_session_t *s,
                               uint32_t         slot_id,
                               const char      *subject_dn);

/* Retrieve the stored CSR for a key slot. Caller frees *out. */
cantil_err_t cantil_get_key_csr(cantil_session_t *s,
                               uint32_t  slot_id,
                               uint8_t **out, size_t *out_len);

/*
 * Push a signed certificate (and optional chain) for a key slot.
 * The device validates that the cert matches the slot's public key.
 * If `chain` is non-NULL it is persisted as the slot's chain.der and
 * surfaced by cantil_get_key_chain; pass NULL/0 if the cert chains up
 * to a CA already on the device.
 */
cantil_err_t cantil_push_key_cert(cantil_session_t *s,
                                 uint32_t         slot_id,
                                 const uint8_t   *cert,  size_t cert_len,
                                 const uint8_t   *chain, size_t chain_len);

/*
 * Key-usage bits for cantil_x509_data_t.key_usage.
 *
 * Values follow the RFC 5280 §4.2.1.3 BIT STRING numbering (bit 0 is the
 * high-order bit of the first octet). The constants below are the only
 * usages the firmware emits today — extend in parallel with the device
 * side if more are needed.
 */
#define CANTIL_KU_DIGITAL_SIGNATURE 0x0080  /* bit 0 */
#define CANTIL_KU_KEY_CERT_SIGN     0x0004  /* bit 5 */
#define CANTIL_KU_CRL_SIGN          0x0002  /* bit 6 */

/*
 * x.509 subject data for a key slot.
 *
 * Strings are NUL-terminated C strings; pass NULL or "" for any optional
 * field. Length caps follow the firmware's parser (`x509_params_t` in
 * firmware/src/ca/ca.c): CN/O/OU/ST/L ≤ 64 bytes each, C exactly 2 bytes
 * (ISO 3166 alpha-2) or empty.
 *
 * path_len = -1 means "unconstrained" (encoded on the wire as 0xFF);
 * 0..253 are valid finite path-length constraints; ignored when is_ca = 0.
 */
typedef struct cantil_x509_data {
    uint16_t    validity_days;   /* required, non-zero */
    bool        is_ca;
    int8_t      path_len;        /* -1 = unconstrained */
    uint16_t    key_usage;       /* CANTIL_KU_* bitmask */

    const char *cn;              /* required, non-empty */
    const char *o;               /* optional */
    const char *ou;              /* optional */
    const char *c;               /* optional, 2-char ISO 3166 or NULL/"" */
    const char *st;              /* optional */
    const char *l;               /* optional */
} cantil_x509_data_t;

/*
 * Upload x.509 subject data for a key slot.
 *
 * The device writes the data to /keys/<slot>/x509_data.bin and, if the slot
 * already has a private key, rebuilds the slot's self-signed cert from it
 * immediately. Slot 0 (the master CA) requires this call after first boot
 * before any CA operation succeeds (eager keygen + lazy cert gen, see the
 * "Slot 0 bootstrap" entry in CLAUDE.md).
 *
 * Returns CANTIL_ERR_DEVICE_LOCKED if the slot is protected and already
 * holds a cert (bootstrap exemption: a protected slot with no cert still
 * accepts this call, so slot 0 can be initialised). CANTIL_ERR_INVALID_ARG
 * for missing CN, validity_days=0, or wrong country-code length.
 */
cantil_err_t cantil_push_key_x509(cantil_session_t *s,
                                 uint32_t         slot_id,
                                 const cantil_x509_data_t *x509);


/* ─── Intra-device signing ───────────────────────────────────────────────── */

/*
 * Sign the CSR of one device key slot using a different device key slot as
 * the issuing CA — entirely on-device. No key material leaves the hardware.
 *
 * issuer_slot: the signing key (must have a cert establishing its CA role).
 *              Pass CANTIL_KEY_SLOT_CA (0) to use the primary CA key.
 * subject_slot: the key whose stored CSR is to be signed. The CSR must
 *               have been generated first with cantil_gen_key_csr().
 *
 * The resulting certificate is stored in the subject slot's cert.der and
 * added to the issued cert store, exactly as if signed via cantil_sign_csr().
 * Caller does NOT receive the cert directly — retrieve it afterward with
 * cantil_get_key_csr() or by listing keys.
 *
 * Use case: the device holds an intermediate CA key (slot 1) signed by the
 * root CA key (slot 0), and you want the intermediate to sign an end-entity
 * key (slot 2) — all without any key leaving the device.
 */
cantil_err_t cantil_sign_key_slot(cantil_session_t *s,
                                 uint32_t issuer_slot,
                                 uint32_t subject_slot);


/* ─── Configuration ──────────────────────────────────────────────────────── */

#define CANTIL_TAP_SINGLE 1
#define CANTIL_TAP_DOUBLE 2
#define CANTIL_TAP_MAX_LEN 16

/*
 * Replace the tap-gesture unlock sequence on the device.
 * taps: array of CANTIL_TAP_SINGLE / CANTIL_TAP_DOUBLE, length <= CANTIL_TAP_MAX_LEN.
 */
cantil_err_t cantil_set_unlock_sequence(cantil_session_t *s,
                                      const uint8_t *taps,
                                      uint8_t        tap_count);


/* ─── Firmware update ────────────────────────────────────────────────────── */

/*
 * Trigger a reboot into the UF2 bootloader over an authenticated Noise session.
 * The device sends an ACK, then immediately sets GPREGRET=0x57 and warm-reboots
 * into the Adafruit UF2 mass-storage bootloader. Returns CANTIL_OK when the ACK
 * is received (the device is rebooting). Returns CANTIL_ERR_NOT_SUPPORTED on
 * firmware built without UF2 support (MCUBOOT tier).
 *
 * After this returns CANTIL_OK, poll for the XIAO-SENSE* drive (up to ~10 s)
 * and copy the new .uf2 file to it. The cantil CLI's `update-firmware` command
 * does this automatically.
 */
cantil_err_t cantil_trigger_uf2_reboot(cantil_session_t *s);

/*
 * Stream a signed firmware image to the device over the Noise session and
 * trigger installation via the MCUboot secondary slot.
 *
 * Available only on MCUBOOT firmware tier.  Returns
 * CANTIL_ERR_NOT_SUPPORTED on UF2-only firmware (use cantil_trigger_uf2_reboot
 * + out-of-band UF2 copy for those builds).
 *
 * Flow:
 *   1. Send BEGIN with the image size.
 *   2. Send CHUNK messages (up to CANTIL_FW_CHUNK_MAX bytes each).
 *   3. Send COMMIT — device prompts for a tap-confirm gesture.
 *   4. On user tap: device reboots into MCUboot, which validates and swaps.
 *
 * progress_cb (optional): called after each chunk ACK with bytes done / total.
 * Pass NULL to suppress progress reporting.
 *
 * Returns CANTIL_OK when COMMIT is acknowledged (device is about to reboot).
 * On any error the in-progress update is rolled back on the device side.
 */
#define CANTIL_FW_CHUNK_MAX 3968

cantil_err_t cantil_fw_update(cantil_session_t *s,
                              const char *image_path,
                              void (*progress_cb)(size_t done, size_t total,
                                                  void *user),
                              void *user);


/* ─── Hardware TRNG ──────────────────────────────────────────────────────── */

/*
 * Request len bytes of entropy from the device's CryptoCell-310 TRNG.
 * The bytes arrive over the Noise session (encrypted in transit).
 * Maximum single request: 4096 bytes.
 *
 * For formatted output (UUID, hex strings, random integers, etc.) see
 * cantil_random.h, which wraps this call through a pluggable source interface
 * and can also be used with non-device entropy sources.
 */
cantil_err_t cantil_random_bytes(cantil_session_t *s,
                                uint8_t *buf, size_t len);

#define CANTIL_RANDOM_MAX_REQUEST 4096


#ifdef __cplusplus
}
#endif

#endif /* CANTIL_H */
