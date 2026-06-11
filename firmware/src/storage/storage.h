#pragma once

#include <stdint.h>
#include <stddef.h>

int storage_init(void);

/* Key slot — encrypted key blob */
int storage_key_write(uint32_t slot, const uint8_t *blob, size_t len);
int storage_key_read(uint32_t slot, uint8_t *blob, size_t *len);

/* Key slot — DER-encoded certificate (CA cert or issued cert for the slot) */
int storage_slot_cert_write(uint32_t slot, const uint8_t *der, size_t len);
int storage_slot_cert_read(uint32_t slot, uint8_t *der, size_t *len);
/* Returns 1 if /keys/<slot>/cert.der exists, 0 if not, negative errno on error. */
int storage_slot_cert_exists(uint32_t slot);

/*
 * Per-slot issuer chain (concatenated DER certs above this slot's own cert).
 * Written by ca_push_cert / ca_push_key_cert when the host supplies a chain.
 * `storage_slot_chain_read` returns -ENOENT if no chain was persisted (the
 * slot is a self-signed root, or it was signed on-device by another slot).
 */
int storage_slot_chain_write(uint32_t slot, const uint8_t *der, size_t len);
int storage_slot_chain_read(uint32_t slot, uint8_t *der, size_t *len);
int storage_slot_chain_exists(uint32_t slot);
/* Remove a stale chain. Returns 0 on success or if no chain existed. */
int storage_slot_chain_delete(uint32_t slot);
/* Returns 1 if /keys/<slot>/key.bin exists, 0 if not, negative errno on error. */
int storage_slot_key_exists(uint32_t slot);
/* Returns 1 if /keys/<slot>/csr.der exists, 0 if not, negative errno on error. */
int storage_slot_csr_exists(uint32_t slot);

/*
 * Wipe all files under /keys/<slot>/ and remove the directory.  Overwrites
 * key.bin with random garbage first so the encrypted blob is unrecoverable
 * (same rationale as storage_secure_wipe).  Returns 0 on a clean wipe (or
 * if the slot was already empty), negative errno on storage error.
 */
int storage_slot_delete(uint32_t slot);

/*
 * Per-slot metadata: protection flags + key type.  See slot_meta_t in
 * storage.c for the wire layout (versioned, packed, 24 bytes).
 */
int storage_slot_meta_write(uint32_t slot, const uint8_t *blob, size_t len);
int storage_slot_meta_read(uint32_t slot, uint8_t *blob, size_t *len);

/*
 * Per-slot x509 subject data (CN, O, validity, extensions).  Format owned
 * by ca.c; storage layer treats it as opaque bytes.
 */
int storage_slot_x509_write(uint32_t slot, const uint8_t *blob, size_t len);
int storage_slot_x509_read(uint32_t slot, uint8_t *blob, size_t *len);

/* Key slot — DER-encoded CSR */
int storage_slot_csr_write(uint32_t slot, const uint8_t *der, size_t len);
int storage_slot_csr_read(uint32_t slot, uint8_t *der, size_t *len);

/* Issued certificate store — indexed by serial number */
int storage_issued_cert_write(const uint8_t *serial, size_t serial_len,
			      const uint8_t *der, size_t der_len);
int storage_issued_cert_read(const uint8_t *serial, size_t serial_len,
			     uint8_t *der, size_t *der_len);

/* Per-issued-cert metadata (issuer slot, revocation flags, subject CN).
 * Format is opaque to storage — see issued_cert_meta_t in ca.c. */
int storage_issued_meta_write(const uint8_t *serial, size_t serial_len,
			      const uint8_t *blob, size_t blob_len);
int storage_issued_meta_read(const uint8_t *serial, size_t serial_len,
			     uint8_t *blob, size_t *blob_len);

/* Returns 1 if /certs/<hex>/cert.der exists, 0 if not, negative errno on error. */
int storage_issued_cert_exists(const uint8_t *serial, size_t serial_len);

/*
 * Iterate every entry in /certs/.  For each subdirectory whose name is valid
 * lowercase hex, decode the serial bytes and invoke `cb(serial, serial_len,
 * user_ctx)`. If cb returns non-zero, iteration stops and that value is
 * returned. Returns 0 on a clean walk, negative errno on storage error.
 */
typedef int (*storage_issued_iter_cb)(const uint8_t *serial, size_t serial_len,
				      void *user);
int storage_issued_certs_iter(storage_issued_iter_cb cb, void *user);

/*
 * Per-slot RFC 5280 CRL Number — a monotonic uint32 stored at
 * /keys/<slot>/crl_number.bin. Bumped on every successful revoke by ca.c;
 * read each time GET_CRL builds a fresh DER. Read returns -ENOENT if the
 * slot has never revoked anything (caller treats as 0).
 */
int storage_slot_crl_number_read(uint32_t slot, uint32_t *out);
int storage_slot_crl_number_write(uint32_t slot, uint32_t value);

/* Device config (tap sequences, unlock timeout, LED parameters) */
int storage_config_write(const uint8_t *data, size_t len);
int storage_config_read(uint8_t *data, size_t *len);

/*
 * Unlock sequence — the user's tap gesture stored as a digit array.
 * Written by the gesture layer after CHANGE_SEQ_VERIFY succeeds.
 * Returns -ENOENT on first boot (no sequence stored yet).
 */
int storage_unlock_seq_write(const uint8_t *seq, size_t len);
int storage_unlock_seq_read(uint8_t *seq, size_t *len);

/*
 * Failed-unlock counter — persists across reboot so a power-cycle does not
 * reset the rate-limit ramp. The gesture layer increments on every wrong
 * attempt while LOCKED and clears on successful unlock. Returns -ENOENT if
 * never written (caller treats as 0).
 */
int storage_unlock_attempts_write(uint32_t count);
int storage_unlock_attempts_read(uint32_t *out);

/*
 * Secure wipe: erase /keys/, /certs/, /config*, /noise/, and
 * overwrite the slot 0 encrypted key blob with random data before
 * unlinking. FICR-derived storage key is intrinsic to the chip, so
 * erasing the ciphertext makes the key unrecoverable. Caller must
 * reboot after this returns.
 */
int storage_secure_wipe(void);

/*
 * Inventory helpers used by DEVICE_STATUS.
 *
 * storage_count_slots_used   — slots 0..CANTIL_MAX_KEY_SLOTS-1 with a key.bin
 * storage_count_issued_certs — entries under /certs/
 * storage_free_kb            — free LittleFS space (kilobytes)
 */
int storage_count_slots_used(uint32_t *out);
int storage_count_issued_certs(uint32_t *out);
int storage_free_kb(uint32_t *out);

/*
 * Client bond store (/clients/<hex8>/) — transport+pairing T-15.
 *
 * Each bonded peer is stored under a subdirectory named by the first 4 bytes
 * of their Curve25519 static pubkey (8 lowercase hex chars).  pubkey.bin is
 * the authoritative presence marker; meta.bin holds the client_meta_t blob
 * (format owned by client_bond.c, opaque here).  psk.bin and cert.der are
 * optional (Methods 3/5 and 4/5 respectively).
 */
int storage_client_bond_pubkey_write(const uint8_t id[4], const uint8_t pub[32]);
int storage_client_bond_pubkey_read(const uint8_t id[4], uint8_t pub[32]);
int storage_client_bond_meta_write(const uint8_t id[4], const uint8_t *blob, size_t len);
int storage_client_bond_meta_read(const uint8_t id[4], uint8_t *blob, size_t *len);
int storage_client_bond_psk_write(const uint8_t id[4], const uint8_t *blob, size_t len);
int storage_client_bond_psk_read(const uint8_t id[4], uint8_t *blob, size_t *len);
int storage_client_bond_psk_exists(const uint8_t id[4]);
int storage_client_bond_cert_write(const uint8_t id[4], const uint8_t *der, size_t len);
int storage_client_bond_cert_read(const uint8_t id[4], uint8_t *der, size_t *len);
int storage_client_bond_cert_exists(const uint8_t id[4]);
/* Returns 1 if /clients/<hex8>/pubkey.bin exists, 0 if not, negative errno on error. */
int storage_client_bond_exists(const uint8_t id[4]);
/* Wipe all files under /clients/<hex8>/ and remove the directory. */
int storage_client_bond_delete(const uint8_t id[4]);

typedef int (*storage_client_bond_iter_cb)(const uint8_t id[4], void *user);
int storage_client_bonds_iter(storage_client_bond_iter_cb cb, void *user);
int storage_count_client_bonds(uint32_t *out);

/*
 * Firmware update pending sentinel — /lfs/fw_pending.
 * Written before rebooting into MCUboot to install a new image.
 * Read on next boot to distinguish a post-update boot from a normal one.
 * Cleared once the boot outcome is determined (confirmed or rejected).
 */
int storage_fw_pending_set(void);
int storage_fw_pending_clear(void);
int storage_fw_pending_check(void); /* returns 1 if pending, 0 if not, <0 on error */

/*
 * Noise static keypair at /noise/ — RETIRED (transport+pairing T-04). The live
 * device X25519 key now lives in the session slot (/session/key.bin, see
 * session_slot.c); these functions are no longer called. Left in place only so
 * storage_secure_wipe still erases any /noise/ blob on units flashed before
 * T-04. Do not use for new code.
 * Returns -ENOENT if no keypair has been stored.
 */
int storage_noise_keypair_write(const uint8_t priv[32], const uint8_t pub[32]);
int storage_noise_keypair_read(uint8_t priv[32], uint8_t pub[32]);

/*
 * Session slot (/session/) — the device's transport identity (transport +
 * pairing T-02). NOT one of the numbered /keys/<n>/ slots. The two key blobs
 * are AES-256-GCM encrypted by session_slot.c and treated as opaque bytes
 * here (same split as /keys/): key.bin holds the X25519 Noise scalar, id_key.bin
 * the P-256 cert-signing scalar. All readers return -ENOENT before first boot.
 */
int storage_session_key_write(const uint8_t *blob, size_t len);
int storage_session_key_read(uint8_t *blob, size_t *len);
int storage_session_id_key_write(const uint8_t *blob, size_t len);
int storage_session_id_key_read(uint8_t *blob, size_t *len);
int storage_session_meta_write(const uint8_t *blob, size_t len);
int storage_session_meta_read(uint8_t *blob, size_t *len);
int storage_session_cert_write(const uint8_t *der, size_t len);
int storage_session_cert_read(uint8_t *der, size_t *len);
/* Returns 1 if /session/cert.der exists, 0 if not, negative errno on error. */
int storage_session_cert_exists(void);
/* /session/csr.der — generated on demand by GET_SESSION_CSR (T-05). */
int storage_session_csr_write(const uint8_t *der, size_t len);
int storage_session_csr_read(uint8_t *der, size_t *len);
/*
 * /session/chain.der — issuer chain above the externally-signed leaf, set by
 * PUSH_SESSION_CERT (T-07). The leaf itself is cert.der; this holds the
 * intermediate(s)/root pushed alongside it. `_read` returns -ENOENT if none.
 */
int storage_session_chain_write(const uint8_t *der, size_t len);
int storage_session_chain_read(uint8_t *der, size_t *len);
int storage_session_chain_exists(void);
int storage_session_chain_delete(void);
