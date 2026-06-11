#pragma once

#include <stdint.h>

/*
 * Persistent key storage for the cantil client.
 *
 * Files live in ${XDG_CONFIG_HOME:-$HOME/.config}/cantil/:
 *   client_priv.bin              — 32-byte Curve25519 private key  (mode 0600)
 *   client_pub.bin               — 32-byte Curve25519 public key
 *   client_cert.der              — stored client certificate (optional)
 *   client_chain.der             — optional client certificate chain
 *
 *   devices/<fp16>/              — one subdir per paired device
 *                                  (fp16 = SHA-256(dev_pub)[0:8] as lowercase hex)
 *     device_pub.bin             — 32-byte pinned device Noise static public key
 *     session_fp.bin             — 32-byte SHA-256 fingerprint of device session cert leaf
 *     session_cn.bin             — NUL-terminated CN string from the device session cert
 *
 * key_store_init() creates the directory structure if it does not exist.
 * key_store_init_device() / key_store_select_device() select the per-device
 * subdir; device-scoped functions operate relative to the selected subdir.
 */

int key_store_init(void);

/*
 * Create (if needed) and select the per-device subdir for pub.
 * Must be called before any device-scoped save/load during 'pair'.
 */
int key_store_init_device(const uint8_t pub[32]);

/*
 * Select an existing per-device subdir for pub.
 * Returns 0 on success, -ENOENT if this device has never been paired.
 */
int key_store_select_device(const uint8_t pub[32]);

/* Returns 0 if both files exist and were read, -ENOENT if not yet generated. */
int key_store_load_client_keypair(uint8_t priv[32], uint8_t pub[32]);

/* Writes both files; client_priv.bin is created with mode 0600. */
int key_store_save_client_keypair(const uint8_t priv[32], const uint8_t pub[32]);

/* Returns 0 on success, -ENOENT if device has not been paired yet. */
int key_store_load_device_pubkey(uint8_t pub[32]);
int key_store_save_device_pubkey(const uint8_t pub[32]);

/* Returns 1 if the device pubkey file exists in the selected device dir, 0 otherwise. */
int key_store_has_device_pubkey(void);

/*
 * Session cert fingerprint (SHA-256 of leaf DER, 32 bytes).
 * Written by 'pair'; read by subsequent commands to enable Tier 2 by default.
 * Returns -ENOENT if not yet stored.
 */
int key_store_save_session_fp(const uint8_t fp[32]);
int key_store_load_session_fp(uint8_t fp[32]);

/*
 * Session cert CN string (FICR-derived device serial, e.g. "Cantil-69A3031F0204C8EE").
 * Written by 'pair'; used as the default expected_cn for Tier 4 (--trust ca+cn).
 * buf must be at least 65 bytes. Returns -ENOENT if not yet stored.
 */
int key_store_save_session_cn(const char *cn);
int key_store_load_session_cn(char *buf, size_t buflen);

/*
 * Client identity certificate DER (Method 4, T-19).
 *
 * client_cert.der  — the client's X.509 leaf cert (must be signed by the
 *                    device's trust anchor CA).
 * client_chain.der — optional intermediate chain (concatenated DER); absent
 *                    when the leaf is directly signed by the anchor CA.
 *
 * key_store_load_client_cert() malloc-allocates *out; caller frees with free().
 * key_store_has_client_cert() returns 1 if client_cert.der exists, 0 otherwise.
 * key_store_load_client_chain() returns -ENOENT if no chain has been stored.
 */
int key_store_save_client_cert(const uint8_t *cert_der, size_t cert_len);
int key_store_load_client_cert(uint8_t **out, size_t *out_len);
int key_store_has_client_cert(void);
int key_store_save_client_chain(const uint8_t *chain_der, size_t chain_len);
int key_store_load_client_chain(uint8_t **out, size_t *out_len);
