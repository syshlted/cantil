/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * Session slot — the device's transport identity (transport + pairing T-02).
 *
 * The slot lives at /session/ on LittleFS (NOT one of the numbered /keys/<n>/
 * slots) and holds two private keys: the X25519 Noise static key used for the
 * handshake (key.bin) and a P-256 identity key (id_key.bin) that signs an
 * ECDSA self-signed X.509 cert (cert.der). The 32-byte X25519 pubkey is bound
 * into the cert via a private-OID extension and cached in meta.bin.
 */

/*
 * Boot-time init. On first boot generates the identity (a fresh X25519 Noise
 * static key + a P-256 cert-signing key — the session slot is the single source
 * of truth as of T-04; session.c loads the X25519 key from /session/key.bin),
 * builds the self-signed cert, and persists everything. On later boots it runs
 * the strict subject comparison against the build constant (T-03). Must run
 * after storage_init() and crypto_init(); ca_build_session_cert() depends on
 * the CA crypto path.
 *
 * Returns 0 on success or when the slot already exists, negative errno on a
 * keygen / crypto / storage failure.
 */
int session_slot_init(void);

/*
 * True if the device booted into identity-recovery mode (T-03): strict mode is
 * on and the stored session cert's subject-side fields no longer match the
 * build constant. While true, the protocol dispatcher refuses every opcode
 * except DEVICE_STATUS and RESET_DEVICE. Always false in non-strict builds.
 */
bool session_slot_in_recovery(void);

/* Cached X25519 Noise static public key from /session/meta.bin. */
int session_slot_get_pubkey(uint8_t pub[32]);

/*
 * Read the stored session identity cert DER. *len is in/out (capacity →
 * length). Returns -ENOENT before first-boot init.
 */
int session_slot_get_cert(uint8_t *der, size_t *len);

/*
 * Generate a PKCS#10 CSR for the session transport identity (T-05) and write
 * it into the caller's buffer. The CSR is signed by the P-256 identity key,
 * carries the device's build-constant subject DN (with the FICR-derived CN),
 * and embeds the Noise X25519 static key as an extensionRequest. Also persists
 * the result to /session/csr.der. *len is in/out (capacity → length). Returns
 * -ENOENT before first-boot init, -ENOMEM if the CSR doesn't fit.
 */
int session_slot_get_csr(uint8_t *der, size_t *len);

/*
 * CA-sign the session transport-identity cert with on-device CA slot
 * `issuer_slot` (transport + pairing T-06). Decrypts the P-256 identity key,
 * rebuilds the build-constant subject DN (FICR CN), calls ca_sign_session_cert()
 * to produce a cert issued by the CA slot (X25519 binding extension preserved),
 * overwrites /session/cert.der, and sets the meta "CA-signed" flag.
 *
 * Re-signing rule: if the stored cert is already CA-signed, the call is refused
 * with -EEXIST unless `force` is true. Self-signed -> CA-signed is always
 * allowed.
 *
 * Returns 0 on success, -ENOENT before first-boot init, -EEXIST when already
 * CA-signed and !force, -ENOENT / -EINVAL from the issuer slot, or another
 * negative errno on a crypto / storage failure. The session slot may never be
 * the issuer (the caller / dispatcher rejects issuer_slot in the session range).
 */
int session_slot_sign_from_slot(uint32_t issuer_slot, bool force);

/*
 * Install an externally-signed session transport-identity cert (transport +
 * pairing T-07, PUSH_SESSION_CERT). `cert` is the new leaf DER; `chain` is the
 * issuer chain above it (concatenated DER, may be empty for a self-signed
 * leaf). The cert is validated before it touches storage — see
 * ca_validate_pushed_session_cert(): the SPKI must equal the device's P-256
 * identity key, the X25519 binding must match, the subject-side fields must
 * match the build constant, and a CA-signed leaf's chain links are verified.
 *
 * On success the leaf overwrites /session/cert.der, the chain is written to
 * /session/chain.der (or cleared if none), and the meta "CA-signed" flag is set
 * iff the pushed leaf is not self-signed.
 *
 * Re-signing rule (mirrors session_slot_sign_from_slot): if the stored cert is
 * already CA-signed, the call is refused with -EEXIST unless `force`.
 *
 * Returns 0 on success, -ENOENT before first-boot init, -EEXIST when already
 * CA-signed and !force, -EINVAL on any validation failure, or another negative
 * errno on a crypto / storage failure.
 */
int session_slot_push_cert(const uint8_t *cert, size_t cert_len,
			   const uint8_t *chain, size_t chain_len, bool force);
