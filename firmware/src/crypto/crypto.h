/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

#pragma once

#include <stdint.h>
#include <stddef.h>

int crypto_init(void);

/* Hardware TRNG — fills buf with len random bytes via CryptoCell-310 */
int crypto_trng(uint8_t *buf, size_t len);

/*
 * Key slot operations.
 * The private key material lives in an AES-256-GCM encrypted blob in storage.
 * During signing: decrypt → load into CC310 → sign → zero RAM copy.
 */
int crypto_keygen(uint8_t *privkey_out, size_t *privkey_len);
int crypto_pubkey_from_privkey(const uint8_t *privkey, size_t privkey_len, uint8_t *pubkey_out,
			       size_t *pubkey_len);
int crypto_sign(const uint8_t *privkey, size_t privkey_len, const uint8_t *digest,
		size_t digest_len, uint8_t *sig_out, size_t *sig_len);

/*
 * SHA-256 of one buffer.
 *
 * Added by step 6a of docs/roadmap/wolfssl-migration.md. crypto_sign() takes a
 * pre-digested hash, so whoever signs must hash first — ca.c does, for the CRL
 * TBS, and had been reaching straight into mbedtls_sha256() to do it. That was
 * the last reason for the CRL path to know which library is underneath.
 */
int crypto_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

/*
 * RFC 5869 HKDF-SHA256 (extract-then-expand), general form.
 *
 * Added by step 6b of docs/roadmap/wolfssl-migration.md. Both backends already
 * had HKDF inside crypto_storage_key_derive(); this exposes it, because
 * clients/pairing.c was calling mbedtls_hkdf() directly to derive the passkey
 * PSK and was the last file outside the backend implementations to name an
 * X.509/crypto library at all.
 *
 * A NULL salt (salt_len 0) means RFC 5869's "not provided" case, for which the
 * standard substitutes a hash-length block of zeros. Both libraries implement
 * that, so a key derived under one backend is byte-identical under the other —
 * which is not a nicety: crypto_storage_key_derive() sits on this, and a
 * divergence there is an unreadable CA key. firmware/tests/crypto_kat{,_wolfssl}
 * pins it against a fixed answer for exactly that reason.
 *
 * Note for implementers: mbedTLS takes salt before IKM, wolfCrypt takes IKM
 * before salt. This signature follows the RFC's own order (IKM is the secret,
 * so it leads).
 */
int crypto_hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len,
		       const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len);

/*
 * Storage encryption.
 * Key derived from FICR device UID via HKDF-SHA256.
 */
int crypto_storage_key_derive(uint8_t key_out[32]);

/* crypto_device_id() — the FICR UID this HKDFs from. Standalone so callers
 * that want the ID but not a crypto stack need not link one. */
#include "crypto/device_id.h"
int crypto_encrypt_blob(const uint8_t storage_key[32], const uint8_t *plaintext, size_t pt_len,
			uint8_t *ciphertext, size_t *ct_len);
int crypto_decrypt_blob(const uint8_t storage_key[32], const uint8_t *ciphertext, size_t ct_len,
			uint8_t *plaintext, size_t *pt_len);
