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
int crypto_pubkey_from_privkey(const uint8_t *privkey, size_t privkey_len,
			       uint8_t *pubkey_out, size_t *pubkey_len);
int crypto_sign(const uint8_t *privkey, size_t privkey_len,
		const uint8_t *digest, size_t digest_len,
		uint8_t *sig_out, size_t *sig_len);

/*
 * Storage encryption.
 * Key derived from FICR device UID via HKDF-SHA256.
 */
int crypto_storage_key_derive(uint8_t key_out[32]);
int crypto_encrypt_blob(const uint8_t storage_key[32],
			const uint8_t *plaintext, size_t pt_len,
			uint8_t *ciphertext, size_t *ct_len);
int crypto_decrypt_blob(const uint8_t storage_key[32],
			const uint8_t *ciphertext, size_t ct_len,
			uint8_t *plaintext, size_t *pt_len);
