/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

/*
 * crypto module — PSA backend.
 *
 * Counterpart to crypto.c. Selected when CANTIL_CRYPTO_BACKEND_ACCELERATED=y;
 * routes ECC P-256 (keygen / pubkey-derive / deterministic ECDSA-SHA256),
 * AES-256-GCM, SHA-256 HKDF, and TRNG through PSA. Under NCS this dispatches
 * to CC3XX silicon for AES + ECDSA + SHA-256 + HKDF + TRNG; Oberon handles
 * primitives CC3XX doesn't cover (none in this module).
 *
 * Wire-format invariants kept bit-identical to crypto.c, so a stored
 * encrypted key blob written under the FREE backend is decryptable here:
 *   - Private key: 32-byte big-endian scalar (matches PSA ECC_KEY_PAIR export).
 *   - Public key: 65-byte SEC1 uncompressed 0x04 || X || Y (matches PSA
 *     ECC_PUBLIC_KEY export).
 *   - ECDSA signature: raw 64-byte r || s (matches PSA P1363 output of
 *     psa_sign_hash; the FREE backend produces the same layout by
 *     concatenating the two mbedtls_mpi values).
 *   - Encrypted blob layout: [12-byte nonce][ct][16-byte GCM tag] — PSA's
 *     psa_aead_encrypt with ad=NULL,0 emits ct || tag adjacent in the
 *     output, identical to mbedtls_gcm_crypt_and_tag's behaviour here.
 *   - Storage key: HKDF-SHA256(salt=empty, ikm=FICR UID, info="cantil-storage-key").
 *     PSA's psa_key_derivation_input_bytes(SALT, "", 0) matches an omitted
 *     RFC 5869 salt (defaults to hash_length zero bytes).
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <string.h>
#include <errno.h>

#include <psa/crypto.h>

#include "crypto.h"

LOG_MODULE_REGISTER(crypto_psa, LOG_LEVEL_INF);

#define P256_COORD_LEN  32
#define P256_PRIV_LEN   32
#define P256_PUB_LEN    65
#define P256_SIG_LEN    64

#define BLOB_NONCE_LEN  12
#define BLOB_TAG_LEN    16

#if defined(CONFIG_SOC_FAMILY_NORDIC_NRF)
#define FICR_BASE       0x10000000UL
#define FICR_DEVICEID0  (*(volatile uint32_t *)(FICR_BASE + 0x060))
#define FICR_DEVICEID1  (*(volatile uint32_t *)(FICR_BASE + 0x064))
#else
#define FICR_DEVICEID0  0xDEADBEEFu
#define FICR_DEVICEID1  0xCAFEF00Du
#endif

static int ensure_psa(void)
{
	psa_status_t s = psa_crypto_init();

	if (s != PSA_SUCCESS) {
		LOG_ERR("psa_crypto_init=%d", (int)s);
		return -EIO;
	}
	return 0;
}

int crypto_init(void)
{
	if (ensure_psa()) {
		return -EIO;
	}
	LOG_INF("crypto ready (PSA, P-256 + AES-256-GCM via CC3XX/Oberon)");
	return 0;
}

int crypto_trng(uint8_t *buf, size_t len)
{
	if (ensure_psa()) {
		return -EIO;
	}
	psa_status_t s = psa_generate_random(buf, len);

	return (s == PSA_SUCCESS) ? 0 : -EIO;
}

int crypto_keygen(uint8_t *privkey_out, size_t *privkey_len)
{
	if (*privkey_len < P256_PRIV_LEN) {
		return -EINVAL;
	}
	if (ensure_psa()) {
		return -EIO;
	}

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t kid = PSA_KEY_ID_NULL;
	psa_status_t s;
	int rc = 0;

	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);
	psa_set_key_algorithm(&attr,
			      PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);

	s = psa_generate_key(&attr, &kid);
	if (s != PSA_SUCCESS) {
		LOG_ERR("psa_generate_key=%d", (int)s);
		rc = -EIO;
		goto out;
	}

	size_t out_len = 0;

	s = psa_export_key(kid, privkey_out, P256_PRIV_LEN, &out_len);
	if (s != PSA_SUCCESS || out_len != P256_PRIV_LEN) {
		LOG_ERR("psa_export_key=%d len=%zu", (int)s, out_len);
		rc = -EIO;
		goto out;
	}
	*privkey_len = P256_PRIV_LEN;

out:
	psa_reset_key_attributes(&attr);
	if (kid != PSA_KEY_ID_NULL) {
		psa_destroy_key(kid);
	}
	return rc;
}

/* Load a 32-byte raw P-256 private scalar as a volatile PSA key with the
 * requested usage + algorithm. Caller destroys via psa_destroy_key.
 */
static int import_p256_priv(const uint8_t *priv, size_t priv_len,
			    psa_key_usage_t usage, psa_algorithm_t alg,
			    psa_key_id_t *kid_out)
{
	if (priv_len != P256_PRIV_LEN) {
		return -EINVAL;
	}

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t s;

	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);
	psa_set_key_algorithm(&attr, alg);
	psa_set_key_usage_flags(&attr, usage);

	s = psa_import_key(&attr, priv, priv_len, kid_out);
	psa_reset_key_attributes(&attr);
	return (s == PSA_SUCCESS) ? 0 : -EIO;
}

int crypto_pubkey_from_privkey(const uint8_t *privkey, size_t privkey_len,
			       uint8_t *pubkey_out, size_t *pubkey_len)
{
	if (privkey_len != P256_PRIV_LEN || *pubkey_len < P256_PUB_LEN) {
		return -EINVAL;
	}
	if (ensure_psa()) {
		return -EIO;
	}

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	int rc = import_p256_priv(privkey, privkey_len,
				  PSA_KEY_USAGE_EXPORT,
				  PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256),
				  &kid);
	if (rc) {
		return rc;
	}

	size_t out_len = 0;
	psa_status_t s = psa_export_public_key(kid, pubkey_out,
					       *pubkey_len, &out_len);

	psa_destroy_key(kid);
	if (s != PSA_SUCCESS || out_len != P256_PUB_LEN) {
		LOG_ERR("psa_export_public_key=%d len=%zu", (int)s, out_len);
		return -EIO;
	}
	*pubkey_len = out_len;
	return 0;
}

int crypto_sign(const uint8_t *privkey, size_t privkey_len,
		const uint8_t *digest, size_t digest_len,
		uint8_t *sig_out, size_t *sig_len)
{
	if (privkey_len != P256_PRIV_LEN || *sig_len < P256_SIG_LEN) {
		return -EINVAL;
	}
	if (ensure_psa()) {
		return -EIO;
	}

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	psa_algorithm_t alg = PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256);
	int rc = import_p256_priv(privkey, privkey_len,
				  PSA_KEY_USAGE_SIGN_HASH, alg, &kid);
	if (rc) {
		return rc;
	}

	size_t out_len = 0;
	psa_status_t s = psa_sign_hash(kid, alg, digest, digest_len,
				       sig_out, *sig_len, &out_len);

	psa_destroy_key(kid);
	if (s != PSA_SUCCESS || out_len != P256_SIG_LEN) {
		LOG_ERR("psa_sign_hash=%d len=%zu", (int)s, out_len);
		return -EIO;
	}
	*sig_len = P256_SIG_LEN;
	return 0;
}

int crypto_storage_key_derive(uint8_t key_out[32])
{
	if (ensure_psa()) {
		return -EIO;
	}

	uint8_t uid[8];
	uint32_t d0 = FICR_DEVICEID0;
	uint32_t d1 = FICR_DEVICEID1;

	memcpy(uid,     &d0, 4);
	memcpy(uid + 4, &d1, 4);

	static const uint8_t info[] = "cantil-storage-key";

	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_status_t s;
	int rc = 0;

	s = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
	if (s != PSA_SUCCESS) {
		rc = -EIO;
		goto out;
	}
	/* RFC 5869: when salt is absent, HKDF-Extract uses HashLen zero bytes.
	 * mbedtls_hkdf(salt=NULL,len=0) substitutes this internally; PSA's
	 * empty-bytes SALT input is implementation-defined and Nordic's PSA
	 * does NOT substitute. Pass the 32 zero bytes explicitly so the two
	 * backends derive bit-identical storage keys for the same FICR UID.
	 */
	static const uint8_t zero_salt[32] = {0};

	s = psa_key_derivation_input_bytes(&op,
					   PSA_KEY_DERIVATION_INPUT_SALT,
					   zero_salt, sizeof(zero_salt));
	if (s != PSA_SUCCESS) {
		rc = -EIO;
		goto out;
	}
	s = psa_key_derivation_input_bytes(&op,
					   PSA_KEY_DERIVATION_INPUT_SECRET,
					   uid, sizeof(uid));
	if (s != PSA_SUCCESS) {
		rc = -EIO;
		goto out;
	}
	s = psa_key_derivation_input_bytes(&op,
					   PSA_KEY_DERIVATION_INPUT_INFO,
					   info, sizeof(info) - 1);
	if (s != PSA_SUCCESS) {
		rc = -EIO;
		goto out;
	}
	s = psa_key_derivation_output_bytes(&op, key_out, 32);
	if (s != PSA_SUCCESS) {
		rc = -EIO;
	}

out:
	memset(uid, 0, sizeof(uid));
	psa_key_derivation_abort(&op);
	return rc;
}

/* Import a 32-byte AES key for AEAD with the requested usage. */
static int import_aes256_gcm(const uint8_t key[32], psa_key_usage_t usage,
			     psa_key_id_t *kid_out)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t s;

	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, 256);
	psa_set_key_algorithm(&attr, PSA_ALG_GCM);
	psa_set_key_usage_flags(&attr, usage);

	s = psa_import_key(&attr, key, 32, kid_out);
	psa_reset_key_attributes(&attr);
	return (s == PSA_SUCCESS) ? 0 : -EIO;
}

int crypto_encrypt_blob(const uint8_t storage_key[32],
			const uint8_t *plaintext, size_t pt_len,
			uint8_t *ciphertext, size_t *ct_len)
{
	/* Layout: [12-byte nonce][ciphertext][16-byte GCM tag] */
	if (*ct_len < BLOB_NONCE_LEN + pt_len + BLOB_TAG_LEN) {
		return -EINVAL;
	}
	if (ensure_psa()) {
		return -EIO;
	}

	uint8_t nonce[BLOB_NONCE_LEN];
	psa_status_t s = psa_generate_random(nonce, sizeof(nonce));

	if (s != PSA_SUCCESS) {
		return -EIO;
	}

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	int rc = import_aes256_gcm(storage_key, PSA_KEY_USAGE_ENCRYPT, &kid);

	if (rc) {
		return rc;
	}

	size_t produced = 0;

	s = psa_aead_encrypt(kid, PSA_ALG_GCM,
			     nonce, sizeof(nonce),
			     NULL, 0,
			     plaintext, pt_len,
			     ciphertext + BLOB_NONCE_LEN,
			     *ct_len - BLOB_NONCE_LEN,
			     &produced);
	psa_destroy_key(kid);

	if (s != PSA_SUCCESS || produced != pt_len + BLOB_TAG_LEN) {
		LOG_ERR("psa_aead_encrypt=%d produced=%zu", (int)s, produced);
		return -EIO;
	}

	memcpy(ciphertext, nonce, BLOB_NONCE_LEN);
	*ct_len = BLOB_NONCE_LEN + produced;
	return 0;
}

int crypto_decrypt_blob(const uint8_t storage_key[32],
			const uint8_t *ciphertext, size_t ct_len,
			uint8_t *plaintext, size_t *pt_len)
{
	if (ct_len < BLOB_NONCE_LEN + BLOB_TAG_LEN) {
		return -EINVAL;
	}
	size_t body_len = ct_len - BLOB_NONCE_LEN - BLOB_TAG_LEN;

	if (*pt_len < body_len) {
		return -EINVAL;
	}
	if (ensure_psa()) {
		return -EIO;
	}

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	int rc = import_aes256_gcm(storage_key, PSA_KEY_USAGE_DECRYPT, &kid);

	if (rc) {
		return rc;
	}

	size_t produced = 0;
	psa_status_t s = psa_aead_decrypt(kid, PSA_ALG_GCM,
					  ciphertext, BLOB_NONCE_LEN,
					  NULL, 0,
					  ciphertext + BLOB_NONCE_LEN,
					  ct_len - BLOB_NONCE_LEN,
					  plaintext, *pt_len, &produced);

	psa_destroy_key(kid);

	if (s == PSA_ERROR_INVALID_SIGNATURE) {
		return -EBADMSG;
	}
	if (s != PSA_SUCCESS || produced != body_len) {
		LOG_ERR("psa_aead_decrypt=%d produced=%zu", (int)s, produced);
		return -EIO;
	}
	*pt_len = body_len;
	return 0;
}
