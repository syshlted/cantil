/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

/*
 * Noise crypto primitives — PSA backend.
 *
 * Counterpart to noise_crypto_mbedtls.c. Selected when
 * CANTIL_CRYPTO_BACKEND_ACCELERATED=y; under NCS this dispatches X25519 +
 * ChaCha20-Poly1305 to Oberon (ARM software, hardware-tuned) and SHA-256 +
 * HMAC to CC3XX. The Noise_XX state machine in session.c sees only the
 * noise_crypto.h API; it does not know which backend is linked in.
 *
 * Wire formats kept bit-identical to the mbedtls backend:
 *   - X25519 scalar / pubkey: 32-byte little-endian (RFC 7748).
 *   - X25519 scalars are clamped on input to match noise_crypto_mbedtls.c,
 *     so a stored keypair from the FREE backend can be re-loaded under the
 *     ACCELERATED backend without re-derivation.
 *   - ChaCha20-Poly1305 nonce: 4 zero bytes || 8-byte little-endian counter.
 *   - AEAD ciphertext layout: ct || 16-byte tag (matches mbedtls + PSA).
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <string.h>
#include <errno.h>

#include <psa/crypto.h>

#include "noise_crypto.h"

LOG_MODULE_REGISTER(noise_psa, LOG_LEVEL_INF);

/* psa_crypto_init() is idempotent per the PSA spec; call it lazily so the
 * Noise backend works regardless of where else PSA gets initialised.
 */
static int ensure_psa(void)
{
	psa_status_t s = psa_crypto_init();

	if (s != PSA_SUCCESS) {
		LOG_ERR("psa_crypto_init=%d", (int)s);
		return -EIO;
	}
	return 0;
}

/* Noise nonce: 4 zero bytes || 8-byte little-endian counter. */
static void nonce_encode(uint8_t out[12], uint64_t n)
{
	memset(out, 0, 4);
	for (int i = 0; i < 8; i++) {
		out[4 + i] = (uint8_t)(n >> (8 * i));
	}
}

static void clamp_x25519(uint8_t s[32])
{
	s[0]  &= 248;
	s[31] &= 127;
	s[31] |= 64;
}

int noise_crypto_dh_keygen(uint8_t priv_out[32], uint8_t pub_out[32])
{
	if (ensure_psa()) {
		return -EIO;
	}

	/* Nordic's PSA / Oberon does not implement psa_generate_key for
	 * MONTGOMERY 255 (PSA_ERROR_NOT_SUPPORTED). RFC 7748 §5 says any
	 * 32 random bytes, clamped, form a valid X25519 scalar, so we
	 * generate via TRNG, clamp, and import.
	 */
	psa_status_t s = psa_generate_random(priv_out, 32);

	if (s != PSA_SUCCESS) {
		LOG_ERR("psa_generate_random=%d", (int)s);
		return -EIO;
	}
	clamp_x25519(priv_out);

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t kid = PSA_KEY_ID_NULL;
	int rc = 0;

	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
	psa_set_key_bits(&attr, 255);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);

	s = psa_import_key(&attr, priv_out, 32, &kid);
	if (s != PSA_SUCCESS) {
		LOG_ERR("psa_import_key(MONT priv)=%d", (int)s);
		rc = -EIO;
		goto out;
	}

	size_t pub_len = 0;

	s = psa_export_public_key(kid, pub_out, 32, &pub_len);
	if (s != PSA_SUCCESS || pub_len != 32) {
		LOG_ERR("psa_export_public_key=%d len=%zu", (int)s, pub_len);
		rc = -EIO;
		goto out;
	}

out:
	psa_reset_key_attributes(&attr);
	if (kid != PSA_KEY_ID_NULL) {
		psa_destroy_key(kid);
	}
	return rc;
}

int noise_crypto_dh(uint8_t shared_out[32],
		    const uint8_t priv[32], const uint8_t pub[32])
{
	if (ensure_psa()) {
		return -EIO;
	}

	uint8_t priv_clamped[32];

	memcpy(priv_clamped, priv, 32);
	clamp_x25519(priv_clamped);

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t kid = PSA_KEY_ID_NULL;
	psa_status_t s;
	int rc = 0;

	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
	psa_set_key_bits(&attr, 255);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);

	s = psa_import_key(&attr, priv_clamped, 32, &kid);
	if (s != PSA_SUCCESS) {
		LOG_ERR("psa_import_key=%d", (int)s);
		rc = -EIO;
		goto out;
	}

	size_t shared_len = 0;

	s = psa_raw_key_agreement(PSA_ALG_ECDH, kid, pub, 32,
				  shared_out, 32, &shared_len);
	if (s != PSA_SUCCESS || shared_len != 32) {
		LOG_ERR("psa_raw_key_agreement=%d len=%zu",
			(int)s, shared_len);
		rc = -EIO;
		goto out;
	}

out:
	memset(priv_clamped, 0, sizeof(priv_clamped));
	psa_reset_key_attributes(&attr);
	if (kid != PSA_KEY_ID_NULL) {
		psa_destroy_key(kid);
	}
	return rc;
}

/* Shared body for ChaCha20-Poly1305 AEAD encrypt/decrypt.
 * encrypt=true → psa_aead_encrypt; encrypt=false → psa_aead_decrypt.
 * On decrypt, in/out semantics flip: input is ct||tag (in_len includes tag),
 * output is plaintext (out_len_out excludes tag).
 */
static int aead_run(bool encrypt,
		    uint8_t *out, size_t out_buf_len, size_t *out_len_out,
		    const uint8_t key[32], uint64_t nonce,
		    const uint8_t *ad, size_t ad_len,
		    const uint8_t *in, size_t in_len)
{
	if (ensure_psa()) {
		return -EIO;
	}

	uint8_t nonce_buf[12];

	nonce_encode(nonce_buf, nonce);

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t kid = PSA_KEY_ID_NULL;
	psa_status_t s;
	int rc = 0;
	size_t produced = 0;

	psa_set_key_type(&attr, PSA_KEY_TYPE_CHACHA20);
	psa_set_key_bits(&attr, 256);
	psa_set_key_algorithm(&attr, PSA_ALG_CHACHA20_POLY1305);
	psa_set_key_usage_flags(&attr,
				encrypt ? PSA_KEY_USAGE_ENCRYPT
					: PSA_KEY_USAGE_DECRYPT);

	s = psa_import_key(&attr, key, 32, &kid);
	if (s != PSA_SUCCESS) {
		LOG_ERR("aead import=%d", (int)s);
		rc = -EIO;
		goto out;
	}

	if (encrypt) {
		s = psa_aead_encrypt(kid, PSA_ALG_CHACHA20_POLY1305,
				     nonce_buf, sizeof(nonce_buf),
				     ad, ad_len,
				     in, in_len,
				     out, out_buf_len, &produced);
	} else {
		s = psa_aead_decrypt(kid, PSA_ALG_CHACHA20_POLY1305,
				     nonce_buf, sizeof(nonce_buf),
				     ad, ad_len,
				     in, in_len,
				     out, out_buf_len, &produced);
	}
	if (s == PSA_ERROR_INVALID_SIGNATURE) {
		rc = -EBADMSG;
		goto out;
	}
	if (s != PSA_SUCCESS) {
		LOG_ERR("aead %s=%d", encrypt ? "encrypt" : "decrypt", (int)s);
		rc = -EIO;
		goto out;
	}

	*out_len_out = produced;

out:
	psa_reset_key_attributes(&attr);
	if (kid != PSA_KEY_ID_NULL) {
		psa_destroy_key(kid);
	}
	return rc;
}

int noise_crypto_encrypt(uint8_t *ct_out, size_t ct_buf_len, size_t *ct_len_out,
			 const uint8_t key[32], uint64_t nonce,
			 const uint8_t *ad, size_t ad_len,
			 const uint8_t *pt, size_t pt_len)
{
	if (ct_buf_len < pt_len + 16) {
		return -EINVAL;
	}
	return aead_run(true, ct_out, ct_buf_len, ct_len_out,
			key, nonce, ad, ad_len, pt, pt_len);
}

int noise_crypto_decrypt(uint8_t *pt_out, size_t pt_buf_len, size_t *pt_len_out,
			 const uint8_t key[32], uint64_t nonce,
			 const uint8_t *ad, size_t ad_len,
			 const uint8_t *ct, size_t ct_len)
{
	if (ct_len < 16) {
		return -EINVAL;
	}
	if (pt_buf_len < ct_len - 16) {
		return -EINVAL;
	}
	return aead_run(false, pt_out, pt_buf_len, pt_len_out,
			key, nonce, ad, ad_len, ct, ct_len);
}

int noise_crypto_hash(uint8_t out[32],
		      const uint8_t *a, size_t a_len,
		      const uint8_t *b, size_t b_len)
{
	if (ensure_psa()) {
		return -EIO;
	}

	psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
	psa_status_t s;
	int rc = 0;
	size_t produced = 0;

	s = psa_hash_setup(&op, PSA_ALG_SHA_256);
	if (s != PSA_SUCCESS) {
		rc = -EIO;
		goto out;
	}
	if (a_len) {
		s = psa_hash_update(&op, a, a_len);
		if (s != PSA_SUCCESS) {
			rc = -EIO;
			goto out;
		}
	}
	if (b_len) {
		s = psa_hash_update(&op, b, b_len);
		if (s != PSA_SUCCESS) {
			rc = -EIO;
			goto out;
		}
	}
	s = psa_hash_finish(&op, out, 32, &produced);
	if (s != PSA_SUCCESS || produced != 32) {
		rc = -EIO;
		goto out;
	}

out:
	if (rc) {
		psa_hash_abort(&op);
	}
	return rc;
}

int noise_crypto_hkdf2(uint8_t out1[32], uint8_t out2[32],
		       const uint8_t ck[32],
		       const uint8_t *ikm, size_t ikm_len)
{
	if (ensure_psa()) {
		return -EIO;
	}

	/* HKDF(salt=ck, ikm, info="", L=64) split into two 32-byte halves.
	 * Same proof as noise_crypto_mbedtls.c.
	 */
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_status_t s;
	int rc = 0;
	uint8_t okm[64];

	s = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
	if (s != PSA_SUCCESS) {
		rc = -EIO;
		goto out;
	}
	s = psa_key_derivation_input_bytes(&op,
					   PSA_KEY_DERIVATION_INPUT_SALT,
					   ck, 32);
	if (s != PSA_SUCCESS) {
		rc = -EIO;
		goto out;
	}
	s = psa_key_derivation_input_bytes(&op,
					   PSA_KEY_DERIVATION_INPUT_SECRET,
					   ikm, ikm_len);
	if (s != PSA_SUCCESS) {
		rc = -EIO;
		goto out;
	}
	s = psa_key_derivation_input_bytes(&op,
					   PSA_KEY_DERIVATION_INPUT_INFO,
					   NULL, 0);
	if (s != PSA_SUCCESS) {
		rc = -EIO;
		goto out;
	}
	s = psa_key_derivation_output_bytes(&op, okm, sizeof(okm));
	if (s != PSA_SUCCESS) {
		rc = -EIO;
		goto out;
	}

	memcpy(out1, okm, 32);
	memcpy(out2, okm + 32, 32);

out:
	memset(okm, 0, sizeof(okm));
	psa_key_derivation_abort(&op);
	return rc;
}
