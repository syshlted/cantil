/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

/*
 * crypto.h implemented against wolfCrypt.
 *
 * Sibling of crypto.c (mbedTLS) and crypto_psa.c (Oberon/CC3XX); exactly one is
 * linked, selected by the CANTIL_CRYPTO_BACKEND choice.
 *
 * One output here is not merely an interoperability concern but a
 * data-availability one: crypto_storage_key_derive() must produce the same 32
 * bytes on every backend. The CA private key is stored AES-256-GCM encrypted
 * under that key and cannot be exported or re-wrapped, so a backend that
 * derived it differently would turn a firmware update into unrecoverable key
 * loss — the device would boot, mount its volume, and fail to authenticate its
 * own key blob. Both backends therefore use plain RFC 5869 HKDF-SHA256 with an
 * empty salt over the same FICR UID and the same info string.
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <string.h>
#include <errno.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "crypto.h"
#include "crypto/wc_rand.h"
#include "crypto/zeroize.h"

LOG_MODULE_REGISTER(crypto_wolfssl, LOG_LEVEL_INF);

#define P256_COORD_LEN 32
#define P256_PRIV_LEN  32
#define P256_PUB_LEN   65 /* 0x04 || X(32) || Y(32) uncompressed SEC1 */
#define P256_SIG_LEN   64 /* r(32) || s(32) raw, matches PSA P1363 */

/*
 * wolfCrypt still wants a WC_RNG handle even though CUSTOM_RAND_GENERATE_BLOCK
 * means every byte comes straight from the hardware TRNG: ECC blinding and
 * curve25519 blinding take one as an argument. wc_InitRng() is cheap under that
 * setting — there is no DRBG state to seed — so it is done per call rather than
 * kept as global mutable state.
 */
static int rng_open(WC_RNG *rng)
{
	int rc = wc_InitRng(rng);

	if (rc != 0) {
		LOG_ERR("wc_InitRng=%d", rc);
		return -EIO;
	}
	return 0;
}

int crypto_init(void)
{
	LOG_INF("crypto ready (wolfCrypt, P-256 + AES-256-GCM)");
	return 0;
}

int crypto_trng(uint8_t *buf, size_t len)
{
	return cantil_wc_trng(buf, len);
}

int crypto_keygen(uint8_t *privkey_out, size_t *privkey_len)
{
	if (*privkey_len < P256_PRIV_LEN) {
		return -EINVAL;
	}

	WC_RNG rng;
	ecc_key key;
	int rc = rng_open(&rng);

	if (rc) {
		return rc;
	}

	rc = wc_ecc_init(&key);
	if (rc != 0) {
		wc_FreeRng(&rng);
		return -EIO;
	}

	rc = wc_ecc_make_key_ex(&rng, P256_PRIV_LEN, &key, ECC_SECP256R1);
	if (rc != 0) {
		LOG_ERR("ecc_make_key=%d", rc);
		goto out;
	}

	word32 olen = P256_PRIV_LEN;

	rc = wc_ecc_export_private_only(&key, privkey_out, &olen);
	if (rc == 0) {
		*privkey_len = olen;
	}

out:
	wc_ecc_free(&key);
	wc_FreeRng(&rng);
	return rc ? -EIO : 0;
}

int crypto_pubkey_from_privkey(const uint8_t *privkey, size_t privkey_len, uint8_t *pubkey_out,
			       size_t *pubkey_len)
{
	if (privkey_len != P256_PRIV_LEN || *pubkey_len < P256_PUB_LEN) {
		return -EINVAL;
	}

	WC_RNG rng;
	ecc_key key;
	int rc = rng_open(&rng);

	if (rc) {
		return rc;
	}

	rc = wc_ecc_init(&key);
	if (rc != 0) {
		wc_FreeRng(&rng);
		return -EIO;
	}

	/* NULL public part: import the scalar alone, then derive Q = d*G. */
	rc = wc_ecc_import_private_key_ex(privkey, (word32)privkey_len, NULL, 0, &key,
					  ECC_SECP256R1);
	if (rc != 0) {
		goto out;
	}

	rc = wc_ecc_set_rng(&key, &rng);
	if (rc != 0) {
		goto out;
	}

	/* pubOut NULL stores the result in key->pubkey. */
	rc = wc_ecc_make_pub(&key, NULL);
	if (rc != 0) {
		LOG_ERR("ecc_make_pub=%d", rc);
		goto out;
	}

	word32 olen = (word32)*pubkey_len;

	rc = wc_ecc_export_x963(&key, pubkey_out, &olen);
	if (rc == 0) {
		*pubkey_len = olen;
	}

out:
	wc_ecc_free(&key);
	wc_FreeRng(&rng);
	return rc ? -EIO : 0;
}

int crypto_sign(const uint8_t *privkey, size_t privkey_len, const uint8_t *digest,
		size_t digest_len, uint8_t *sig_out, size_t *sig_len)
{
	if (privkey_len != P256_PRIV_LEN || *sig_len < P256_SIG_LEN) {
		return -EINVAL;
	}

	WC_RNG rng;
	ecc_key key;
	mp_int r, s;
	int rc = rng_open(&rng);

	if (rc) {
		return rc;
	}

	rc = wc_ecc_init(&key);
	if (rc != 0) {
		wc_FreeRng(&rng);
		return -EIO;
	}

	if (mp_init(&r) != MP_OKAY) {
		rc = -1;
		goto out_key;
	}
	if (mp_init(&s) != MP_OKAY) {
		rc = -1;
		goto out_r;
	}

	rc = wc_ecc_import_private_key_ex(privkey, (word32)privkey_len, NULL, 0, &key,
					  ECC_SECP256R1);
	if (rc != 0) {
		goto out_s;
	}

	rc = wc_ecc_set_rng(&key, &rng);
	if (rc != 0) {
		goto out_s;
	}

	/*
	 * Deterministic ECDSA per RFC 6979, same as the mbedTLS backend's
	 * mbedtls_ecdsa_sign_det_ext. The hash type is stated explicitly rather
	 * than inferred from the digest length, so a future caller signing a
	 * SHA-384 digest cannot silently change how k is derived.
	 */
	rc = wc_ecc_set_deterministic_ex(&key, 1, WC_HASH_TYPE_SHA256);
	if (rc != 0) {
		goto out_s;
	}

	rc = wc_ecc_sign_hash_ex(digest, (word32)digest_len, &rng, &key, &r, &s);
	if (rc != 0) {
		LOG_ERR("ecc_sign_hash_ex=%d", rc);
		goto out_s;
	}

	/* PSA P1363 / raw r||s: 32-byte big-endian r, then 32-byte s. */
	rc = mp_to_unsigned_bin_len(&r, sig_out, P256_COORD_LEN);
	if (rc != MP_OKAY) {
		goto out_s;
	}
	rc = mp_to_unsigned_bin_len(&s, sig_out + P256_COORD_LEN, P256_COORD_LEN);
	if (rc != MP_OKAY) {
		goto out_s;
	}
	*sig_len = P256_SIG_LEN;
	rc = 0;

out_s:
	mp_free(&s);
out_r:
	mp_free(&r);
out_key:
	wc_ecc_free(&key);
	wc_FreeRng(&rng);
	return rc ? -EIO : 0;
}

int crypto_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
	if ((!data && len) || !out) {
		return -EINVAL;
	}
	return wc_Sha256Hash(data, (word32)len, out) ? -EIO : 0;
}

int crypto_hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len,
		       const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len)
{
	if (!ikm || !ikm_len || !out || !out_len) {
		return -EINVAL;
	}

	/* wolfCrypt takes IKM before salt, which is the order this seam uses;
	 * mbedTLS is the other way round. */
	int rc = wc_HKDF(WC_SHA256, ikm, (word32)ikm_len, /* IKM  */
			 salt, (word32)salt_len,          /* salt */
			 info, (word32)info_len,          /* info */
			 out, (word32)out_len);

	return rc ? -EIO : 0;
}

int crypto_storage_key_derive(uint8_t key_out[32])
{
	uint8_t uid[8];

	crypto_device_id(uid);

	static const uint8_t info[] = "cantil-storage-key";

	/*
	 * Empty salt. RFC 5869 substitutes a hash-length block of zeros, and
	 * both libraries implement that, so the derived key is identical to the
	 * mbedTLS backend's. Do not "improve" the salt here without a migration
	 * path — see the note at the top of this file.
	 */
	int rc = crypto_hkdf_sha256(uid, sizeof(uid), NULL, 0, /* salt */
				    info, sizeof(info) - 1, key_out, 32);

	cantil_zeroize(uid, sizeof(uid));
	return rc;
}

int crypto_encrypt_blob(const uint8_t storage_key[32], const uint8_t *plaintext, size_t pt_len,
			uint8_t *ciphertext, size_t *ct_len)
{
	/* Layout: [12-byte nonce][ciphertext][16-byte GCM tag] */
	if (*ct_len < 12 + pt_len + 16) {
		return -EINVAL;
	}

	uint8_t nonce[12];

	if (cantil_wc_trng(nonce, sizeof(nonce))) {
		return -EIO;
	}

	Aes aes;
	int rc = wc_AesInit(&aes, NULL, INVALID_DEVID);

	if (rc != 0) {
		return -EIO;
	}

	rc = wc_AesGcmSetKey(&aes, storage_key, 32);
	if (rc != 0) {
		goto out;
	}

	rc = wc_AesGcmEncrypt(&aes, ciphertext + 12,                              /* out  */
			      plaintext, (word32)pt_len,                          /* in   */
			      nonce, sizeof(nonce), ciphertext + 12 + pt_len, 16, /* tag */
			      NULL, 0);                                           /* no AAD */
	if (rc != 0) {
		goto out;
	}

	memcpy(ciphertext, nonce, 12);
	*ct_len = 12 + pt_len + 16;

out:
	wc_AesFree(&aes);
	return rc ? -EIO : 0;
}

int crypto_decrypt_blob(const uint8_t storage_key[32], const uint8_t *ciphertext, size_t ct_len,
			uint8_t *plaintext, size_t *pt_len)
{
	if (ct_len < 12 + 16) {
		return -EINVAL;
	}

	size_t body_len = ct_len - 12 - 16;

	if (*pt_len < body_len) {
		return -EINVAL;
	}

	Aes aes;
	int rc = wc_AesInit(&aes, NULL, INVALID_DEVID);

	if (rc != 0) {
		return -EIO;
	}

	rc = wc_AesGcmSetKey(&aes, storage_key, 32);
	if (rc != 0) {
		goto out;
	}

	rc = wc_AesGcmDecrypt(&aes, plaintext,                                   /* out */
			      ciphertext + 12, (word32)body_len, ciphertext, 12, /* nonce */
			      ciphertext + 12 + body_len, 16,                    /* tag */
			      NULL, 0);
	if (rc == AES_GCM_AUTH_E) {
		wc_AesFree(&aes);
		return -EBADMSG;
	}
	if (rc == 0) {
		*pt_len = body_len;
	}

out:
	wc_AesFree(&aes);
	return rc ? -EIO : 0;
}
