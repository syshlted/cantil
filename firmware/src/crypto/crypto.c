/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/entropy.h>
#include <string.h>
#include <errno.h>

#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <mbedtls/bignum.h>
#include <mbedtls/platform_util.h>

#include "crypto.h"

LOG_MODULE_REGISTER(crypto, LOG_LEVEL_INF);

/*
 * Direct Zephyr entropy → CC310 hardware TRNG.  Used for keygen, nonces,
 * and as the RNG callback for mbedtls.  We bypass mbedtls's CTR_DRBG layer
 * because the hardware TRNG already meets our entropy requirements and the
 * extra DRBG state is wasted RAM.
 */
static int trng_bytes(uint8_t *buf, size_t len)
{
	static const struct device *rng;

	if (!rng) {
		rng = DEVICE_DT_GET(DT_CHOSEN(zephyr_entropy));
	}
	if (!device_is_ready(rng)) {
		LOG_ERR("entropy device not ready");
		return -EIO;
	}
	return entropy_get_entropy(rng, buf, len);
}

/* mbedtls f_rng callback signature: returns 0 on success. */
static int mbedtls_rng_cb(void *ctx, unsigned char *buf, size_t len)
{
	ARG_UNUSED(ctx);
	/* mbedtls treats any non-zero return as RNG failure.  We don't pull in
	 * MBEDTLS_ENTROPY_C, so MBEDTLS_ERR_ENTROPY_SOURCE_FAILED isn't visible. */
	return trng_bytes(buf, len) ? -1 : 0;
}

/*
 * FICR registers — device unique ID.
 * On non-nRF builds (e.g. native_sim ztests) FICR is not memory-mapped, so we
 * fall back to a fixed test UID. The IKM is opaque to anything outside this
 * file; correctness only requires that the same UID be returned on each call,
 * which is true for both real FICR and the host fallback.
 */
#if defined(CONFIG_SOC_FAMILY_NORDIC_NRF)
#define FICR_BASE       0x10000000UL
#define FICR_DEVICEID0  (*(volatile uint32_t *)(FICR_BASE + 0x060))
#define FICR_DEVICEID1  (*(volatile uint32_t *)(FICR_BASE + 0x064))
#else
#define FICR_DEVICEID0  0xDEADBEEFu
#define FICR_DEVICEID1  0xCAFEF00Du
#endif

#define P256_COORD_LEN  32
#define P256_PRIV_LEN   32
#define P256_PUB_LEN    65   /* 0x04 || X(32) || Y(32) uncompressed SEC1 */
#define P256_SIG_LEN    64   /* r(32) || s(32) raw, matches PSA P1363 */

int crypto_init(void)
{
	LOG_INF("crypto ready (mbedtls direct, P-256 + AES-256-GCM)");
	return 0;
}

int crypto_trng(uint8_t *buf, size_t len)
{
	return trng_bytes(buf, len);
}

int crypto_keygen(uint8_t *privkey_out, size_t *privkey_len)
{
	if (*privkey_len < P256_PRIV_LEN) {
		return -EINVAL;
	}

	mbedtls_ecp_keypair kp;

	mbedtls_ecp_keypair_init(&kp);

	int rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &kp,
				     mbedtls_rng_cb, NULL);
	if (rc) {
		LOG_ERR("ecp_gen_key=%d", rc);
		mbedtls_ecp_keypair_free(&kp);
		return -EIO;
	}

	rc = mbedtls_mpi_write_binary(&kp.MBEDTLS_PRIVATE(d),
				      privkey_out, P256_PRIV_LEN);
	mbedtls_ecp_keypair_free(&kp);
	if (rc) {
		return -EIO;
	}
	*privkey_len = P256_PRIV_LEN;
	return 0;
}

int crypto_pubkey_from_privkey(const uint8_t *privkey, size_t privkey_len,
			       uint8_t *pubkey_out, size_t *pubkey_len)
{
	if (privkey_len != P256_PRIV_LEN || *pubkey_len < P256_PUB_LEN) {
		return -EINVAL;
	}

	mbedtls_ecp_keypair kp;

	mbedtls_ecp_keypair_init(&kp);

	int rc = mbedtls_ecp_group_load(&kp.MBEDTLS_PRIVATE(grp),
					MBEDTLS_ECP_DP_SECP256R1);
	if (rc) {
		goto out;
	}

	rc = mbedtls_mpi_read_binary(&kp.MBEDTLS_PRIVATE(d),
				     privkey, privkey_len);
	if (rc) {
		goto out;
	}

	/* Q = d * G */
	rc = mbedtls_ecp_mul(&kp.MBEDTLS_PRIVATE(grp),
			     &kp.MBEDTLS_PRIVATE(Q),
			     &kp.MBEDTLS_PRIVATE(d),
			     &kp.MBEDTLS_PRIVATE(grp).G,
			     mbedtls_rng_cb, NULL);
	if (rc) {
		goto out;
	}

	size_t olen = 0;

	rc = mbedtls_ecp_point_write_binary(&kp.MBEDTLS_PRIVATE(grp),
					    &kp.MBEDTLS_PRIVATE(Q),
					    MBEDTLS_ECP_PF_UNCOMPRESSED,
					    &olen,
					    pubkey_out, *pubkey_len);
	if (rc) {
		goto out;
	}
	*pubkey_len = olen;

out:
	mbedtls_ecp_keypair_free(&kp);
	return rc ? -EIO : 0;
}

int crypto_sign(const uint8_t *privkey, size_t privkey_len,
		const uint8_t *digest, size_t digest_len,
		uint8_t *sig_out, size_t *sig_len)
{
	if (privkey_len != P256_PRIV_LEN || *sig_len < P256_SIG_LEN) {
		return -EINVAL;
	}

	mbedtls_ecp_group grp;
	mbedtls_mpi d, r, s;

	mbedtls_ecp_group_init(&grp);
	mbedtls_mpi_init(&d);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	int rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

	if (rc) {
		goto out;
	}
	rc = mbedtls_mpi_read_binary(&d, privkey, privkey_len);
	if (rc) {
		goto out;
	}

	/*
	 * Deterministic ECDSA per RFC 6979 — eliminates nonce-reuse risk.
	 * Same wire format as randomized ECDSA; verifiers don't care.
	 */
	rc = mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d,
					digest, digest_len,
					MBEDTLS_MD_SHA256,
					mbedtls_rng_cb, NULL);
	if (rc) {
		LOG_ERR("ecdsa_sign_det_ext=%d", rc);
		goto out;
	}

	/* PSA P1363 / raw r||s format: 32-byte big-endian r, then 32-byte s. */
	rc = mbedtls_mpi_write_binary(&r, sig_out, P256_COORD_LEN);
	if (rc) {
		goto out;
	}
	rc = mbedtls_mpi_write_binary(&s, sig_out + P256_COORD_LEN, P256_COORD_LEN);
	if (rc) {
		goto out;
	}
	*sig_len = P256_SIG_LEN;

out:
	mbedtls_mpi_free(&s);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&d);
	mbedtls_ecp_group_free(&grp);
	return rc ? -EIO : 0;
}

int crypto_storage_key_derive(uint8_t key_out[32])
{
	/* Derive a 256-bit storage key from the 64-bit FICR device UID via HKDF-SHA256 */
	uint8_t uid[8];
	uint32_t d0 = FICR_DEVICEID0;
	uint32_t d1 = FICR_DEVICEID1;

	memcpy(uid,     &d0, 4);
	memcpy(uid + 4, &d1, 4);

	static const uint8_t info[] = "cantil-storage-key";
	const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

	int rc = mbedtls_hkdf(md,
			      NULL, 0,                  /* salt (empty) */
			      uid, sizeof(uid),         /* ikm */
			      info, sizeof(info) - 1,   /* info */
			      key_out, 32);

	mbedtls_platform_zeroize(uid, sizeof(uid));
	return rc ? -EIO : 0;
}

int crypto_encrypt_blob(const uint8_t storage_key[32],
			const uint8_t *plaintext, size_t pt_len,
			uint8_t *ciphertext, size_t *ct_len)
{
	/* Layout: [12-byte nonce][ciphertext][16-byte GCM tag] */
	if (*ct_len < 12 + pt_len + 16) {
		return -EINVAL;
	}

	uint8_t nonce[12];

	if (trng_bytes(nonce, sizeof(nonce))) {
		return -EIO;
	}

	mbedtls_gcm_context gcm;

	mbedtls_gcm_init(&gcm);

	int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
				    storage_key, 256);
	if (rc) {
		goto out;
	}

	rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
				       pt_len,
				       nonce, sizeof(nonce),
				       NULL, 0,
				       plaintext, ciphertext + 12,
				       16, ciphertext + 12 + pt_len);
	if (rc) {
		goto out;
	}

	memcpy(ciphertext, nonce, 12);
	*ct_len = 12 + pt_len + 16;

out:
	mbedtls_gcm_free(&gcm);
	return rc ? -EIO : 0;
}

int crypto_decrypt_blob(const uint8_t storage_key[32],
			const uint8_t *ciphertext, size_t ct_len,
			uint8_t *plaintext, size_t *pt_len)
{
	if (ct_len < 12 + 16) {
		return -EINVAL;
	}

	size_t body_len = ct_len - 12 - 16;

	if (*pt_len < body_len) {
		return -EINVAL;
	}

	mbedtls_gcm_context gcm;

	mbedtls_gcm_init(&gcm);

	int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
				    storage_key, 256);
	if (rc) {
		goto out;
	}

	rc = mbedtls_gcm_auth_decrypt(&gcm,
				      body_len,
				      ciphertext, 12,
				      NULL, 0,
				      ciphertext + 12 + body_len, 16,
				      ciphertext + 12, plaintext);
	if (rc == MBEDTLS_ERR_GCM_AUTH_FAILED) {
		mbedtls_gcm_free(&gcm);
		return -EBADMSG;
	}
	if (rc == 0) {
		*pt_len = body_len;
	}

out:
	mbedtls_gcm_free(&gcm);
	return rc ? -EIO : 0;
}
