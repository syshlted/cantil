/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/entropy.h>
#include <string.h>
#include <errno.h>

#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/chachapoly.h>
#include <mbedtls/sha256.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>

#include "noise_crypto.h"

LOG_MODULE_REGISTER(noise_mbedtls, LOG_LEVEL_INF);

static int trng_bytes(uint8_t *buf, size_t len)
{
	static const struct device *rng;

	if (!rng) {
		rng = DEVICE_DT_GET(DT_CHOSEN(zephyr_entropy));
	}
	if (!device_is_ready(rng)) {
		return -EIO;
	}
	return entropy_get_entropy(rng, buf, len);
}

static int mbedtls_rng_cb(void *ctx, unsigned char *buf, size_t len)
{
	ARG_UNUSED(ctx);
	return trng_bytes(buf, len) ? -1 : 0;
}

/* Noise nonce: 4 zero bytes || 8-byte little-endian counter. */
static void nonce_encode(uint8_t out[12], uint64_t n)
{
	memset(out, 0, 4);
	for (int i = 0; i < 8; i++) {
		out[4 + i] = (uint8_t)(n >> (8 * i));
	}
}

int noise_crypto_dh_keygen(uint8_t priv_out[32], uint8_t pub_out[32])
{
	int ret = trng_bytes(priv_out, 32);

	if (ret) {
		return -EIO;
	}

	/* RFC 7748 X25519 scalar clamping */
	priv_out[0]  &= 248;
	priv_out[31] &= 127;
	priv_out[31] |= 64;

	mbedtls_ecp_group grp;
	mbedtls_mpi d;
	mbedtls_ecp_point Q;

	mbedtls_ecp_group_init(&grp);
	mbedtls_mpi_init(&d);
	mbedtls_ecp_point_init(&Q);

	int rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);

	if (rc) {
		goto out;
	}
	/* Curve25519 scalars are little-endian per RFC 7748. */
	rc = mbedtls_mpi_read_binary_le(&d, priv_out, 32);
	if (rc) {
		goto out;
	}

	rc = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G,
			     mbedtls_rng_cb, NULL);
	if (rc) {
		LOG_ERR("ecp_mul keygen=%d", rc);
		goto out;
	}

	rc = mbedtls_mpi_write_binary_le(&Q.MBEDTLS_PRIVATE(X), pub_out, 32);

out:
	mbedtls_ecp_point_free(&Q);
	mbedtls_mpi_free(&d);
	mbedtls_ecp_group_free(&grp);
	return rc ? -EIO : 0;
}

int noise_crypto_dh(uint8_t shared_out[32],
		    const uint8_t priv[32], const uint8_t pub[32])
{
	mbedtls_ecp_group grp;
	mbedtls_mpi d;
	mbedtls_ecp_point peer, result;

	mbedtls_ecp_group_init(&grp);
	mbedtls_mpi_init(&d);
	mbedtls_ecp_point_init(&peer);
	mbedtls_ecp_point_init(&result);

	int rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);

	if (rc) {
		goto out;
	}
	/* X25519 clamps the scalar per RFC 7748 §5.  mbedtls' Curve25519 ECP
	 * check_privkey rejects unclamped scalars, so we clamp on input —
	 * makes noise_crypto_dh a true X25519 (idempotent for clamped keys).
	 */
	uint8_t priv_clamped[32];

	memcpy(priv_clamped, priv, 32);
	priv_clamped[0]  &= 248;
	priv_clamped[31] &= 127;
	priv_clamped[31] |= 64;

	rc = mbedtls_mpi_read_binary_le(&d, priv_clamped, 32);
	mbedtls_platform_zeroize(priv_clamped, sizeof(priv_clamped));
	if (rc) {
		goto out;
	}
	rc = mbedtls_mpi_read_binary_le(&peer.MBEDTLS_PRIVATE(X), pub, 32);
	if (rc) {
		goto out;
	}
	/* Affine form: Z = 1 (Y is unused for Montgomery curves). */
	rc = mbedtls_mpi_lset(&peer.MBEDTLS_PRIVATE(Z), 1);
	if (rc) {
		goto out;
	}

	rc = mbedtls_ecp_mul(&grp, &result, &d, &peer,
			     mbedtls_rng_cb, NULL);
	if (rc) {
		LOG_ERR("ecp_mul dh=%d", rc);
		goto out;
	}

	rc = mbedtls_mpi_write_binary_le(&result.MBEDTLS_PRIVATE(X),
					 shared_out, 32);

out:
	mbedtls_ecp_point_free(&result);
	mbedtls_ecp_point_free(&peer);
	mbedtls_mpi_free(&d);
	mbedtls_ecp_group_free(&grp);
	return rc ? -EIO : 0;
}

int noise_crypto_encrypt(uint8_t *ct_out, size_t ct_buf_len, size_t *ct_len_out,
			 const uint8_t key[32], uint64_t nonce,
			 const uint8_t *ad, size_t ad_len,
			 const uint8_t *pt, size_t pt_len)
{
	if (ct_buf_len < pt_len + 16) {
		return -EINVAL;
	}

	uint8_t nonce_buf[12];

	nonce_encode(nonce_buf, nonce);

	mbedtls_chachapoly_context ctx;

	mbedtls_chachapoly_init(&ctx);

	int rc = mbedtls_chachapoly_setkey(&ctx, key);

	if (rc) {
		goto out;
	}

	/* mbedtls emits ciphertext into ct_out and the 16-byte tag separately. */
	rc = mbedtls_chachapoly_encrypt_and_tag(&ctx, pt_len,
						nonce_buf, ad, ad_len,
						pt, ct_out,
						ct_out + pt_len);
	if (rc == 0) {
		*ct_len_out = pt_len + 16;
	}

out:
	mbedtls_chachapoly_free(&ctx);
	return rc ? -EIO : 0;
}

int noise_crypto_decrypt(uint8_t *pt_out, size_t pt_buf_len, size_t *pt_len_out,
			 const uint8_t key[32], uint64_t nonce,
			 const uint8_t *ad, size_t ad_len,
			 const uint8_t *ct, size_t ct_len)
{
	if (ct_len < 16) {
		return -EINVAL;
	}

	size_t body_len = ct_len - 16;

	if (pt_buf_len < body_len) {
		return -EINVAL;
	}

	uint8_t nonce_buf[12];

	nonce_encode(nonce_buf, nonce);

	mbedtls_chachapoly_context ctx;

	mbedtls_chachapoly_init(&ctx);

	int rc = mbedtls_chachapoly_setkey(&ctx, key);

	if (rc) {
		mbedtls_chachapoly_free(&ctx);
		return -EIO;
	}

	rc = mbedtls_chachapoly_auth_decrypt(&ctx, body_len,
					     nonce_buf, ad, ad_len,
					     ct + body_len,   /* tag */
					     ct, pt_out);
	mbedtls_chachapoly_free(&ctx);

	if (rc == MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED) {
		return -EBADMSG;
	}
	if (rc) {
		return -EIO;
	}
	*pt_len_out = body_len;
	return 0;
}

int noise_crypto_hash(uint8_t out[32],
		      const uint8_t *a, size_t a_len,
		      const uint8_t *b, size_t b_len)
{
	mbedtls_sha256_context ctx;

	mbedtls_sha256_init(&ctx);

	int rc = mbedtls_sha256_starts(&ctx, 0);  /* 0 = SHA-256, not SHA-224 */

	if (rc) {
		goto out;
	}
	rc = mbedtls_sha256_update(&ctx, a, a_len);
	if (rc) {
		goto out;
	}
	rc = mbedtls_sha256_update(&ctx, b, b_len);
	if (rc) {
		goto out;
	}
	rc = mbedtls_sha256_finish(&ctx, out);

out:
	mbedtls_sha256_free(&ctx);
	return rc ? -EIO : 0;
}

int noise_crypto_hkdf2(uint8_t out1[32], uint8_t out2[32],
		       const uint8_t ck[32],
		       const uint8_t *ikm, size_t ikm_len)
{
	/*
	 * Noise's HKDF function (2 outputs) is identical to RFC 5869
	 * HKDF(salt=ck, ikm, info="", L=64) split into two 32-byte halves.
	 *
	 * Proof: HKDF-Extract(salt, ikm) = HMAC(salt, ikm) = temp_key.
	 * HKDF-Expand(temp_key, "", 64):
	 *   T(1) = HMAC(temp_key, 0x01)
	 *   T(2) = HMAC(temp_key, T(1) || 0x02)
	 *   OKM  = T(1) || T(2)
	 * which matches Noise's output1, output2 exactly.
	 */
	const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	uint8_t okm[64];

	int rc = mbedtls_hkdf(md,
			      ck, 32,
			      ikm, ikm_len,
			      NULL, 0,
			      okm, sizeof(okm));
	if (rc) {
		return -EIO;
	}
	memcpy(out1, okm, 32);
	memcpy(out2, okm + 32, 32);
	mbedtls_platform_zeroize(okm, sizeof(okm));
	return 0;
}
