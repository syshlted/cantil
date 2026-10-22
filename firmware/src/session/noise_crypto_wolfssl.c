/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

/*
 * noise_crypto.h implemented against wolfCrypt.
 *
 * The only noise_crypto.h backend since the mbedTLS one was removed, selected by
 * the CANTIL_CRYPTO_BACKEND choice. session.c drives the Noise_XX state machine
 * through these six functions and never sees either library.
 *
 * The two backends must agree byte for byte, not merely each with itself — a
 * device on one backend has to talk to a host on the other. firmware/tests/
 * noise_crypto/ is what holds that: it runs fixed vectors, generated
 * independently by gen_vectors.py, against whichever backend is built.
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <string.h>
#include <errno.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "noise_crypto.h"
#include "crypto/wc_rand.h"
#include "crypto/zeroize.h"

LOG_MODULE_REGISTER(noise_wolfssl, LOG_LEVEL_INF);

/* Noise nonce: 4 zero bytes || 8-byte little-endian counter. */
static void nonce_encode(uint8_t out[12], uint64_t n)
{
	memset(out, 0, 4);
	for (int i = 0; i < 8; i++) {
		out[4 + i] = (uint8_t)(n >> (8 * i));
	}
}

/*
 * Stand-in for a zero-length buffer.
 *
 * wc_ChaCha20Poly1305_Encrypt() validates its arguments as though a NULL
 * plaintext with length 0 were legal — "(inPlaintextLen > 0 && inPlaintext ==
 * NULL)" — and then hands that NULL to wc_ChaCha20Poly1305_UpdateData(), which
 * rejects a NULL data pointer outright regardless of length. The result is
 * BAD_FUNC_ARG (-173) for an empty payload, where mbedTLS returns a bare tag.
 *
 * That is not an edge case here. Noise_XX AEAD-encrypts an empty payload in
 * the handshake, so every session would fail on the first message. Passing a
 * pointer to this array instead keeps the call inside wolfCrypt's contract; no
 * byte of it is read or written, because the length is zero.
 */
static uint8_t zero_len_stand_in[1];

/* RFC 7748 §5 scalar clamping. */
static void x25519_clamp(uint8_t k[32])
{
	k[0] &= 248;
	k[31] &= 127;
	k[31] |= 64;
}

int noise_crypto_dh_keygen(uint8_t priv_out[32], uint8_t pub_out[32])
{
	if (cantil_wc_trng(priv_out, 32)) {
		return -EIO;
	}
	x25519_clamp(priv_out);

	/*
	 * wc_curve25519_make_pub takes the raw little-endian scalar and
	 * basepoint form of RFC 7748, which is the same encoding Noise puts on
	 * the wire — no import/export step, and no endianness argument to get
	 * wrong. It rejects an unclamped scalar outright, hence the clamp above.
	 */
	int rc = wc_curve25519_make_pub(32, pub_out, 32, priv_out);

	if (rc != 0) {
		LOG_ERR("curve25519_make_pub=%d", rc);
		return -EIO;
	}
	return 0;
}

int noise_crypto_dh(uint8_t shared_out[32], const uint8_t priv[32], const uint8_t pub[32])
{
	/*
	 * Clamp a copy rather than requiring callers to hand us a clamped
	 * scalar, so this is a true X25519 and is idempotent for keys that were
	 * already clamped. Matches the mbedTLS backend, which clamps for the
	 * same reason.
	 */
	uint8_t priv_clamped[32];

	memcpy(priv_clamped, priv, 32);
	x25519_clamp(priv_clamped);

	int rc = wc_curve25519_generic(32, shared_out, 32, priv_clamped, 32, pub);

	cantil_zeroize(priv_clamped, sizeof(priv_clamped));

	if (rc != 0) {
		/*
		 * Unlike mbedTLS, wolfCrypt refuses to return an all-zero
		 * shared secret — the result of a peer sending a small-order
		 * point. That is a stricter contract than Noise requires and a
		 * safer one, but it means a handshake that mbedTLS would have
		 * carried on with fails here instead. It surfaces as a failed
		 * handshake, not as a silently weak session.
		 */
		LOG_ERR("curve25519_generic=%d", rc);
		return -EIO;
	}
	return 0;
}

int noise_crypto_encrypt(uint8_t *ct_out, size_t ct_buf_len, size_t *ct_len_out,
			 const uint8_t key[32], uint64_t nonce, const uint8_t *ad, size_t ad_len,
			 const uint8_t *pt, size_t pt_len)
{
	if (ct_buf_len < pt_len + 16) {
		return -EINVAL;
	}

	uint8_t nonce_buf[12];

	nonce_encode(nonce_buf, nonce);

	/* Ciphertext into ct_out, 16-byte tag appended after it. */
	int rc = wc_ChaCha20Poly1305_Encrypt(key, nonce_buf, ad, (word32)ad_len,
					     pt_len ? pt : zero_len_stand_in, (word32)pt_len,
					     ct_out, ct_out + pt_len);
	if (rc != 0) {
		LOG_ERR("chacha20poly1305_encrypt=%d", rc);
		return -EIO;
	}
	*ct_len_out = pt_len + 16;
	return 0;
}

int noise_crypto_decrypt(uint8_t *pt_out, size_t pt_buf_len, size_t *pt_len_out,
			 const uint8_t key[32], uint64_t nonce, const uint8_t *ad, size_t ad_len,
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

	int rc = wc_ChaCha20Poly1305_Decrypt(key, nonce_buf, ad, (word32)ad_len,
					     body_len ? ct : zero_len_stand_in, (word32)body_len,
					     ct + body_len, /* tag */
					     body_len ? pt_out : zero_len_stand_in);
	if (rc == MAC_CMP_FAILED_E) {
		return -EBADMSG;
	}
	if (rc != 0) {
		return -EIO;
	}
	*pt_len_out = body_len;
	return 0;
}

int noise_crypto_hash(uint8_t out[32], const uint8_t *a, size_t a_len, const uint8_t *b,
		      size_t b_len)
{
	wc_Sha256 ctx;
	int rc = wc_InitSha256(&ctx);

	if (rc != 0) {
		return -EIO;
	}

	rc = wc_Sha256Update(&ctx, a, (word32)a_len);
	if (rc == 0) {
		rc = wc_Sha256Update(&ctx, b, (word32)b_len);
	}
	if (rc == 0) {
		rc = wc_Sha256Final(&ctx, out);
	}

	wc_Sha256Free(&ctx);
	return rc ? -EIO : 0;
}

int noise_crypto_hkdf2(uint8_t out1[32], uint8_t out2[32], const uint8_t ck[32], const uint8_t *ikm,
		       size_t ikm_len)
{
	/*
	 * Noise's HKDF (2 outputs) is RFC 5869 HKDF(salt=ck, ikm, info="",
	 * L=64) cut in half — see the derivation in the comment above.
	 *
	 * wc_HKDF does Extract then Expand internally, which keeps the whole
	 * derivation inside the library rather than composing HMAC calls here.
	 * That is a deliberate choice: anything Cantil computes itself sits
	 * outside a validated module's boundary and would have to be re-argued
	 * by a downstream party pursuing certification. See "Why abstraction
	 * serves the FIPS goal" in docs/roadmap/wolfssl-migration.md.
	 *
	 * Argument order differs from mbedtls_hkdf(): wolfCrypt takes the IKM
	 * first and the salt second.
	 */
	static const uint8_t empty;
	uint8_t okm[64];

	int rc = wc_HKDF(WC_SHA256, ikm_len ? ikm : &empty, (word32)ikm_len, /* IKM  */
			 ck, 32,                                             /* salt */
			 NULL, 0,                                            /* info */
			 okm, sizeof(okm));
	if (rc != 0) {
		LOG_ERR("wc_HKDF=%d", rc);
		return -EIO;
	}

	memcpy(out1, okm, 32);
	memcpy(out2, okm + 32, 32);
	cantil_zeroize(okm, sizeof(okm));
	return 0;
}
