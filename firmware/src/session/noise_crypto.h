#pragma once

#include <stdint.h>
#include <stddef.h>

/*
 * Noise protocol cryptographic primitives.
 *
 * Single backend: noise_crypto_mbedtls.c (mbedtls direct, no PSA layer).
 * The abstraction is kept so an alternate backend (e.g. libsodium on the host)
 * is a one-file swap.
 *
 * session.c implements the Noise_XX state machine using only these 6 functions,
 * with no direct dependency on any crypto library.
 */

/* Curve25519 keypair generation. */
int noise_crypto_dh_keygen(uint8_t priv_out[32], uint8_t pub_out[32]);

/* Curve25519 DH: shared_out = X25519(priv, pub). */
int noise_crypto_dh(uint8_t shared_out[32],
		    const uint8_t priv[32], const uint8_t pub[32]);

/*
 * ChaCha20-Poly1305 AEAD encrypt.
 * ct_out must be at least (pt_len + 16) bytes; ct_buf_len is its capacity.
 * Nonce is a 64-bit counter encoded as 4 zero bytes || 8-byte little-endian.
 */
int noise_crypto_encrypt(uint8_t *ct_out, size_t ct_buf_len, size_t *ct_len_out,
			 const uint8_t key[32], uint64_t nonce,
			 const uint8_t *ad, size_t ad_len,
			 const uint8_t *pt, size_t pt_len);

/*
 * ChaCha20-Poly1305 AEAD decrypt.
 * pt_out must be at least (ct_len - 16) bytes; pt_buf_len is its capacity.
 * Returns -EBADMSG on authentication failure.
 */
int noise_crypto_decrypt(uint8_t *pt_out, size_t pt_buf_len, size_t *pt_len_out,
			 const uint8_t key[32], uint64_t nonce,
			 const uint8_t *ad, size_t ad_len,
			 const uint8_t *ct, size_t ct_len);

/* SHA-256(a || b). Used for MixHash in the Noise handshake. */
int noise_crypto_hash(uint8_t out[32],
		      const uint8_t *a, size_t a_len,
		      const uint8_t *b, size_t b_len);

/*
 * Noise HKDF-2: (out1[32], out2[32]) = HKDF(salt=ck, ikm) using HMAC-SHA-256.
 * Implements the Noise Protocol spec HKDF function with 2 output blocks.
 * ikm_len may be 0 for the Split() call.
 */
int noise_crypto_hkdf2(uint8_t out1[32], uint8_t out2[32],
		       const uint8_t ck[32],
		       const uint8_t *ikm, size_t ikm_len);
