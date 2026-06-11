/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <string.h>

#include "noise_crypto.h"
#include "vectors.h"

ZTEST_SUITE(noise_crypto, NULL, NULL, NULL, NULL, NULL);

/* ── X25519 KAT (RFC 7748 §6.1) ──────────────────────────────────────── */

ZTEST(noise_crypto, x25519_alice_derives_pub)
{
	uint8_t pub[32];
	uint8_t shared[32];

	/* Re-derive Alice's public key by DH(alice_priv, basepoint).
	 * X25519 basepoint = 9 || 0...0 — encode directly.
	 */
	uint8_t basepoint[32] = {9};

	zassert_ok(noise_crypto_dh(shared, X25519_ALICE_PRIV, basepoint),
		   "DH(alice, basepoint)");
	zassert_mem_equal(shared, X25519_ALICE_PUB, 32,
			  "alice pub mismatch");
}

ZTEST(noise_crypto, x25519_bob_derives_pub)
{
	uint8_t basepoint[32] = {9};
	uint8_t pub[32];

	zassert_ok(noise_crypto_dh(pub, X25519_BOB_PRIV, basepoint),
		   "DH(bob, basepoint)");
	zassert_mem_equal(pub, X25519_BOB_PUB, 32, "bob pub mismatch");
}

ZTEST(noise_crypto, x25519_shared_secret_both_directions)
{
	uint8_t s_ab[32], s_ba[32];

	zassert_ok(noise_crypto_dh(s_ab, X25519_ALICE_PRIV, X25519_BOB_PUB),
		   "DH(alice, bob_pub)");
	zassert_ok(noise_crypto_dh(s_ba, X25519_BOB_PRIV, X25519_ALICE_PUB),
		   "DH(bob, alice_pub)");
	zassert_mem_equal(s_ab, X25519_SHARED, 32, "ab shared mismatch");
	zassert_mem_equal(s_ba, X25519_SHARED, 32, "ba shared mismatch");
}

ZTEST(noise_crypto, x25519_keygen_roundtrip)
{
	uint8_t priv[32], pub[32], pub_check[32];
	uint8_t basepoint[32] = {9};

	zassert_ok(noise_crypto_dh_keygen(priv, pub), "keygen");

	/* Clamping invariants per RFC 7748 §5. */
	zassert_equal(priv[0] & 7, 0, "low 3 bits not cleared");
	zassert_equal(priv[31] & 0x80, 0, "top bit not cleared");
	zassert_equal(priv[31] & 0x40, 0x40, "bit 254 not set");

	zassert_ok(noise_crypto_dh(pub_check, priv, basepoint),
		   "redrive pub from priv");
	zassert_mem_equal(pub, pub_check, 32, "keygen pub != DH(priv, base)");
}

/* ── SHA-256 KAT ─────────────────────────────────────────────────────── */

ZTEST(noise_crypto, sha256_abc_split_input)
{
	/* noise_crypto_hash takes two halves — feed "a" || "bc" = "abc". */
	uint8_t out[32];

	zassert_ok(noise_crypto_hash(out,
				     SHA256_ABC_A,  sizeof(SHA256_ABC_A),
				     SHA256_ABC_BC, sizeof(SHA256_ABC_BC)),
		   "hash");
	zassert_mem_equal(out, SHA256_ABC_HASH, 32, "SHA-256(abc) mismatch");
}

ZTEST(noise_crypto, sha256_empty)
{
	/* SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
	static const uint8_t expected[32] = {
		0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
		0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
		0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
		0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
	};
	uint8_t out[32];

	zassert_ok(noise_crypto_hash(out, NULL, 0, NULL, 0), "hash empty");
	zassert_mem_equal(out, expected, 32, "SHA-256(empty) mismatch");
}

/* ── ChaCha20-Poly1305 KAT ──────────────────────────────────────────── */

ZTEST(noise_crypto, aead_encrypt_n0)
{
	uint8_t ct[sizeof(AEAD_PT1) + 16];
	size_t  ct_len = 0;

	zassert_ok(noise_crypto_encrypt(ct, sizeof(ct), &ct_len,
					AEAD_KEY1, 0,
					AEAD_AD1, sizeof(AEAD_AD1),
					AEAD_PT1, sizeof(AEAD_PT1)),
		   "encrypt n=0");
	zassert_equal(ct_len, sizeof(AEAD_CT1_N0), "ct length");
	zassert_mem_equal(ct, AEAD_CT1_N0, ct_len, "ct n=0 mismatch");
}

ZTEST(noise_crypto, aead_encrypt_n1_differs)
{
	uint8_t ct[sizeof(AEAD_PT1) + 16];
	size_t  ct_len = 0;

	zassert_ok(noise_crypto_encrypt(ct, sizeof(ct), &ct_len,
					AEAD_KEY1, 1,
					AEAD_AD1, sizeof(AEAD_AD1),
					AEAD_PT1, sizeof(AEAD_PT1)),
		   "encrypt n=1");
	zassert_mem_equal(ct, AEAD_CT1_N1, ct_len, "ct n=1 mismatch");
	/* Cross-check the nonce-encoding bug class: same inputs, nonce only
	 * differs in the uint64 counter — outputs must differ.
	 */
	zassert_true(memcmp(AEAD_CT1_N0, AEAD_CT1_N1, ct_len) != 0,
		     "n=0 and n=1 ciphertexts must differ");
}

ZTEST(noise_crypto, aead_decrypt_n0)
{
	uint8_t pt[sizeof(AEAD_PT1)];
	size_t  pt_len = 0;

	zassert_ok(noise_crypto_decrypt(pt, sizeof(pt), &pt_len,
					AEAD_KEY1, 0,
					AEAD_AD1, sizeof(AEAD_AD1),
					AEAD_CT1_N0, sizeof(AEAD_CT1_N0)),
		   "decrypt n=0");
	zassert_equal(pt_len, sizeof(AEAD_PT1), "pt length");
	zassert_mem_equal(pt, AEAD_PT1, pt_len, "pt mismatch");
}

ZTEST(noise_crypto, aead_decrypt_wrong_nonce_fails)
{
	uint8_t pt[sizeof(AEAD_PT1)];
	size_t  pt_len = 0;

	int rc = noise_crypto_decrypt(pt, sizeof(pt), &pt_len,
				      AEAD_KEY1, 1,  /* wrong nonce */
				      AEAD_AD1, sizeof(AEAD_AD1),
				      AEAD_CT1_N0, sizeof(AEAD_CT1_N0));
	zassert_equal(rc, -EBADMSG, "expected auth failure, got %d", rc);
}

ZTEST(noise_crypto, aead_decrypt_tampered_tag_fails)
{
	uint8_t ct[sizeof(AEAD_CT1_N0)];
	uint8_t pt[sizeof(AEAD_PT1)];
	size_t  pt_len = 0;

	memcpy(ct, AEAD_CT1_N0, sizeof(ct));
	ct[sizeof(ct) - 1] ^= 0x01;  /* flip a tag byte */

	int rc = noise_crypto_decrypt(pt, sizeof(pt), &pt_len,
				      AEAD_KEY1, 0,
				      AEAD_AD1, sizeof(AEAD_AD1),
				      ct, sizeof(ct));
	zassert_equal(rc, -EBADMSG, "expected auth failure, got %d", rc);
}

ZTEST(noise_crypto, aead_decrypt_tampered_ad_fails)
{
	uint8_t bad_ad[sizeof(AEAD_AD1)];
	uint8_t pt[sizeof(AEAD_PT1)];
	size_t  pt_len = 0;

	memcpy(bad_ad, AEAD_AD1, sizeof(bad_ad));
	bad_ad[0] ^= 0x01;

	int rc = noise_crypto_decrypt(pt, sizeof(pt), &pt_len,
				      AEAD_KEY1, 0,
				      bad_ad, sizeof(bad_ad),
				      AEAD_CT1_N0, sizeof(AEAD_CT1_N0));
	zassert_equal(rc, -EBADMSG, "expected auth failure, got %d", rc);
}

ZTEST(noise_crypto, aead_empty_plaintext)
{
	/* Noise handshake messages frequently AEAD-encrypt an empty payload. */
	uint8_t ct[16];
	size_t  ct_len = 0;

	zassert_ok(noise_crypto_encrypt(ct, sizeof(ct), &ct_len,
					AEAD_KEY3_ZERO, 0,
					NULL, 0,
					NULL, 0),
		   "encrypt empty");
	zassert_equal(ct_len, 16, "empty ct must be tag-only (16 bytes)");
	zassert_mem_equal(ct, AEAD_CT3_EMPTY, 16, "empty ct mismatch");
}

/* ── HKDF-2 KAT ─────────────────────────────────────────────────────── */

ZTEST(noise_crypto, hkdf2_basic)
{
	uint8_t o1[32], o2[32];

	zassert_ok(noise_crypto_hkdf2(o1, o2, HKDF_CK,
				      HKDF_IKM, sizeof(HKDF_IKM)),
		   "hkdf2");
	zassert_mem_equal(o1, HKDF_OUT1, 32, "hkdf2 out1 mismatch");
	zassert_mem_equal(o2, HKDF_OUT2, 32, "hkdf2 out2 mismatch");
}

ZTEST(noise_crypto, hkdf2_empty_ikm)
{
	/* Noise Split() calls HKDF-2 with empty ikm. */
	uint8_t o1[32], o2[32];

	zassert_ok(noise_crypto_hkdf2(o1, o2, HKDF_CK, NULL, 0),
		   "hkdf2 empty ikm");
	zassert_mem_equal(o1, HKDF_OUT1_EMPTY, 32,
			  "hkdf2 empty out1 mismatch");
	zassert_mem_equal(o2, HKDF_OUT2_EMPTY, 32,
			  "hkdf2 empty out2 mismatch");
}
