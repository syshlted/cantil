/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

/*
 * Known-answer tests for crypto.h, run against whichever backend the suite
 * directory links (crypto.c / mbedTLS, or crypto_wolfssl.c / wolfCrypt).
 *
 * Two of these are not ordinary correctness checks but data-availability ones.
 * The CA private key is stored AES-256-GCM encrypted under
 * crypto_storage_key_derive(), cannot be exported, and has no backup. If a
 * backend derived that key differently, or laid the blob out differently, then
 * changing backends would turn a firmware update into unrecoverable key loss —
 * the device would boot, mount its volume, find its key blob intact, and fail
 * to authenticate it. storage_key_derive_kat and decrypt_blob_kat are what
 * stop that reaching a device.
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <string.h>
#include <errno.h>

#include "crypto.h"
#include "vectors.h"

ZTEST_SUITE(crypto_kat, NULL, NULL, NULL, NULL, NULL);

/* ── storage key ─────────────────────────────────────────────────────── */

ZTEST(crypto_kat, storage_key_derive_kat)
{
	uint8_t key[32];

	zassert_ok(crypto_storage_key_derive(key), "derive");
	zassert_mem_equal(key, KAT_STORAGE_KEY, 32,
			  "storage key differs from HKDF-SHA256(salt=empty, "
			  "ikm=FICR UID, info=\"cantil-storage-key\") — every "
			  "stored key blob becomes undecryptable");
}

ZTEST(crypto_kat, storage_key_derive_is_stable)
{
	uint8_t a[32], b[32];

	zassert_ok(crypto_storage_key_derive(a), "derive a");
	zassert_ok(crypto_storage_key_derive(b), "derive b");
	zassert_mem_equal(a, b, 32, "derivation is not deterministic");
}

/* ── HKDF ────────────────────────────────────────────────────────────── */

/*
 * crypto_hkdf_sha256() is what crypto_storage_key_derive() and the pairing PSK
 * both sit on, so it is pinned against RFC 5869 Test Case 1 — a published
 * answer, which is the only kind that can say two libraries agree without
 * nominating one of them as the oracle.
 */
ZTEST(crypto_kat, hkdf_rfc5869_tc1)
{
	uint8_t okm[42];

	zassert_ok(crypto_hkdf_sha256(KAT_HKDF_IKM, sizeof(KAT_HKDF_IKM), KAT_HKDF_SALT,
				      sizeof(KAT_HKDF_SALT), KAT_HKDF_INFO, sizeof(KAT_HKDF_INFO),
				      okm, sizeof(okm)),
		   "hkdf");
	zassert_mem_equal(okm, KAT_HKDF_OKM, sizeof(okm),
			  "HKDF-SHA256 disagrees with RFC 5869 TC1");
}

/*
 * A NULL salt must mean RFC 5869's "not provided" case, which the standard
 * defines as a hash-length block of zeros — not as an empty HMAC key. The two
 * are different, both libraries happen to implement the former, and
 * crypto_storage_key_derive() depends on it: get this wrong and every stored
 * key blob becomes undecryptable. Assert the equivalence directly rather than
 * trusting that both libraries kept it.
 */
ZTEST(crypto_kat, hkdf_null_salt_is_a_zero_block)
{
	const uint8_t zeros[32] = {0};
	uint8_t a[32], b[32];

	zassert_ok(crypto_hkdf_sha256(KAT_HKDF_IKM, sizeof(KAT_HKDF_IKM), NULL, 0, KAT_HKDF_INFO,
				      sizeof(KAT_HKDF_INFO), a, sizeof(a)),
		   "null salt");
	zassert_ok(crypto_hkdf_sha256(KAT_HKDF_IKM, sizeof(KAT_HKDF_IKM), zeros, sizeof(zeros),
				      KAT_HKDF_INFO, sizeof(KAT_HKDF_INFO), b, sizeof(b)),
		   "explicit zero salt");
	zassert_mem_equal(a, b, sizeof(a),
			  "NULL salt is not being treated as a 32-byte zero block");
}

/*
 * The pairing PSK, as src/clients/pairing.c derive_psk() computes it. That
 * function is static, so the inputs are reproduced here rather than called;
 * what is being pinned is the seam's answer for them.
 *
 * Worth a fixed answer because the failure is silent: the two peers derive
 * this independently, so a backend that disagreed would not report an error —
 * pairing would simply never complete, with nothing on either side saying why.
 */
ZTEST(crypto_kat, pairing_psk_kat)
{
	const uint8_t ikm[4] = {(uint8_t)(KAT_PSK_PASSKEY >> 24), (uint8_t)(KAT_PSK_PASSKEY >> 16),
				(uint8_t)(KAT_PSK_PASSKEY >> 8), (uint8_t)(KAT_PSK_PASSKEY)};
	uint8_t salt[64];
	uint8_t psk[32];
	static const uint8_t info[] = "cantil-psk-v1";

	memcpy(salt, KAT_PSK_LOCAL, 32);
	memcpy(salt + 32, KAT_PSK_REMOTE, 32);

	zassert_ok(crypto_hkdf_sha256(ikm, sizeof(ikm), salt, sizeof(salt), info, sizeof(info) - 1,
				      psk, sizeof(psk)),
		   "derive psk");
	zassert_mem_equal(psk, KAT_PSK, sizeof(psk),
			  "pairing PSK differs — passkey pairing would fail "
			  "silently against a peer on the other backend");
}

/* ── P-256 ───────────────────────────────────────────────────────────── */

ZTEST(crypto_kat, pubkey_from_privkey_kat)
{
	uint8_t pub[65];
	size_t len = sizeof(pub);

	zassert_ok(crypto_pubkey_from_privkey(KAT_P256_PRIV, 32, pub, &len), "pubkey");
	zassert_equal(len, 65, "expected uncompressed SEC1, got %zu", len);
	zassert_mem_equal(pub, KAT_P256_PUB, 65, "pubkey mismatch");
}

ZTEST(crypto_kat, sign_deterministic_kat)
{
	/*
	 * RFC 6979 §A.2.5. A signature that matches this proves the backend
	 * derives k the same way, which is what makes two backends produce
	 * byte-identical certificates from the same CA key — and what stops a
	 * biased or repeated k leaking a key that can never be rotated.
	 */
	uint8_t sig[64];
	size_t len = sizeof(sig);

	zassert_ok(crypto_sign(KAT_P256_PRIV, 32, KAT_P256_DIGEST, 32, sig, &len), "sign");
	zassert_equal(len, 64, "expected raw r||s, got %zu", len);
	zassert_mem_equal(sig, KAT_P256_SIG, 64, "signature differs from RFC 6979 A.2.5");
}

ZTEST(crypto_kat, sign_repeats_exactly)
{
	uint8_t a[64], b[64];
	size_t la = sizeof(a), lb = sizeof(b);

	zassert_ok(crypto_sign(KAT_P256_PRIV, 32, KAT_P256_DIGEST, 32, a, &la), "sign a");
	zassert_ok(crypto_sign(KAT_P256_PRIV, 32, KAT_P256_DIGEST, 32, b, &lb), "sign b");
	zassert_mem_equal(a, b, 64, "signing is not deterministic");
}

ZTEST(crypto_kat, keygen_produces_a_usable_key)
{
	uint8_t priv[32];
	size_t plen = sizeof(priv);
	uint8_t pub[65];
	size_t publen = sizeof(pub);

	zassert_ok(crypto_keygen(priv, &plen), "keygen");
	zassert_equal(plen, 32, "expected a 32-byte scalar, got %zu", plen);

	zassert_ok(crypto_pubkey_from_privkey(priv, plen, pub, &publen),
		   "pubkey from generated key");
	zassert_equal(publen, 65, "expected uncompressed SEC1");
	zassert_equal(pub[0], 0x04, "expected the uncompressed point tag");

	uint8_t sig[64];
	size_t siglen = sizeof(sig);

	zassert_ok(crypto_sign(priv, plen, KAT_P256_DIGEST, 32, sig, &siglen),
		   "sign with generated key");
}

/* ── AES-256-GCM key blobs ───────────────────────────────────────────── */

ZTEST(crypto_kat, decrypt_blob_kat)
{
	uint8_t pt[64];
	size_t len = sizeof(pt);

	zassert_ok(crypto_decrypt_blob(KAT_BLOB_KEY, KAT_BLOB, sizeof(KAT_BLOB), pt, &len),
		   "decrypt");
	zassert_equal(len, sizeof(KAT_BLOB_PT), "length %zu", len);
	zassert_mem_equal(pt, KAT_BLOB_PT, sizeof(KAT_BLOB_PT),
			  "blob layout or cipher differs — stored key blobs "
			  "written by another backend would not read back");
}

ZTEST(crypto_kat, encrypt_decrypt_roundtrip)
{
	uint8_t ct[128];
	size_t ctlen = sizeof(ct);
	uint8_t pt[64];
	size_t ptlen = sizeof(pt);

	zassert_ok(crypto_encrypt_blob(KAT_BLOB_KEY, KAT_BLOB_PT, sizeof(KAT_BLOB_PT), ct, &ctlen),
		   "encrypt");
	zassert_equal(ctlen, 12 + sizeof(KAT_BLOB_PT) + 16, "expected [nonce][ct][tag], got %zu",
		      ctlen);

	zassert_ok(crypto_decrypt_blob(KAT_BLOB_KEY, ct, ctlen, pt, &ptlen), "decrypt");
	zassert_equal(ptlen, sizeof(KAT_BLOB_PT), "roundtrip length");
	zassert_mem_equal(pt, KAT_BLOB_PT, sizeof(KAT_BLOB_PT), "roundtrip");
}

ZTEST(crypto_kat, encrypt_blob_nonce_is_fresh)
{
	uint8_t a[128], b[128];
	size_t la = sizeof(a), lb = sizeof(b);

	zassert_ok(crypto_encrypt_blob(KAT_BLOB_KEY, KAT_BLOB_PT, sizeof(KAT_BLOB_PT), a, &la),
		   "a");
	zassert_ok(crypto_encrypt_blob(KAT_BLOB_KEY, KAT_BLOB_PT, sizeof(KAT_BLOB_PT), b, &lb),
		   "b");

	/* A repeated GCM nonce under the same key is a total break, so this is
	 * checked rather than assumed of the TRNG wiring. */
	zassert_true(memcmp(a, b, 12) != 0, "nonce repeated across calls");
}

ZTEST(crypto_kat, decrypt_blob_rejects_a_tampered_tag)
{
	uint8_t blob[sizeof(KAT_BLOB)];
	uint8_t pt[64];
	size_t len = sizeof(pt);

	memcpy(blob, KAT_BLOB, sizeof(blob));
	blob[sizeof(blob) - 1] ^= 0x01;

	zassert_equal(crypto_decrypt_blob(KAT_BLOB_KEY, blob, sizeof(blob), pt, &len), -EBADMSG,
		      "a corrupted tag must be -EBADMSG, not a silent pass");
}

ZTEST(crypto_kat, decrypt_blob_rejects_a_tampered_ciphertext)
{
	uint8_t blob[sizeof(KAT_BLOB)];
	uint8_t pt[64];
	size_t len = sizeof(pt);

	memcpy(blob, KAT_BLOB, sizeof(blob));
	blob[20] ^= 0x01;

	zassert_equal(crypto_decrypt_blob(KAT_BLOB_KEY, blob, sizeof(blob), pt, &len), -EBADMSG,
		      "a corrupted blob body must be -EBADMSG");
}

/* ── TRNG ────────────────────────────────────────────────────────────── */

ZTEST(crypto_kat, trng_does_not_repeat)
{
	uint8_t a[32], b[32];

	zassert_ok(crypto_trng(a, sizeof(a)), "trng a");
	zassert_ok(crypto_trng(b, sizeof(b)), "trng b");
	zassert_true(memcmp(a, b, sizeof(a)) != 0, "TRNG returned twice alike");
}
