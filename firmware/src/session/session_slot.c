/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/hwinfo.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <mbedtls/platform_util.h>

#include "session_slot.h"
#include "session_x509.h"
#include "noise_crypto.h"
#include "ca/ca.h"
#include "crypto/crypto.h"
#include "storage/storage.h"

LOG_MODULE_REGISTER(session_slot, LOG_LEVEL_INF);

/* AES-256-GCM blob: 12-byte nonce + 32-byte ciphertext + 16-byte tag. */
#define SESSION_ENC_LEN       (12 + 32 + 16)
#define SESSION_CERT_DER_MAX  2048

/*
 * /session/meta.bin layout (packed, 44 bytes). Caches the X25519 pubkey and an
 * init timestamp (0 — no RTC). `flags` bit0 is reserved for the Phase B
 * "cert has been CA-signed" marker.
 */
#define SESSION_META_VERSION  1
#define SESSION_META_FLAG_CA_SIGNED  0x01  /* bit0: cert is CA-signed (T-06) */
typedef struct __attribute__((packed)) {
	uint8_t  version;          /* 1 */
	uint8_t  flags;            /* bit0 = CA-signed (set in Phase B) */
	uint8_t  reserved[2];
	uint64_t init_unix;        /* 0 if no RTC */
	uint8_t  x25519_pub[32];   /* cached Noise static pubkey */
} session_meta_t;
BUILD_ASSERT(sizeof(session_meta_t) == 44, "session_meta_t layout");

/*
 * Recovery mode (T-03). Set when CONFIG_CANTIL_SESSION_X509_STRICT=y and the
 * stored cert's identity fields no longer match the build constant. The
 * protocol dispatcher consults session_slot_in_recovery() to refuse all
 * opcodes except DEVICE_STATUS / RESET_DEVICE, and main.c shows
 * LED_PATTERN_IDENTITY_MISMATCH.
 */
static bool s_in_recovery;

bool session_slot_in_recovery(void)
{
	return s_in_recovery;
}

/*
 * Strict boot-time identity check (T-03). Re-reads the stored cert and compares
 * its subject-side fields against the build constant via ca_session_cert_matches
 * _constant(). On mismatch (or an unreadable / unparseable cert) under strict
 * mode, latches recovery mode; under non-strict mode logs a warning and lets the
 * device boot normally. Returns 0 unless a non-strict storage read genuinely
 * fails.
 */
static int verify_session_identity(void)
{
	uint8_t cert[SESSION_CERT_DER_MAX];
	size_t  cert_len = sizeof(cert);
	int ret = storage_session_cert_read(cert, &cert_len);

	if (ret) {
		LOG_ERR("session slot: read cert.der=%d", ret);
		if (IS_ENABLED(CONFIG_CANTIL_SESSION_X509_STRICT)) {
			s_in_recovery = true;  /* can't validate -> fail safe */
			return 0;
		}
		return ret;
	}

	int m = ca_session_cert_matches_constant(
			cert, cert_len,
			cantil_session_x509_constant,
			cantil_session_x509_constant_len);

	if (m == 1) {
		LOG_INF("session slot present; identity matches build constant");
		return 0;
	}

	if (m < 0) {
		LOG_ERR("session slot: identity compare error %d", m);
	} else {
		LOG_ERR("session slot: identity MISMATCH vs build constant");
	}

	if (IS_ENABLED(CONFIG_CANTIL_SESSION_X509_STRICT)) {
		LOG_ERR("session slot: entering recovery mode (strict)");
		s_in_recovery = true;
	} else {
		LOG_WRN("session slot: continuing despite mismatch (non-strict)");
	}
	return 0;
}

/* CN = "Cantil-" + 16 hex chars of the FICR device id (matches the USB
 * iSerial). Falls back to the bare constant CN if hwinfo is unavailable. */
static void derive_cn(char *out, size_t cap)
{
	uint8_t id[8];
	ssize_t n = hwinfo_get_device_id(id, sizeof(id));

	if (n == (ssize_t)sizeof(id)) {
		snprintf(out, cap,
			 "Cantil-%02X%02X%02X%02X%02X%02X%02X%02X",
			 id[0], id[1], id[2], id[3],
			 id[4], id[5], id[6], id[7]);
	} else {
		LOG_WRN("hwinfo_get_device_id -> %d; CN falls back to constant",
			(int)n);
		snprintf(out, cap, "Cantil");
	}
}

int session_slot_init(void)
{
	uint8_t x_priv[32], x_pub[32];
	uint8_t id_priv[64];
	uint8_t storage_key[32];
	uint8_t enc[SESSION_ENC_LEN];
	uint8_t cert[SESSION_CERT_DER_MAX];
	size_t  id_len = sizeof(id_priv);
	size_t  enc_len;
	size_t  cert_len = sizeof(cert);
	char    cn[40];
	session_meta_t m;
	int ret;

	ret = storage_session_cert_exists();
	if (ret == 1) {
		return verify_session_identity();
	}
	if (ret < 0) {
		return ret;
	}

	LOG_INF("session slot: first-boot init");

	/*
	 * X25519 Noise static key. As of T-04 the session slot is the single
	 * source of truth: generate the scalar here, persist it (encrypted) to
	 * /session/key.bin below, and let session.c load it from there at
	 * handshake time. The former /noise/ store is retired.
	 */
	ret = noise_crypto_dh_keygen(x_priv, x_pub);
	if (ret) {
		LOG_ERR("session slot: noise keygen=%d", ret);
		goto out;
	}

	/* P-256 identity (cert-signing) key. */
	ret = crypto_keygen(id_priv, &id_len);
	if (ret || id_len != 32) {
		LOG_ERR("session slot: P-256 keygen=%d len=%zu", ret, id_len);
		ret = ret ? ret : -EIO;
		goto out;
	}

	derive_cn(cn, sizeof(cn));

	ret = ca_build_session_cert(cantil_session_x509_constant,
				    cantil_session_x509_constant_len,
				    cn, id_priv, x_pub, cert, &cert_len);
	if (ret) {
		LOG_ERR("session slot: build cert=%d", ret);
		goto out;
	}

	ret = crypto_storage_key_derive(storage_key);
	if (ret) {
		goto out;
	}

	enc_len = sizeof(enc);
	ret = crypto_encrypt_blob(storage_key, x_priv, 32, enc, &enc_len);
	if (!ret) {
		ret = storage_session_key_write(enc, enc_len);
	}
	if (ret) {
		LOG_ERR("session slot: write key.bin=%d", ret);
		goto out;
	}

	enc_len = sizeof(enc);
	ret = crypto_encrypt_blob(storage_key, id_priv, 32, enc, &enc_len);
	if (!ret) {
		ret = storage_session_id_key_write(enc, enc_len);
	}
	if (ret) {
		LOG_ERR("session slot: write id_key.bin=%d", ret);
		goto out;
	}

	ret = storage_session_cert_write(cert, cert_len);
	if (ret) {
		LOG_ERR("session slot: write cert.der=%d", ret);
		goto out;
	}

	memset(&m, 0, sizeof(m));
	m.version = SESSION_META_VERSION;
	memcpy(m.x25519_pub, x_pub, 32);
	ret = storage_session_meta_write((const uint8_t *)&m, sizeof(m));
	if (ret) {
		LOG_ERR("session slot: write meta.bin=%d", ret);
		goto out;
	}

	LOG_INF("session slot: identity written (%zu B cert), CN=%s",
		cert_len, cn);

out:
	mbedtls_platform_zeroize(x_priv, sizeof(x_priv));
	mbedtls_platform_zeroize(id_priv, sizeof(id_priv));
	mbedtls_platform_zeroize(storage_key, sizeof(storage_key));
	mbedtls_platform_zeroize(enc, sizeof(enc));
	return ret;
}

/*
 * Re-signing rule (T-08): self-signed → CA-signed is free; an already-CA-signed
 * cert refuses any mutation unless force=true. Returns -EEXIST if blocked.
 */
static int check_resign_allowed(uint8_t flags, bool force)
{
	if ((flags & SESSION_META_FLAG_CA_SIGNED) && !force) {
		return -EEXIST;
	}
	return 0;
}

/* Read the full session meta struct, validating version + length. */
static int read_session_meta(session_meta_t *m)
{
	uint8_t buf[sizeof(session_meta_t)];
	size_t  len = sizeof(buf);
	int ret = storage_session_meta_read(buf, &len);

	if (ret) {
		return ret;
	}
	if (len != sizeof(session_meta_t) || buf[0] != SESSION_META_VERSION) {
		return -EINVAL;
	}
	memcpy(m, buf, sizeof(*m));
	return 0;
}

int session_slot_sign_from_slot(uint32_t issuer_slot, bool force)
{
	uint8_t enc[SESSION_ENC_LEN];
	uint8_t id_priv[32];
	uint8_t storage_key[32];
	uint8_t cert[SESSION_CERT_DER_MAX];
	session_meta_t m;
	char    cn[40];
	size_t  enc_len = sizeof(enc);
	size_t  id_len = sizeof(id_priv);
	size_t  cert_len = sizeof(cert);
	int ret;

	/* No session identity yet (pre first-boot init). */
	if (storage_session_cert_exists() != 1) {
		return -ENOENT;
	}

	ret = read_session_meta(&m);
	if (ret) {
		LOG_ERR("session sign: read meta=%d", ret);
		return ret;
	}

	/* Re-signing rule (T-08): self-signed -> CA-signed free; already-CA-signed
	 * requires force. */
	ret = check_resign_allowed(m.flags, force);
	if (ret) {
		LOG_WRN("session sign: cert already CA-signed; force required");
		return ret;
	}

	ret = storage_session_id_key_read(enc, &enc_len);
	if (ret) {
		LOG_ERR("session sign: read id_key.bin=%d", ret);
		return ret;
	}

	ret = crypto_storage_key_derive(storage_key);
	if (ret) {
		goto out;
	}
	ret = crypto_decrypt_blob(storage_key, enc, enc_len, id_priv, &id_len);
	if (ret || id_len != 32) {
		LOG_ERR("session sign: decrypt id key=%d len=%zu", ret, id_len);
		ret = ret ? ret : -EIO;
		goto out;
	}

	derive_cn(cn, sizeof(cn));

	ret = ca_sign_session_cert(issuer_slot,
				   cantil_session_x509_constant,
				   cantil_session_x509_constant_len,
				   cn, id_priv, m.x25519_pub, cert, &cert_len);
	if (ret) {
		LOG_ERR("session sign: ca_sign_session_cert slot %u=%d",
			issuer_slot, ret);
		goto out;
	}

	ret = storage_session_cert_write(cert, cert_len);
	if (ret) {
		LOG_ERR("session sign: write cert.der=%d", ret);
		goto out;
	}

	/* Latch the CA-signed marker so a future re-sign requires force. */
	m.flags |= SESSION_META_FLAG_CA_SIGNED;
	ret = storage_session_meta_write((const uint8_t *)&m, sizeof(m));
	if (ret) {
		LOG_ERR("session sign: write meta.bin=%d", ret);
		goto out;
	}

	LOG_INF("session cert re-signed by slot %u (%zu B)", issuer_slot,
		cert_len);
	ret = 0;

out:
	mbedtls_platform_zeroize(id_priv, sizeof(id_priv));
	mbedtls_platform_zeroize(storage_key, sizeof(storage_key));
	mbedtls_platform_zeroize(enc, sizeof(enc));
	return ret;
}

int session_slot_push_cert(const uint8_t *cert, size_t cert_len,
			   const uint8_t *chain, size_t chain_len, bool force)
{
	uint8_t enc[SESSION_ENC_LEN];
	uint8_t id_priv[32];
	uint8_t storage_key[32];
	uint8_t id_pub[65];
	uint8_t x25519_pub[32];
	session_meta_t m;
	size_t  enc_len = sizeof(enc);
	size_t  id_len = sizeof(id_priv);
	size_t  pub_len = sizeof(id_pub);
	bool    ca_signed = false;
	int ret;

	if (cert == NULL || cert_len == 0) {
		return -EINVAL;
	}

	/* No session identity yet (pre first-boot init). */
	if (storage_session_cert_exists() != 1) {
		return -ENOENT;
	}

	ret = read_session_meta(&m);
	if (ret) {
		LOG_ERR("session push: read meta=%d", ret);
		return ret;
	}

	/* Re-signing rule (T-08). */
	ret = check_resign_allowed(m.flags, force);
	if (ret) {
		LOG_WRN("session push: cert already CA-signed; force required");
		return ret;
	}

	ret = session_slot_get_pubkey(x25519_pub);
	if (ret) {
		return ret;
	}

	/* Derive the device's P-256 identity pubkey for the SPKI gate. */
	ret = storage_session_id_key_read(enc, &enc_len);
	if (ret) {
		LOG_ERR("session push: read id_key.bin=%d", ret);
		return ret;
	}
	ret = crypto_storage_key_derive(storage_key);
	if (ret) {
		goto out;
	}
	ret = crypto_decrypt_blob(storage_key, enc, enc_len, id_priv, &id_len);
	if (ret || id_len != 32) {
		LOG_ERR("session push: decrypt id key=%d len=%zu", ret, id_len);
		ret = ret ? ret : -EIO;
		goto out;
	}
	ret = crypto_pubkey_from_privkey(id_priv, id_len, id_pub, &pub_len);
	if (ret || pub_len != 65) {
		LOG_ERR("session push: derive id pubkey=%d", ret);
		ret = ret ? ret : -EIO;
		goto out;
	}

	ret = ca_validate_pushed_session_cert(cert, cert_len, chain, chain_len,
					      id_pub, x25519_pub,
					      cantil_session_x509_constant,
					      cantil_session_x509_constant_len,
					      &ca_signed);
	if (ret) {
		LOG_WRN("session push: validation failed=%d", ret);
		goto out;
	}

	ret = storage_session_cert_write(cert, cert_len);
	if (ret) {
		LOG_ERR("session push: write cert.der=%d", ret);
		goto out;
	}

	/* Persist (or clear) the issuer chain so msg2 can serve it. */
	if (chain != NULL && chain_len > 0) {
		ret = storage_session_chain_write(chain, chain_len);
	} else {
		ret = storage_session_chain_delete();
	}
	if (ret) {
		LOG_ERR("session push: write/clear chain.der=%d", ret);
		goto out;
	}

	/* Latch the CA-signed marker to match the installed cert. A self-signed
	 * push clears it (a force re-push could revert CA-signed -> self). */
	if (ca_signed) {
		m.flags |= SESSION_META_FLAG_CA_SIGNED;
	} else {
		m.flags &= ~(uint8_t)SESSION_META_FLAG_CA_SIGNED;
	}
	ret = storage_session_meta_write((const uint8_t *)&m, sizeof(m));
	if (ret) {
		LOG_ERR("session push: write meta.bin=%d", ret);
		goto out;
	}

	LOG_INF("session cert pushed (%zu B, %s, chain %zu B)", cert_len,
		ca_signed ? "CA-signed" : "self-signed", chain_len);
	ret = 0;

out:
	mbedtls_platform_zeroize(id_priv, sizeof(id_priv));
	mbedtls_platform_zeroize(storage_key, sizeof(storage_key));
	mbedtls_platform_zeroize(enc, sizeof(enc));
	return ret;
}

int session_slot_get_pubkey(uint8_t pub[32])
{
	uint8_t buf[sizeof(session_meta_t)];
	size_t  len = sizeof(buf);
	int ret = storage_session_meta_read(buf, &len);

	if (ret) {
		return ret;
	}
	if (len != sizeof(session_meta_t) || buf[0] != SESSION_META_VERSION) {
		return -EINVAL;
	}
	memcpy(pub, buf + offsetof(session_meta_t, x25519_pub), 32);
	return 0;
}

int session_slot_get_cert(uint8_t *der, size_t *len)
{
	return storage_session_cert_read(der, len);
}

int session_slot_get_csr(uint8_t *der, size_t *len)
{
	uint8_t enc[SESSION_ENC_LEN];
	uint8_t id_priv[32];
	uint8_t storage_key[32];
	uint8_t x_pub[32];
	char    cn[40];
	size_t  enc_len = sizeof(enc);
	size_t  id_len = sizeof(id_priv);
	int ret;

	/* No session identity yet (pre first-boot init). */
	if (storage_session_cert_exists() != 1) {
		return -ENOENT;
	}

	ret = session_slot_get_pubkey(x_pub);
	if (ret) {
		return ret;
	}

	ret = storage_session_id_key_read(enc, &enc_len);
	if (ret) {
		LOG_ERR("session csr: read id_key.bin=%d", ret);
		return ret;
	}

	ret = crypto_storage_key_derive(storage_key);
	if (ret) {
		goto out;
	}
	ret = crypto_decrypt_blob(storage_key, enc, enc_len, id_priv, &id_len);
	if (ret || id_len != 32) {
		LOG_ERR("session csr: decrypt id key=%d len=%zu", ret, id_len);
		ret = ret ? ret : -EIO;
		goto out;
	}

	derive_cn(cn, sizeof(cn));

	ret = ca_build_session_csr(cantil_session_x509_constant,
				   cantil_session_x509_constant_len,
				   cn, id_priv, x_pub, der, len);
	if (ret) {
		LOG_ERR("session csr: build=%d", ret);
		goto out;
	}

	/* Persist for the record (storage layout: /session/csr.der). A write
	 * failure is non-fatal — the freshly-built CSR is already in *der. */
	int w = storage_session_csr_write(der, *len);

	if (w) {
		LOG_WRN("session csr: persist csr.der=%d (returning anyway)", w);
	}

out:
	mbedtls_platform_zeroize(id_priv, sizeof(id_priv));
	mbedtls_platform_zeroize(storage_key, sizeof(storage_key));
	mbedtls_platform_zeroize(enc, sizeof(enc));
	return ret;
}
