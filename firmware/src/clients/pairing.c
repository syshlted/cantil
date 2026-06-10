/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

/*
 * Device-side pairing gate — transport + pairing T-16/T-17/T-18/T-19/T-20.
 *
 * Called with the verified Noise_XX initiator static pubkey after the
 * handshake completes.  Returns 0 to open the session, negative errno
 * to reject it (caller must close the session).
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <errno.h>
#include <string.h>

#include "pairing.h"
#include "clients/client_bond.h"
#include "gesture/gesture.h"

LOG_MODULE_REGISTER(pairing, LOG_LEVEL_INF);

/* ══════════════════════════════════════════════════════════════════════════
 * Shared passkey helpers — compiled for Method 3 and Method 5.
 * ══════════════════════════════════════════════════════════════════════════ */

#if defined(CONFIG_PAIRING_PASSKEY) || defined(CONFIG_PAIRING_CA_ANCHOR_PLUS_PASSKEY)

#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>

#include "led/led.h"
#include "crypto/crypto.h"
#include "session/session.h"
#include "storage/storage.h"
#include "cantil_cbor.h"
#include "protocol/protocol.h"

static K_SEM_DEFINE(pair_sem, 0, 1);
static cantil_confirm_result_t pair_result;

static void pair_cb(cantil_confirm_result_t result, void *user_data)
{
	ARG_UNUSED(user_data);
	pair_result = result;
	k_sem_give(&pair_sem);
}

#ifdef CONFIG_ZTEST
/* Weak hook: test suites override this to intercept the generated passkey
 * and prime the session stub with the correct reply before session_recv(). */
__weak void pairing_test_passkey_hook(uint32_t pk) { ARG_UNUSED(pk); }
#endif

/*
 * Generate a random 6-digit passkey (000001–999999, never 000000).
 * Returns the passkey value on success, 0 on RNG failure (caller rejects).
 */
static uint32_t generate_passkey(void)
{
	uint32_t val = 0;

	for (int attempt = 0; attempt < 8; attempt++) {
		uint8_t raw[4];

		if (crypto_trng(raw, sizeof(raw)) != 0) {
			continue;
		}
		val = ((uint32_t)raw[0] << 24 | (uint32_t)raw[1] << 16 |
		       (uint32_t)raw[2] << 8  | (uint32_t)raw[3]);
		val = val % 1000000U;
		if (val != 0) {
			return val;
		}
	}
	return 0;
}

/*
 * Blink the 6-digit passkey digit-by-digit using the existing BLE passkey
 * LED scheme: N white flashes for digit N, 1000 ms inter-group pause.
 * Leading zeros are blinked as 10 flashes so they're distinguishable.
 * Blocking — called from the session thread before entering the recv wait.
 */
static void blink_passkey(uint32_t passkey)
{
	uint8_t digits[6];

	digits[0] = (passkey / 100000U) % 10;
	digits[1] = (passkey / 10000U)  % 10;
	digits[2] = (passkey / 1000U)   % 10;
	digits[3] = (passkey / 100U)    % 10;
	digits[4] = (passkey / 10U)     % 10;
	digits[5] =  passkey            % 10;

	for (int i = 0; i < 6; i++) {
		uint8_t d = (digits[i] == 0) ? 10 : digits[i];

		led_blink_digit(d);
		if (CONFIG_CANTIL_PASSKEY_BLINK_PAUSE_MS > 0) {
			k_msleep(CONFIG_CANTIL_PASSKEY_BLINK_PAUSE_MS);
		}
	}
}

/*
 * Derive a 32-byte PSK from the 6-digit passkey and the two static pubkeys.
 *   IKM  = passkey as 4-byte big-endian
 *   salt = local_pub || remote_pub   (64 bytes)
 *   info = "cantil-psk-v1"
 */
static int derive_psk(uint8_t psk[32], uint32_t passkey,
		      const uint8_t local_pub[32], const uint8_t remote_pub[32])
{
	uint8_t ikm[4] = {
		(uint8_t)(passkey >> 24), (uint8_t)(passkey >> 16),
		(uint8_t)(passkey >> 8),  (uint8_t)(passkey)
	};
	uint8_t salt[64];

	memcpy(salt, local_pub, 32);
	memcpy(salt + 32, remote_pub, 32);

	static const uint8_t info[] = "cantil-psk-v1";
	int rc = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
			      salt, sizeof(salt),
			      ikm, sizeof(ikm),
			      info, sizeof(info) - 1,
			      psk, 32);

	return rc ? -EIO : 0;
}

/* Send a CBOR response for CMD_PAIRING_PASSKEY_REPLY. */
static void send_reply(cantil_session_t *session, uint32_t seq, uint32_t err)
{
	uint8_t buf[16];
	int n = cantil_cbor_encode_response(buf, sizeof(buf), seq, err, NULL, 0);

	if (n > 0) {
		(void)session_send(session, buf, (size_t)n);
	}
}

/*
 * Shared passkey exchange: blink + recv + validate + tap-confirm + PSK store.
 * Returns 0 on success, negative errno on failure.
 * On success, the bond has been committed and the PSK stored.
 * seq_out receives the sequence number for the final send_reply() call.
 */
static int passkey_exchange_and_bond(const uint8_t pub[32],
				     cantil_session_t *session)
{
	uint32_t passkey = generate_passkey();

	if (passkey == 0) {
		LOG_ERR("pairing: passkey generation failed (RNG error)");
		return -EACCES;
	}
	LOG_INF("pairing: generated passkey %06u", passkey);

#ifdef CONFIG_ZTEST
	pairing_test_passkey_hook(passkey);
#endif

	led_set_idle(LED_PATTERN_PASSKEY_PROMPT);
	blink_passkey(passkey);

	/* Wait for CMD_PAIRING_PASSKEY_REPLY from the client. */
	static uint8_t rx_buf[64];
	size_t rx_len;
	int rc = session_recv(session, rx_buf, sizeof(rx_buf), &rx_len);

	if (rc) {
		LOG_WRN("pairing: passkey recv error %d (timeout or transport error)", rc);
		return -EACCES;
	}

	uint32_t cmd = 0, seq = 0;
	const uint8_t *data = NULL;
	size_t data_len = 0;

	if (cantil_cbor_decode_request(rx_buf, rx_len, &cmd, &seq,
				       &data, &data_len) != 0) {
		LOG_WRN("pairing: passkey reply malformed CBOR");
		send_reply(session, 0, ERR_INVALID_ARGS);
		return -EACCES;
	}

	if (cmd != CMD_PAIRING_PASSKEY_REPLY) {
		LOG_WRN("pairing: expected passkey reply (0x73), got 0x%02x", cmd);
		send_reply(session, seq, ERR_PASSKEY_REQUIRED);
		return -EACCES;
	}

	if (!data || data_len == 0) {
		LOG_WRN("pairing: passkey reply missing digit data");
		send_reply(session, seq, ERR_INVALID_ARGS);
		return -EACCES;
	}

	size_t off = 0;
	uint32_t received_passkey = 0;

	if (cantil_cbor_read_uint32(data, data_len, &off, &received_passkey) != 0) {
		LOG_WRN("pairing: passkey reply digit parse error");
		send_reply(session, seq, ERR_INVALID_ARGS);
		return -EACCES;
	}

	if (received_passkey != passkey) {
		LOG_WRN("pairing: passkey mismatch (got %06u, expected %06u)",
			received_passkey, passkey);
		send_reply(session, seq, ERR_AUTH);
		return -EACCES;
	}

	LOG_INF("pairing: passkey correct — waiting for tap-confirm");

	rc = gesture_request_pair_confirm(pair_cb, NULL);
	if (rc == -EBUSY || rc == -EALREADY) {
		LOG_WRN("pairing: gesture busy (%d) — rejecting", rc);
		send_reply(session, seq, ERR_BUSY);
		return -EACCES;
	}
	if (rc) {
		LOG_ERR("pairing: gesture_request_pair_confirm error %d", rc);
		send_reply(session, seq, ERR_BUSY);
		return -EACCES;
	}

	k_sem_take(&pair_sem, K_FOREVER);

	if (pair_result != CANTIL_CONFIRM_OK) {
		LOG_INF("pairing: tap-confirm not received (result=%d) — rejecting",
			pair_result);
		send_reply(session, seq, ERR_AUTH);
		return -EACCES;
	}

	/* Derive PSK from passkey + static pubkeys. */
	uint8_t local_pub[32];

	if (session_get_local_pubkey(session, local_pub) != 0) {
		LOG_ERR("pairing: cannot get local pubkey for PSK derivation");
		send_reply(session, seq, ERR_CRYPTO);
		return -EACCES;
	}

	uint8_t psk[32];

	rc = derive_psk(psk, passkey, local_pub, pub);
	memset(local_pub, 0, sizeof(local_pub));
	if (rc) {
		LOG_ERR("pairing: PSK derivation failed %d", rc);
		memset(psk, 0, sizeof(psk));
		send_reply(session, seq, ERR_CRYPTO);
		return -EACCES;
	}

	uint8_t storage_key[32];

	rc = crypto_storage_key_derive(storage_key);
	if (rc) {
		LOG_ERR("pairing: storage key derivation failed %d", rc);
		memset(psk, 0, sizeof(psk));
		send_reply(session, seq, ERR_CRYPTO);
		return -EACCES;
	}

	uint8_t psk_enc[12 + 32 + 16];
	size_t psk_enc_len = sizeof(psk_enc);

	rc = crypto_encrypt_blob(storage_key, psk, sizeof(psk),
				 psk_enc, &psk_enc_len);
	memset(storage_key, 0, sizeof(storage_key));
	memset(psk, 0, sizeof(psk));

	if (rc) {
		LOG_ERR("pairing: PSK encrypt failed %d", rc);
		send_reply(session, seq, ERR_CRYPTO);
		return -EACCES;
	}

	/* Commit the bond. */
	rc = client_bond_add(pub, CLIENT_KIND_HOST, 0 /* no RTC timestamp */);
	if (rc != 0 && rc != -EEXIST) {
		LOG_ERR("pairing: client_bond_add error %d", rc);
		send_reply(session, seq, ERR_STORAGE);
		return -EACCES;
	}

	uint8_t id[4];

	client_bond_id(pub, id);
	rc = storage_client_bond_psk_write(id, psk_enc, psk_enc_len);
	if (rc) {
		LOG_ERR("pairing: PSK store error %d", rc);
		/* Bond committed without PSK — not fatal for connectivity. */
	}

	send_reply(session, seq, ERR_OK);
	return 0;
}

#endif /* CONFIG_PAIRING_PASSKEY || CONFIG_PAIRING_CA_ANCHOR_PLUS_PASSKEY */

/* ══════════════════════════════════════════════════════════════════════════
 * Per-method pairing_check_and_bond() implementations.
 * ══════════════════════════════════════════════════════════════════════════ */

#if defined(CONFIG_PAIRING_PASSKEY)

int pairing_check_and_bond(const uint8_t pub[32], cantil_session_t *session)
{
	int rc = client_bond_exists(pub);

	if (rc == 1) {
		LOG_INF("pairing: known client");
		return 0;
	}
	if (rc < 0) {
		LOG_ERR("pairing: bond lookup error %d", rc);
		return rc;
	}

	/* Check cap before prompting — fail fast if no room. */
	uint32_t hosts = 0, peers = 0;

	rc = client_bond_count(&hosts, &peers);
	if (rc == 0 && hosts >= CONFIG_CANTIL_MAX_CLIENT_BONDS) {
		LOG_WRN("pairing: bond cap full — rejecting unknown client");
		return -EACCES;
	}

	rc = passkey_exchange_and_bond(pub, session);
	if (rc == 0) {
		LOG_INF("pairing: Method 3 — new client bonded with PSK");
	}
	return rc;
}

#elif defined(CONFIG_PAIRING_TAP_CONFIRM)

static K_SEM_DEFINE(pair_sem, 0, 1);
static cantil_confirm_result_t pair_result;

static void pair_cb(cantil_confirm_result_t result, void *user_data)
{
	ARG_UNUSED(user_data);
	pair_result = result;
	k_sem_give(&pair_sem);
}

int pairing_check_and_bond(const uint8_t pub[32], cantil_session_t *session)
{
	ARG_UNUSED(session);

	int rc = client_bond_exists(pub);

	if (rc == 1) {
		LOG_INF("pairing: known client");
		return 0;
	}
	if (rc < 0) {
		LOG_ERR("pairing: bond lookup error %d", rc);
		return rc;
	}

	/* Check cap before prompting — fail fast if no room. */
	uint32_t hosts = 0, peers = 0;

	rc = client_bond_count(&hosts, &peers);
	if (rc == 0 && hosts >= CONFIG_CANTIL_MAX_CLIENT_BONDS) {
		LOG_WRN("pairing: bond cap full — rejecting unknown client without prompt");
		return -EACCES;
	}

	/* Unknown client — enter AWAITING_PAIR and wait for tap-confirm. */
	LOG_INF("pairing: unknown client — prompting for tap-confirm");
	rc = gesture_request_pair_confirm(pair_cb, NULL);
	if (rc == -EBUSY || rc == -EALREADY) {
		LOG_WRN("pairing: gesture busy (%d) — rejecting", rc);
		return -EACCES;
	}
	if (rc) {
		LOG_ERR("pairing: gesture_request_pair_confirm error %d", rc);
		return -EACCES;
	}

	k_sem_take(&pair_sem, K_FOREVER);

	if (pair_result != CANTIL_CONFIRM_OK) {
		LOG_INF("pairing: tap-confirm not received (result=%d) — rejecting",
			pair_result);
		return -EACCES;
	}

	/* User confirmed — commit the bond. */
	rc = client_bond_add(pub, CLIENT_KIND_HOST, 0 /* no RTC timestamp */);
	if (rc == 0) {
		LOG_INF("pairing: tap-confirmed — new client bonded");
		return 0;
	}
	if (rc == -EEXIST) {
		return 0;
	}
	if (rc == -ENOSPC) {
		LOG_WRN("pairing: bond cap full after confirm — rejecting");
	} else {
		LOG_ERR("pairing: client_bond_add error %d — rejecting", rc);
	}
	return -EACCES;
}

#elif defined(CONFIG_PAIRING_TOFU)

int pairing_check_and_bond(const uint8_t pub[32], cantil_session_t *session)
{
	ARG_UNUSED(session);

	int rc = client_bond_exists(pub);

	if (rc == 1) {
		LOG_INF("pairing: known client");
		return 0;
	}
	if (rc < 0) {
		LOG_ERR("pairing: bond lookup error %d", rc);
		return rc;
	}

	/* Unknown client — attempt silent TOFU bond. */
	rc = client_bond_add(pub, CLIENT_KIND_HOST, 0 /* no RTC timestamp */);
	if (rc == 0) {
		LOG_INF("pairing: TOFU — new client bonded");
		return 0;
	}
	if (rc == -EEXIST) {
		return 0;
	}
	if (rc == -ENOSPC) {
		LOG_WRN("pairing: bond cap full — rejecting unknown client");
	} else {
		LOG_ERR("pairing: client_bond_add error %d — rejecting", rc);
	}
	return -EACCES;
}

#elif defined(CONFIG_PAIRING_CA_ANCHOR)

#include "ca/ca.h"

int pairing_check_and_bond(const uint8_t pub[32], cantil_session_t *session)
{
	ARG_UNUSED(pub);

	/* Method 4: client must have provided a cert chain on msg3. */
	size_t cert_count = session_get_client_cert_count(session);

	if (cert_count == 0) {
		LOG_WRN("pairing: Method 4 — no client cert in msg3, rejecting");
		return -EACCES;
	}

	const uint8_t *cert_ders[4];
	size_t         cert_lens[4];

	if (cert_count > ARRAY_SIZE(cert_ders)) {
		LOG_WRN("pairing: Method 4 — too many certs (%zu)", cert_count);
		return -EACCES;
	}

	for (size_t i = 0; i < cert_count; i++) {
		if (session_get_client_cert(session, i,
					    &cert_ders[i], &cert_lens[i]) != 0) {
			LOG_ERR("pairing: cannot read client cert[%zu]", i);
			return -EACCES;
		}
	}

	int rc = ca_validate_client_cert_chain(cert_ders, cert_lens, cert_count,
					       CONFIG_CANTIL_CA_ANCHOR_SLOT);

	if (rc == -ENOENT) {
		LOG_WRN("pairing: Method 4 — anchor slot %u has no cert",
			CONFIG_CANTIL_CA_ANCHOR_SLOT);
		return -EACCES;
	}
	if (rc != 0) {
		LOG_WRN("pairing: Method 4 — client cert chain invalid (%d)", rc);
		return -EACCES;
	}

	LOG_INF("pairing: Method 4 — CA-anchored client accepted (no bond)");
	return 0;
}

#elif defined(CONFIG_PAIRING_CA_ANCHOR_PLUS_PASSKEY)

#include "ca/ca.h"
#include "session/session.h"

int pairing_check_and_bond(const uint8_t pub[32], cantil_session_t *session)
{
	/* Step 1: already-bonded client (completed a previous Method 5 pairing). */
	int rc = client_bond_exists(pub);

	if (rc == 1) {
		LOG_INF("pairing: known client");
		return 0;
	}
	if (rc < 0) {
		LOG_ERR("pairing: bond lookup error %d", rc);
		return rc;
	}

	/* Step 2: validate client cert chain — must be present and anchor-signed. */
	size_t cert_count = session_get_client_cert_count(session);

	if (cert_count == 0) {
		LOG_WRN("pairing: Method 5 — no client cert in msg3, rejecting");
		return -EACCES;
	}

	const uint8_t *cert_ders[4];
	size_t         cert_lens[4];

	if (cert_count > ARRAY_SIZE(cert_ders)) {
		LOG_WRN("pairing: Method 5 — too many certs (%zu)", cert_count);
		return -EACCES;
	}

	for (size_t i = 0; i < cert_count; i++) {
		if (session_get_client_cert(session, i,
					    &cert_ders[i], &cert_lens[i]) != 0) {
			LOG_ERR("pairing: cannot read client cert[%zu]", i);
			return -EACCES;
		}
	}

	rc = ca_validate_client_cert_chain(cert_ders, cert_lens, cert_count,
					   CONFIG_CANTIL_CA_ANCHOR_SLOT);
	if (rc == -ENOENT) {
		LOG_WRN("pairing: Method 5 — anchor slot %u has no cert",
			CONFIG_CANTIL_CA_ANCHOR_SLOT);
		return -EACCES;
	}
	if (rc != 0) {
		LOG_WRN("pairing: Method 5 — client cert chain invalid (%d)", rc);
		return -EACCES;
	}

	/* Step 3: cap check before passkey prompt. */
	uint32_t hosts = 0, peers = 0;

	rc = client_bond_count(&hosts, &peers);
	if (rc == 0 && hosts >= CONFIG_CANTIL_MAX_CLIENT_BONDS) {
		LOG_WRN("pairing: bond cap full — rejecting unknown client");
		return -EACCES;
	}

	/* Step 4: passkey exchange + tap-confirm + PSK bond (Method 3 part). */
	rc = passkey_exchange_and_bond(pub, session);
	if (rc == 0) {
		LOG_INF("pairing: Method 5 — CA-anchored client bonded with PSK");
	}
	return rc;
}

#else  /* PAIRING_PROMISCUOUS (development only) */

/* T-21: Kconfig already prevents PAIRING_PROMISCUOUS when
 * CANTIL_SESSION_X509_STRICT=y (release builds), but assert here as
 * defense-in-depth against accidental config drift. */
BUILD_ASSERT(!IS_ENABLED(CONFIG_CANTIL_SESSION_X509_STRICT),
	     "PAIRING_PROMISCUOUS must not be used in release builds "
	     "(CONFIG_CANTIL_SESSION_X509_STRICT=y)");

int pairing_check_and_bond(const uint8_t pub[32], cantil_session_t *session)
{
	ARG_UNUSED(pub);
	ARG_UNUSED(session);
	return 0;
}

#endif
