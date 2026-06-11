#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/reboot.h>
#include <string.h>

#if IS_ENABLED(CONFIG_CANTIL_BOOTLOADER_MCUBOOT)
#include "fw_update/fw_update.h"
#else
#include <hal/nrf_power.h>
#define DFU_MAGIC_UF2_RESET 0x57
#endif

#include "protocol.h"
#include "gesture/gesture.h"
#include "session/session_slot.h"
#include "ca/ca.h"
#include "clients/client_bond.h"
#include "crypto/crypto.h"
#include "led/led.h"
#include "names/names.h"
#include "storage/storage.h"
#include "cantil_cbor.h"

#define CANTIL_FW_MAJOR 0
#define CANTIL_FW_MINOR 1
#define CANTIL_FW_PATCH 0

/*
 * DEVICE_STATUS wire layout (26 bytes, big-endian multi-byte fields).
 * Mirrors libcantil/include/cantil.h:cantil_status_t field-for-field.
 *
 *   off  len  field
 *     0   1   fw_major
 *     1   1   fw_minor
 *     2   1   fw_patch
 *     3   1   locked              (1 if state == LOCKED, else 0)
 *     4   4   certs_issued        (lifetime — TODO: persist; currently == certs_stored)
 *     8   4   certs_stored        (entries under /certs/)
 *    12   4   key_slots_used      (slots with key.bin present)
 *    16   4   key_slots_total     (CONFIG_CANTIL_MAX_KEY_SLOTS)
 *    20   4   flash_free_kb       (fs_statvfs)
 *    24   1   ble_bonds           (0 for now)
 *    25   1   has_external_flash  (CONFIG_CANTIL_STORAGE_EXTERNAL)
 */
#define STATUS_WIRE_LEN 26

static inline void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >>  8);
	p[3] = (uint8_t)(v);
}

LOG_MODULE_REGISTER(protocol, LOG_LEVEL_INF);

/*
 * CBOR wire format (length-prefixed inside Noise session):
 *   Request:  { "cmd": uint, "seq": uint, "data": bstr? }
 *   Response: { "err": uint, "seq": uint, "data": bstr? }
 * See common/cbor/cantil_cbor.{h,c} and docs/ca/01-cbor-foundation.md.
 */

#define MSG_BUF_SIZE 4096

static uint8_t rx_buf[MSG_BUF_SIZE];
static uint8_t tx_buf[MSG_BUF_SIZE];

/* --- Command handlers --- */

static cantil_err_t handle_sign_csr(const uint8_t *req, size_t req_len,
				   uint8_t *resp, size_t *resp_len)
{
	return ca_sign_csr(req, req_len, resp, resp_len) == 0
		? ERR_OK : ERR_CRYPTO;
}

static cantil_err_t handle_get_ca_cert(uint8_t *resp, size_t *resp_len)
{
	return ca_get_cert(resp, resp_len) == 0 ? ERR_OK : ERR_STORAGE;
}

static cantil_err_t handle_device_status(uint8_t *resp, size_t *resp_len)
{
	if (*resp_len < STATUS_WIRE_LEN) {
		return ERR_INVALID_ARGS;
	}

	cantil_state_t s = gesture_get_state();
	uint32_t slots_used = 0, certs_stored = 0, flash_free = 0;

	(void)storage_count_slots_used(&slots_used);
	(void)storage_count_issued_certs(&certs_stored);
	(void)storage_free_kb(&flash_free);

	resp[0] = CANTIL_FW_MAJOR;
	resp[1] = CANTIL_FW_MINOR;
	resp[2] = CANTIL_FW_PATCH;
	resp[3] = (s == CANTIL_STATE_LOCKED) ? 1 : 0;
	put_be32(&resp[4],  certs_stored);                  /* certs_issued — TODO lifetime */
	put_be32(&resp[8],  certs_stored);
	put_be32(&resp[12], slots_used);
	put_be32(&resp[16], CONFIG_CANTIL_MAX_KEY_SLOTS);
	put_be32(&resp[20], flash_free);
	resp[24] = 0;                                       /* ble_bonds — TODO */
	resp[25] = IS_ENABLED(CONFIG_CANTIL_STORAGE_EXTERNAL) ? 1 : 0;
	*resp_len = STATUS_WIRE_LEN;
	return ERR_OK;
}

static cantil_err_t handle_get_random(const uint8_t *req, size_t req_len,
				     uint8_t *resp, size_t *resp_len)
{
	if (req_len < 2) {
		return ERR_INVALID_ARGS;
	}
	uint16_t n = ((uint16_t)req[0] << 8) | req[1];

	if (n > *resp_len) {
		return ERR_INVALID_ARGS;
	}
	if (crypto_trng(resp, n)) {
		return ERR_CRYPTO;
	}
	*resp_len = n;
	return ERR_OK;
}

static cantil_err_t handle_get_random_names(const uint8_t *req, size_t req_len,
					   uint8_t *resp, size_t *resp_len)
{
	if (req_len < 2) {
		return ERR_INVALID_ARGS;
	}
	uint16_t count = ((uint16_t)req[0] << 8) | req[1];

	int written = names_get_random_batch(count, resp, *resp_len);
	if (written < 0) {
		return ERR_CRYPTO;
	}
	*resp_len = (size_t)written;
	return ERR_OK;
}

/* --- Slot protect/unprotect tap-confirm sync (semaphore + callback) --- */

static K_SEM_DEFINE(protect_confirm_sem, 0, 1);
static cantil_confirm_result_t protect_confirm_result;

static void protect_confirm_cb(cantil_confirm_result_t result, void *user_data)
{
	ARG_UNUSED(user_data);
	protect_confirm_result = result;
	k_sem_give(&protect_confirm_sem);
}

/* Block until the user taps the confirm gesture (or denies / times out).
 * Returns ERR_OK on confirmation, ERR_BUSY otherwise. */
static cantil_err_t await_protect_confirm(void)
{
	int rc = gesture_request_confirm(protect_confirm_cb, NULL);

	if (rc == -EBUSY || rc == -EALREADY) return ERR_BUSY;
	if (rc) return ERR_INVALID_CMD;

	k_sem_take(&protect_confirm_sem, K_FOREVER);
	if (protect_confirm_result != CANTIL_CONFIRM_OK) {
		LOG_INF("protect/unprotect denied (result=%d)",
			protect_confirm_result);
		return ERR_BUSY;
	}
	return ERR_OK;
}

/* --- Reset confirm state (semaphore-based sync with gesture callback) --- */

static K_SEM_DEFINE(reset_confirm_sem, 0, 1);
static cantil_confirm_result_t reset_confirm_result;

static void reset_confirm_cb(cantil_confirm_result_t result, void *user_data)
{
	ARG_UNUSED(user_data);
	reset_confirm_result = result;
	k_sem_give(&reset_confirm_sem);
}

static cantil_err_t handle_reset_device(cantil_session_t *session,
				       uint32_t seq)
{
	int ret = gesture_request_reset(reset_confirm_cb, NULL);

	if (ret == -EBUSY) {
		return ERR_BUSY;
	}
	if (ret) {
		return ERR_INVALID_CMD;
	}

	/* Send an immediate ACK so the client knows the confirm prompt is
	 * active.  The client then waits for disconnect (reboot). */
	uint8_t ack[32];
	int ack_len = cantil_cbor_encode_response(ack, sizeof(ack), seq, ERR_OK,
						  NULL, 0);
	if (ack_len > 0) {
		(void)session_send(session, ack, (size_t)ack_len);
	}

	/* Block until the gesture callback fires (confirm, deny, or timeout). */
	k_sem_take(&reset_confirm_sem, K_FOREVER);

	if (reset_confirm_result != CANTIL_CONFIRM_OK) {
		LOG_INF("reset denied (result=%d)", reset_confirm_result);
		return ERR_BUSY;
	}

	LOG_WRN("reset confirmed — wiping and rebooting");
	led_set_idle(LED_PATTERN_RESET_WIPING);
	storage_secure_wipe();
	led_play_oneshot(LED_PATTERN_RESET_COMPLETE);
	k_msleep(3000);
	sys_reboot(SYS_REBOOT_COLD);

	return ERR_OK; /* unreachable */
}

/* --- UPDATE_FIRMWARE handler --- */

#if IS_ENABLED(CONFIG_CANTIL_BOOTLOADER_MCUBOOT)

/*
 * Decode the UPDATE_FIRMWARE sub-operation from the CBOR data field.
 *
 * Wire format (inner CBOR map):
 *   BEGIN:  {0: 0, 1: total_size (uint32)}
 *   CHUNK:  {0: 1, 1: offset (uint32), 2: <bstr chunk_data>}
 *   COMMIT: {0: 2}
 *
 * Returns the sub-op on success (0/1/2), negative errno on malformed input.
 * Outputs total_size / offset / chunk* from the relevant fields.
 */
static int decode_fw_op(const uint8_t *data, size_t data_len,
			uint32_t *total_size_out,
			uint32_t *offset_out,
			const uint8_t **chunk_out, size_t *chunk_len_out)
{
	if (!data || data_len < 2) return -EINVAL;

	size_t off = 0;
	uint8_t major;
	uint64_t val;

	/* Expect a CBOR map */
	if (cantil_cbor_read_head(data, data_len, &off, &major, &val) != 0)
		return -EINVAL;
	if (major != CANTIL_CBOR_MT_MAP) return -EINVAL;
	uint32_t nkeys = (uint32_t)val;
	if (nkeys < 1 || nkeys > 3) return -EINVAL;

	uint32_t sub_op = UINT32_MAX;
	*total_size_out = 0;
	*offset_out = 0;
	*chunk_out = NULL;
	*chunk_len_out = 0;

	for (uint32_t i = 0; i < nkeys; i++) {
		uint32_t key;
		if (cantil_cbor_read_uint32(data, data_len, &off, &key) != 0)
			return -EINVAL;

		switch (key) {
		case 0: /* sub_op */
			if (cantil_cbor_read_uint32(data, data_len, &off,
						    &sub_op) != 0)
				return -EINVAL;
			break;
		case 1: /* total_size (BEGIN) or offset (CHUNK) */
			if (cantil_cbor_read_uint32(data, data_len, &off,
						    total_size_out) != 0)
				return -EINVAL;
			*offset_out = *total_size_out; /* reuse for CHUNK */
			break;
		case 2: /* chunk data (CHUNK) */
			if (cantil_cbor_read_bstr(data, data_len, &off,
						  chunk_out, chunk_len_out) != 0)
				return -EINVAL;
			break;
		default:
			return -EINVAL;
		}
	}

	if (sub_op > 2) return -EINVAL;
	return (int)sub_op;
}

/* Confirm state for the commit tap-confirm */
static K_SEM_DEFINE(fw_commit_sem, 0, 1);
static cantil_confirm_result_t fw_commit_result;

static void fw_commit_cb(cantil_confirm_result_t result, void *user_data)
{
	ARG_UNUSED(user_data);
	fw_commit_result = result;
	k_sem_give(&fw_commit_sem);
}

static cantil_err_t handle_update_firmware(cantil_session_t *session,
					   uint32_t seq,
					   const uint8_t *data, size_t data_len)
{
	uint32_t total_size = 0, offset = 0;
	const uint8_t *chunk = NULL;
	size_t chunk_len = 0;

	int sub_op = decode_fw_op(data, data_len, &total_size, &offset,
				  &chunk, &chunk_len);
	if (sub_op < 0) {
		return ERR_FW_UPDATE_ARGS;
	}

	switch ((uint32_t)sub_op) {

	case FW_UPDATE_OP_BEGIN: {
		int rc = fw_update_begin(total_size);
		if (rc == -EBUSY)  return ERR_FW_UPDATE_BUSY;
		if (rc == -EFBIG)  return ERR_FW_UPDATE_ARGS;
		if (rc)            return ERR_FW_UPDATE_FLASH;
		return ERR_OK;
	}

	case FW_UPDATE_OP_CHUNK: {
		if (!chunk || chunk_len == 0 ||
		    chunk_len > CONFIG_CANTIL_FW_CHUNK_MAX)
			return ERR_FW_UPDATE_ARGS;
		int rc = fw_update_chunk(offset, chunk, chunk_len);
		if (rc == -ENODEV) return ERR_FW_UPDATE_ARGS;
		if (rc == -ERANGE) return ERR_FW_UPDATE_ARGS;
		if (rc)            return ERR_FW_UPDATE_FLASH;
		return ERR_OK;
	}

	case FW_UPDATE_OP_COMMIT: {
		int rc = fw_update_close();
		if (rc == -ENODEV) return ERR_FW_UPDATE_ARGS;
		if (rc)            return ERR_FW_UPDATE_FLASH;

		/* Request tap-confirm before marking the image as pending. */
		rc = gesture_request_confirm(fw_commit_cb, NULL);
		if (rc == -EBUSY || rc == -EALREADY) {
			fw_update_abort();
			return ERR_BUSY;
		}
		if (rc) {
			fw_update_abort();
			return ERR_INVALID_CMD;
		}

		/* Send ACK so client knows to wait for tap. */
		uint8_t ack[32];
		int ack_len = cantil_cbor_encode_response(ack, sizeof(ack),
							  seq, ERR_OK,
							  NULL, 0);
		if (ack_len > 0) {
			(void)session_send(session, ack, (size_t)ack_len);
		}

		k_sem_take(&fw_commit_sem, K_FOREVER);

		if (fw_commit_result != CANTIL_CONFIRM_OK) {
			LOG_INF("fw_update: commit denied by user");
			fw_update_abort();
			return ERR_BUSY;
		}

		rc = fw_update_set_pending();
		if (rc) {
			fw_update_abort();
			return ERR_FW_UPDATE_FLASH;
		}

		LOG_WRN("fw_update: reboot to install new image");
		led_play_oneshot(LED_PATTERN_FW_APPLIED);
		k_msleep(1100); /* play the full 1 s oneshot */
		sys_reboot(SYS_REBOOT_COLD);
		return ERR_OK; /* unreachable */
	}

	default:
		return ERR_FW_UPDATE_ARGS;
	}
}

#else /* UF2 path */

static cantil_err_t handle_update_firmware(cantil_session_t *session,
					   uint32_t seq,
					   const uint8_t *data, size_t data_len)
{
	ARG_UNUSED(data);
	ARG_UNUSED(data_len);

	/* Send ACK before rebooting so the client knows the reboot is coming. */
	uint8_t ack[32];
	int ack_len = cantil_cbor_encode_response(ack, sizeof(ack), seq,
						  ERR_OK, NULL, 0);
	if (ack_len > 0) {
		(void)session_send(session, ack, (size_t)ack_len);
	}

	LOG_WRN("UPDATE_FIRMWARE: rebooting into UF2 bootloader (GPREGRET=0x57)");
	k_msleep(50);
	nrf_power_gpregret_set(NRF_POWER, 0, DFU_MAGIC_UF2_RESET);
	sys_reboot(SYS_REBOOT_WARM);
	return ERR_OK; /* unreachable */
}

#endif /* CONFIG_CANTIL_BOOTLOADER_MCUBOOT */

/* --- Dispatcher --- */

int protocol_handle_one(cantil_session_t *session)
{
	size_t rx_len = sizeof(rx_buf);
	int ret = session_recv(session, rx_buf, sizeof(rx_buf), &rx_len);

	if (ret) {
		return ret;
	}

	uint32_t cmd = 0, seq = 0;
	size_t data_len = 0;
	const uint8_t *data = NULL;

	if (cantil_cbor_decode_request(rx_buf, rx_len, &cmd, &seq,
				       &data, &data_len) != 0) {
		/* Malformed CBOR — return INVALID_CMD with seq=0 so the client
		 * sees a parseable error rather than a closed session. */
		uint8_t err_resp[16];
		int n = cantil_cbor_encode_response(err_resp, sizeof(err_resp),
						    0, ERR_INVALID_CMD,
						    NULL, 0);
		if (n > 0) {
			(void)session_send(session, err_resp, (size_t)n);
		}
		return 0;
	}

	cantil_state_t state = gesture_get_state();
	uint8_t resp_data[MSG_BUF_SIZE - 2];
	size_t resp_data_len = sizeof(resp_data);
	cantil_err_t err = ERR_OK;

	/* Identity-recovery mode (T-03): the stored session cert no longer
	 * matches the build constant under strict mode. Refuse every opcode
	 * except DEVICE_STATUS (so the client can see the device),
	 * RESET_DEVICE (a wipe always recovers), and UPDATE_FIRMWARE (lets
	 * the user push a corrected image without wiping first).
	 * ACCEPT_IDENTITY_MIGRATION joins this allowlist once implemented. */
	if (session_slot_in_recovery() &&
	    cmd != CMD_DEVICE_STATUS && cmd != CMD_RESET_DEVICE &&
	    cmd != CMD_UPDATE_FIRMWARE) {
		err = ERR_IDENTITY_MISMATCH;
		resp_data_len = 0;
		goto send;
	}

	/* DEVICE_STATUS is always allowed; RESET_DEVICE is allowed while
	 * locked unless CONFIG_CANTIL_RESET_REQUIRES_UNLOCK is set. */
	if (state == CANTIL_STATE_LOCKED && cmd != CMD_DEVICE_STATUS &&
	    cmd != CMD_UPDATE_FIRMWARE &&
	    !(cmd == CMD_RESET_DEVICE &&
	      !IS_ENABLED(CONFIG_CANTIL_RESET_REQUIRES_UNLOCK))) {
		err = ERR_DEVICE_LOCKED;
		resp_data_len = 0;
		goto send;
	}

	switch ((cantil_cmd_t)cmd) {
	case CMD_SIGN_CSR:
		err = handle_sign_csr(data, data_len, resp_data, &resp_data_len);
		break;
	case CMD_GET_CA_CERT:
		err = handle_get_ca_cert(resp_data, &resp_data_len);
		break;
	case CMD_GET_CA_CHAIN: {
		uint32_t slot = 0;

		if (data_len == 4) {
			slot = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
			       ((uint32_t)data[2] <<  8) |  (uint32_t)data[3];
		} else if (data_len != 0) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		int rc = ca_get_chain_slot(slot, resp_data, &resp_data_len);

		if (rc == 0)              err = ERR_OK;
		else if (rc == -ENOENT)   err = ERR_NOT_FOUND;
		else if (rc == -EINVAL)   err = ERR_INVALID_ARGS;
		else                      err = ERR_STORAGE;
		break;
	}
	case CMD_GET_CA_SERIAL:
		err = (ca_get_serial(resp_data, &resp_data_len) == 0) ? ERR_OK : ERR_STORAGE;
		break;
	case CMD_GET_CA_CSR:
		err = (ca_get_csr(resp_data, &resp_data_len) == 0) ? ERR_OK : ERR_STORAGE;
		break;
	case CMD_GET_SESSION_CERT: {
		resp_data_len = sizeof(resp_data);
		int rc = session_slot_get_cert(resp_data, &resp_data_len);

		if (rc == 0)            err = ERR_OK;
		else if (rc == -ENOENT) err = ERR_NOT_FOUND;
		else                    err = ERR_STORAGE;
		if (err != ERR_OK)      resp_data_len = 0;
		break;
	}
	case CMD_GET_SESSION_CSR: {
		resp_data_len = sizeof(resp_data);
		int rc = session_slot_get_csr(resp_data, &resp_data_len);

		if (rc == 0)               err = ERR_OK;
		else if (rc == -ENOENT)    err = ERR_NOT_FOUND;
		else if (rc == -EINVAL)    err = ERR_INVALID_ARGS;
		else if (rc == -ENOMEM)    err = ERR_STORAGE;
		else                       err = ERR_CRYPTO;
		if (err != ERR_OK)         resp_data_len = 0;
		break;
	}
	case CMD_SIGN_SESSION_FROM_SLOT: {
		/* BE u32 issuer_slot + 1-byte force flag. Tap-confirm gated:
		 * the session cert is the device's identity to the world. */
		if (data_len < 5) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		uint32_t issuer_slot = ((uint32_t)data[0] << 24) |
				       ((uint32_t)data[1] << 16) |
				       ((uint32_t)data[2] <<  8) |
					(uint32_t)data[3];
		bool force = data[4] ? true : false;

		/* T-09: session slot is not in /keys/N/; any out-of-range value
		 * (including a hypothetical session sentinel) is refused before
		 * the tap-confirm so a bad issuer wastes no gesture. */
		if (issuer_slot >= CONFIG_CANTIL_MAX_KEY_SLOTS) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}

		err = await_protect_confirm();
		if (err == ERR_OK) {
			int rc = session_slot_sign_from_slot(issuer_slot, force);

			if (rc == 0)              err = ERR_OK;
			else if (rc == -ENOENT)   err = ERR_NOT_FOUND;
			else if (rc == -EEXIST)   err = ERR_INVALID_ARGS; /* force needed */
			else if (rc == -EINVAL)   err = ERR_INVALID_ARGS;
			else if (rc == -ENOMEM)   err = ERR_STORAGE;
			else                      err = ERR_CRYPTO;
		}
		resp_data_len = 0;
		break;
	}
	case CMD_PUSH_SESSION_CERT: {
		/* Layout: 1-byte force || BE u16 cert_len || cert DER || chain DER.
		 * Tap-confirm gated — installs the device's identity to the world. */
		if (data_len < 3) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		bool force = data[0] ? true : false;
		uint16_t cert_len = ((uint16_t)data[1] << 8) | data[2];

		if (3 + (size_t)cert_len > data_len) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		const uint8_t *cert = data + 3;
		const uint8_t *chain = (data_len > 3 + (size_t)cert_len) ?
				       data + 3 + cert_len : NULL;
		size_t chain_len = data_len - 3 - cert_len;

		err = await_protect_confirm();
		if (err == ERR_OK) {
			int rc = session_slot_push_cert(cert, cert_len,
							chain, chain_len, force);

			if (rc == 0)              err = ERR_OK;
			else if (rc == -ENOENT)   err = ERR_NOT_FOUND;
			else if (rc == -EEXIST)   err = ERR_INVALID_ARGS; /* force needed */
			else if (rc == -EINVAL)   err = ERR_INVALID_ARGS;
			else if (rc == -ENOMEM)   err = ERR_STORAGE;
			else                      err = ERR_CRYPTO;
		}
		resp_data_len = 0;
		break;
	}
	case CMD_PUSH_CA_CERT:
		err = (ca_push_cert(data, data_len, NULL, 0) == 0) ? ERR_OK : ERR_STORAGE;
		resp_data_len = 0;
		break;
	case CMD_LIST_CERTS:
		err = (ca_list_certs(resp_data, &resp_data_len) == 0) ? ERR_OK : ERR_STORAGE;
		break;
	case CMD_GET_CERT:
		err = (ca_get_issued_cert(data, data_len, resp_data, &resp_data_len) == 0)
			? ERR_OK : ERR_NOT_FOUND;
		break;
	case CMD_GET_CERT_COUNT: {
		uint32_t count = 0;
		err = (ca_get_cert_count(&count) == 0) ? ERR_OK : ERR_STORAGE;
		resp_data[0] = (count >> 24) & 0xFF;
		resp_data[1] = (count >> 16) & 0xFF;
		resp_data[2] = (count >>  8) & 0xFF;
		resp_data[3] = count & 0xFF;
		resp_data_len = 4;
		break;
	}
	case CMD_AUTO_EXPIRE: {
		if (data_len < 8) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		uint64_t now =
			((uint64_t)data[0] << 56) | ((uint64_t)data[1] << 48) |
			((uint64_t)data[2] << 40) | ((uint64_t)data[3] << 32) |
			((uint64_t)data[4] << 24) | ((uint64_t)data[5] << 16) |
			((uint64_t)data[6] <<  8) |  (uint64_t)data[7];
		uint32_t count = 0;
		err = (ca_auto_expire(now, &count) == 0) ? ERR_OK : ERR_STORAGE;
		resp_data[0] = (count >> 24) & 0xFF;
		resp_data[1] = (count >> 16) & 0xFF;
		resp_data[2] = (count >>  8) & 0xFF;
		resp_data[3] = count & 0xFF;
		resp_data_len = 4;
		break;
	}
	case CMD_REVOKE_CERT: {
		/*
		 * Wire (task 2): serial_len(1) + serial[serial_len]
		 *                + [now_unix BE u64]? (8 trailing bytes optional)
		 * The trailing timestamp is required iff
		 * CONFIG_CANTIL_REVOKE_REQUIRE_NOW_UNIX=y.
		 */
		if (data_len < 2) {  /* at least 1-byte length prefix + 1-byte serial */
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		size_t sl = data[0];
		if (sl == 0 || sl > 20 || sl + 1 > data_len) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		const uint8_t *serial = &data[1];
		size_t tail = data_len - 1 - sl;
		uint64_t now_unix = 0;
		if (tail == 8) {
			now_unix =
			    ((uint64_t)data[1+sl] << 56) | ((uint64_t)data[2+sl] << 48) |
			    ((uint64_t)data[3+sl] << 40) | ((uint64_t)data[4+sl] << 32) |
			    ((uint64_t)data[5+sl] << 24) | ((uint64_t)data[6+sl] << 16) |
			    ((uint64_t)data[7+sl] <<  8) |  (uint64_t)data[8+sl];
		} else if (tail != 0) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
#ifdef CONFIG_CANTIL_REVOKE_REQUIRE_NOW_UNIX
		if (tail != 8 || now_unix == 0) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
#endif
		int rc = ca_revoke_cert(serial, sl, now_unix);
		if      (rc == 0)         err = ERR_OK;
		else if (rc == -EINVAL)   err = ERR_INVALID_ARGS;
		else if (rc == -EACCES)   err = ERR_INVALID_ARGS;
		else if (rc == -ENOENT)   err = ERR_NOT_FOUND;
		else if (rc == -EALREADY) err = ERR_INVALID_ARGS;
		else                      err = ERR_STORAGE;
		resp_data_len = 0;
		break;
	}
	case CMD_GET_CRL: {
		/* Wire (task 2): BE u32 slot + BE u64 now_unix → DER CRL */
		if (data_len != 12) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		uint32_t slot =
			((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
			((uint32_t)data[2] <<  8) |  (uint32_t)data[3];
		uint64_t now =
			((uint64_t)data[4] << 56) | ((uint64_t)data[5] << 48) |
			((uint64_t)data[6] << 40) | ((uint64_t)data[7] << 32) |
			((uint64_t)data[8] << 24) | ((uint64_t)data[9] << 16) |
			((uint64_t)data[10]<<  8) |  (uint64_t)data[11];
		/* T-09: CRL issuer must be a numbered /keys/N/ slot. */
		if (slot >= CONFIG_CANTIL_MAX_KEY_SLOTS) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		int rc = ca_get_crl(slot, now, resp_data, &resp_data_len);
		if      (rc == 0)        err = ERR_OK;
		else if (rc == -EINVAL)  err = ERR_INVALID_ARGS;
		else if (rc == -ENOENT)  err = ERR_NOT_FOUND;
		else if (rc == -ENOMEM)  err = ERR_STORAGE;
		else                     err = ERR_STORAGE;
		if (rc) resp_data_len = 0;
		break;
	}
	case CMD_LIST_KEYS:
		err = (ca_list_keys(resp_data, &resp_data_len) == 0) ? ERR_OK : ERR_STORAGE;
		break;
	case CMD_GEN_KEY: {
		uint32_t slot_id = 0;
		int rc = ca_gen_key(data_len > 0 ? data[0] : 0, &slot_id);
		if (rc == 0)               err = ERR_OK;
		else if (rc == -ENOSPC)    err = ERR_NO_SLOTS;
		else if (rc == -ENOTSUP)   err = ERR_INVALID_ARGS;
		else if (rc == -EINVAL)    err = ERR_INVALID_ARGS;
		else                       err = ERR_CRYPTO;
		resp_data[0] = (slot_id >> 24) & 0xFF;
		resp_data[1] = (slot_id >> 16) & 0xFF;
		resp_data[2] = (slot_id >>  8) & 0xFF;
		resp_data[3] = slot_id & 0xFF;
		resp_data_len = 4;
		break;
	}
	case CMD_PROTECT_SLOT: {
		if (data_len < 5) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		uint32_t slot_id = ((uint32_t)data[0] << 24) |
				   ((uint32_t)data[1] << 16) |
				   ((uint32_t)data[2] <<  8) |
				    (uint32_t)data[3];
		bool protect_issued = data[4] ? true : false;
		err = await_protect_confirm();
		if (err == ERR_OK) {
			int rc = ca_protect_slot(slot_id, protect_issued);
			if (rc == -ENOENT)       err = ERR_NOT_FOUND;
			else if (rc == -EINVAL)  err = ERR_INVALID_ARGS;
			else if (rc)             err = ERR_STORAGE;
		}
		resp_data_len = 0;
		break;
	}
	case CMD_UNPROTECT_SLOT: {
		if (data_len < 4) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		uint32_t slot_id = ((uint32_t)data[0] << 24) |
				   ((uint32_t)data[1] << 16) |
				   ((uint32_t)data[2] <<  8) |
				    (uint32_t)data[3];
		err = await_protect_confirm();
		if (err == ERR_OK) {
			int rc = ca_unprotect_slot(slot_id);
			if (rc == -ENOENT)       err = ERR_NOT_FOUND;
			else if (rc == -EINVAL)  err = ERR_INVALID_ARGS;
			else if (rc)             err = ERR_STORAGE;
		}
		resp_data_len = 0;
		break;
	}
	case CMD_DELETE_KEY: {
		if (data_len < 4) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		uint32_t slot_id = ((uint32_t)data[0] << 24) |
				   ((uint32_t)data[1] << 16) |
				   ((uint32_t)data[2] <<  8) |
				    (uint32_t)data[3];
		int rc = ca_delete_key(slot_id);
		if (rc == 0)               err = ERR_OK;
		else if (rc == -EPERM)     err = ERR_DEVICE_LOCKED;
		else if (rc == -EACCES)    err = ERR_DEVICE_LOCKED;
		else if (rc == -ENOENT)    err = ERR_NOT_FOUND;
		else if (rc == -EINVAL)    err = ERR_INVALID_ARGS;
		else                       err = ERR_STORAGE;
		resp_data_len = 0;
		break;
	}
	case CMD_GEN_KEY_CSR: {
		if (data_len < 5) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		uint32_t slot_id = ((uint32_t)data[0] << 24) |
				   ((uint32_t)data[1] << 16) |
				   ((uint32_t)data[2] <<  8) |
				    (uint32_t)data[3];
		/* DN follows as a NUL-terminated UTF-8 string. */
		size_t dn_max = data_len - 4;
		char dn[256];

		if (dn_max == 0 || dn_max >= sizeof(dn)) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		memcpy(dn, data + 4, dn_max);
		dn[dn_max] = '\0';
		int rc = ca_gen_key_csr(slot_id, dn);
		if (rc == 0)               err = ERR_OK;
		else if (rc == -ENOENT)    err = ERR_NOT_FOUND;
		else if (rc == -EINVAL)    err = ERR_INVALID_ARGS;
		else                       err = ERR_CRYPTO;
		resp_data_len = 0;
		break;
	}
	case CMD_GET_KEY_CSR: {
		if (data_len < 4) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		uint32_t slot_id = ((uint32_t)data[0] << 24) |
				   ((uint32_t)data[1] << 16) |
				   ((uint32_t)data[2] <<  8) |
				    (uint32_t)data[3];
		int rc = ca_get_key_csr(slot_id, resp_data, &resp_data_len);
		if (rc == 0)               err = ERR_OK;
		else if (rc == -ENOENT)    err = ERR_NOT_FOUND;
		else                       err = ERR_STORAGE;
		if (rc) resp_data_len = 0;
		break;
	}
	case CMD_SIGN_CSR_SLOT: {
		/* Layout: BE u32 issuer_slot || CSR DER */
		if (data_len < 5) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		uint32_t issuer = ((uint32_t)data[0] << 24) |
				  ((uint32_t)data[1] << 16) |
				  ((uint32_t)data[2] <<  8) |
				   (uint32_t)data[3];
		/* T-09: session slot is not in /keys/N/; refuse any out-of-range
		 * issuer at the dispatcher before reaching ca_sign_csr_slot. */
		if (issuer >= CONFIG_CANTIL_MAX_KEY_SLOTS) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		int rc = ca_sign_csr_slot(issuer, data + 4, data_len - 4,
					  resp_data, &resp_data_len);
		if (rc == 0)             err = ERR_OK;
		else if (rc == -ENOENT)  err = ERR_NOT_FOUND;
		else if (rc == -EINVAL)  err = ERR_INVALID_ARGS;
		else                     err = ERR_CRYPTO;
		if (rc) resp_data_len = 0;
		break;
	}
	case CMD_SIGN_KEY_SLOT: {
		/* Layout: BE u32 issuer_slot || BE u32 subject_slot */
		if (data_len < 8) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		uint32_t issuer  = ((uint32_t)data[0] << 24) |
				   ((uint32_t)data[1] << 16) |
				   ((uint32_t)data[2] <<  8) |
				    (uint32_t)data[3];
		uint32_t subject = ((uint32_t)data[4] << 24) |
				   ((uint32_t)data[5] << 16) |
				   ((uint32_t)data[6] <<  8) |
				    (uint32_t)data[7];
		/* T-09: refuse session slot as issuer; subject checked inside
		 * ca_sign_key_slot (it can legitimately be any populated slot). */
		if (issuer >= CONFIG_CANTIL_MAX_KEY_SLOTS) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		int rc = ca_sign_key_slot(issuer, subject);
		if (rc == 0)              err = ERR_OK;
		else if (rc == -ENOENT)   err = ERR_NOT_FOUND;
		else if (rc == -EINVAL)   err = ERR_INVALID_ARGS;
		else                      err = ERR_CRYPTO;
		resp_data_len = 0;
		break;
	}
	case CMD_PUSH_KEY_CERT: {
		/* Layout: BE u32 slot || BE u16 cert_len || cert DER || chain DER */
		if (data_len < 6) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		uint32_t slot_id = ((uint32_t)data[0] << 24) |
				   ((uint32_t)data[1] << 16) |
				   ((uint32_t)data[2] <<  8) |
				    (uint32_t)data[3];
		uint16_t cert_len = ((uint16_t)data[4] << 8) | data[5];

		if (6 + (size_t)cert_len > data_len) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		const uint8_t *cert = data + 6;
		const uint8_t *chain = (data_len > 6 + (size_t)cert_len) ?
				       data + 6 + cert_len : NULL;
		size_t chain_len = data_len - 6 - cert_len;

		int rc = ca_push_key_cert(slot_id, cert, cert_len,
					  chain, chain_len);
		if (rc == 0)               err = ERR_OK;
		else if (rc == -EACCES)    err = ERR_DEVICE_LOCKED;
		else if (rc == -ENOENT)    err = ERR_NOT_FOUND;
		else if (rc == -EINVAL)    err = ERR_INVALID_ARGS;
		else                       err = ERR_CRYPTO;
		resp_data_len = 0;
		break;
	}
	case CMD_PUSH_KEY_X509: {
		if (data_len < 4) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		uint32_t slot_id = ((uint32_t)data[0] << 24) |
				   ((uint32_t)data[1] << 16) |
				   ((uint32_t)data[2] <<  8) |
				   ((uint32_t)data[3]);
		int rc = ca_push_key_x509(slot_id, data + 4, data_len - 4);

		if (rc == 0) {
			err = ERR_OK;
		} else if (rc == -EACCES) {
			err = ERR_DEVICE_LOCKED;   /* protected slot, no confirm yet */
		} else if (rc == -EINVAL) {
			err = ERR_INVALID_ARGS;
		} else {
			err = ERR_CRYPTO;
		}
		resp_data_len = 0;
		break;
	}
	case CMD_SET_UNLOCK_SEQ: {
		if (!data || data_len == 0) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		int rc = gesture_set_unlock_seq(data, (uint8_t)data_len);

		if (rc == -EBUSY) {
			err = ERR_BUSY;
		} else if (rc == -EINVAL) {
			err = ERR_INVALID_ARGS;
		} else if (rc) {
			err = ERR_STORAGE;
		}
		resp_data_len = 0;
		break;
	}
	case CMD_RESET_DEVICE:
		err = handle_reset_device(session, seq);
		if (err == ERR_OK) {
			return 0; /* unreachable — device rebooted */
		}
		resp_data_len = 0;
		break;
	case CMD_DEVICE_STATUS:
		err = handle_device_status(resp_data, &resp_data_len);
		break;
	case CMD_GET_RANDOM:
		err = handle_get_random(data, data_len, resp_data, &resp_data_len);
		break;
	case CMD_GET_RANDOM_NAMES:
		err = handle_get_random_names(data, data_len, resp_data, &resp_data_len);
		break;

	/* T-15: Client bond management (0x70–0x72). */
	case CMD_LIST_CLIENTS: {
		int rc = client_bond_list_cbor(resp_data, &resp_data_len);
		if (rc == 0)               err = ERR_OK;
		else if (rc == -ENOMEM)    err = ERR_STORAGE;
		else                       err = ERR_STORAGE;
		if (rc) resp_data_len = 0;
		break;
	}
	case CMD_UNPAIR_CLIENT: {
		if (data_len != 32) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		err = await_protect_confirm();
		if (err == ERR_OK) {
			int rc = client_bond_remove(data);
			if (rc == -ENOENT) err = ERR_NOT_FOUND;
			else if (rc)       err = ERR_STORAGE;
		}
		resp_data_len = 0;
		break;
	}
	case CMD_SET_CLIENT_NAME: {
		/* Layout: 32 B pubkey || UTF-8 name (1–31 bytes, no null required on wire) */
		if (data_len < 33 || data_len > 32 + CLIENT_META_NAME_MAX - 1) {
			err = ERR_INVALID_ARGS;
			resp_data_len = 0;
			break;
		}
		char name[CLIENT_META_NAME_MAX];
		size_t name_len = data_len - 32;
		memcpy(name, data + 32, name_len);
		name[name_len] = '\0';
		int rc = client_bond_set_name(data, name);
		if (rc == -ENOENT)      err = ERR_NOT_FOUND;
		else if (rc == -EINVAL) err = ERR_INVALID_ARGS;
		else if (rc)            err = ERR_STORAGE;
		resp_data_len = 0;
		break;
	}
	case CMD_UPDATE_FIRMWARE:
		err = handle_update_firmware(session, seq, data, data_len);
		if (err == ERR_OK) {
			return 0; /* unreachable — device rebooted */
		}
		resp_data_len = 0;
		break;
	default:
		err = ERR_INVALID_CMD;
		resp_data_len = 0;
		break;
	}

send:
	;
	int tx_len = cantil_cbor_encode_response(tx_buf, sizeof(tx_buf),
						 seq, err,
						 resp_data_len > 0 ? resp_data : NULL,
						 resp_data_len);
	if (tx_len <= 0) {
		LOG_ERR("response encode failed: %d", tx_len);
		return -ENOMEM;
	}
	return session_send(session, tx_buf, (size_t)tx_len);
}
