#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/hwinfo.h>

#include "gesture/gesture.h"
#include "led/led.h"
#include "storage/storage.h"
#include "crypto/crypto.h"
#include "transport/transport.h"
#include "session/session.h"
#include "session/session_slot.h"
#include "protocol/protocol.h"
#include "ca/ca.h"
#include "clients/pairing.h"
#if IS_ENABLED(CONFIG_CANTIL_BOOTLOADER_MCUBOOT)
#include "fw_update/fw_update.h"
#endif

LOG_MODULE_REGISTER(cantil, LOG_LEVEL_INF);

int main(void)
{
	int ret;

	/* The "did we reach main?" blink is now the POST one-shot emitted
	 * by led_init() / led_play_oneshot(LED_PATTERN_POST) below. */
	LOG_INF("cantil starting");

	/* Log the nRF52840 FICR DEVICEID so the serial output unambiguously
	 * identifies which physical board this is (matches USB iSerial). */
	{
		uint8_t id[8];
		ssize_t n = hwinfo_get_device_id(id, sizeof(id));
		if (n == sizeof(id)) {
			LOG_INF("device serial: %02X%02X%02X%02X%02X%02X%02X%02X",
				id[0], id[1], id[2], id[3],
				id[4], id[5], id[6], id[7]);
		} else {
			LOG_WRN("hwinfo_get_device_id -> %d", (int)n);
		}
	}

	ret = crypto_init();
	if (ret) {
		LOG_ERR("crypto_init failed: %d", ret);
		return ret;
	}

	ret = led_init();
	if (ret) {
		LOG_ERR("led_init failed: %d", ret);
		return ret;
	}

	/*
	 * Initialize transport BEFORE storage so USB enumerates while
	 * storage_init() formats the flash (first boot: ~23 s for 2 MB erase).
	 * The USB power-cycle in transport_usb_init() must complete before
	 * the QSPI flash driver starts issuing long erase commands.
	 */
	ret = transport_init();
	if (ret) {
		LOG_ERR("transport_init failed: %d", ret);
		return ret;
	}

	/* Storage may take a long time on first boot (full flash format). */
	ret = storage_init();
	if (ret) {
		LOG_ERR("storage_init failed: %d — CA ops unavailable", ret);
	} else {
		ret = ca_init();
		if (ret) {
			LOG_ERR("ca_init failed: %d", ret);
		}

		/* Transport identity (Noise static key + self-signed cert). */
		ret = session_slot_init();
		if (ret) {
			LOG_ERR("session_slot_init failed: %d", ret);
		}
	}

	/*
	 * Gesture init runs AFTER storage_init() so gesture_init() can read the
	 * persisted unlock sequence from the mounted filesystem. (Before, it ran
	 * ahead of the mount and silently fell back to the factory default,
	 * making a customized unlock sequence never survive a reboot.)
	 */
	ret = gesture_init();
	if (ret) {
		LOG_ERR("gesture_init failed: %d", ret);
		return ret;
	}

#if IS_ENABLED(CONFIG_CANTIL_BOOTLOADER_MCUBOOT)
	fw_update_boot_check();
#endif

	led_play_oneshot(LED_PATTERN_POST);
	if (session_slot_in_recovery()) {
		led_set_idle(LED_PATTERN_IDENTITY_MISMATCH);
		LOG_ERR("session identity mismatch — RECOVERY mode "
			"(only DEVICE_STATUS / RESET_DEVICE accepted)");
	} else {
		led_set_idle(LED_PATTERN_LOCKED);
		LOG_INF("ready — device is LOCKED");
	}

	while (1) {
		cantil_transport_t *t = transport_get_active();

		if (t != NULL) {
			cantil_session_t *session = NULL;

			/* Flush any stale bytes left by a previous session or
			 * by a failed pair attempt (each leaves ~50 B DEVICE_STATUS
			 * frame in the UART RX buffer). The client waits 700 ms
			 * before sending msg1, so bytes present here are residual. */
			k_msleep(50);
			transport_usb_flush_rx();

			ret = session_open(t, NULL, &session);
			if (ret) {
				LOG_WRN("session_open failed: %d", ret);
				k_msleep(100);
				continue;
			}

			/* Pairing gate: check/bond the authenticated client. */
			{
				uint8_t remote_pub[32];

				if (session_get_remote_pubkey(session,
							      remote_pub) == 0) {
					ret = pairing_check_and_bond(remote_pub, session);
					if (ret) {
						LOG_WRN("pairing rejected: %d",
							ret);
						session_close(session);
						k_msleep(100);
						continue;
					}
				}
			}

			LOG_INF("Noise_XX handshake complete");
			gesture_reset_inactivity_timer();

			while (1) {
				ret = protocol_handle_one(session);
				if (ret) {
					LOG_INF("session closed: %d", ret);
					break;
				}
				gesture_reset_inactivity_timer();
			}

			session_close(session);
		}

		k_msleep(10);
	}

	return 0;
}
