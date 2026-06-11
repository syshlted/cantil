#include "fw_update.h"

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/dfu/mcuboot.h>

#include "led/led.h"
#include "gesture/gesture.h"
#include "storage/storage.h"

LOG_MODULE_REGISTER(fw_update, LOG_LEVEL_INF);

/* ── Update-in-progress state ──────────────────────────────────────────────── */

static enum { FW_IDLE, FW_OPEN, FW_CLOSED } update_state = FW_IDLE;
static uint32_t update_total_size;
static const struct flash_area *update_fa;

int fw_update_begin(uint32_t total_size)
{
	if (update_state != FW_IDLE) {
		return -EBUSY;
	}
	if (total_size == 0 || total_size > CONFIG_CANTIL_FW_SLOT_SIZE) {
		return -EFBIG;
	}

	int rc = flash_area_open(FIXED_PARTITION_ID(mcuboot_secondary), &update_fa);
	if (rc) {
		LOG_ERR("flash_area_open secondary: %d", rc);
		return -EIO;
	}

	LOG_INF("fw_update: erasing secondary slot (%u B)", total_size);
	rc = flash_area_erase(update_fa, 0, update_fa->fa_size);
	if (rc) {
		LOG_ERR("flash_area_erase: %d", rc);
		flash_area_close(update_fa);
		update_fa = NULL;
		return -EIO;
	}

	update_total_size = total_size;
	update_state = FW_OPEN;
	LOG_INF("fw_update: secondary slot open, expecting %u bytes", total_size);
	return 0;
}

int fw_update_chunk(uint32_t offset, const uint8_t *data, size_t len)
{
	if (update_state != FW_OPEN) {
		return -ENODEV;
	}
	if ((uint64_t)offset + len > update_total_size) {
		return -ERANGE;
	}

	int rc = flash_area_write(update_fa, offset, data, len);
	if (rc) {
		LOG_ERR("flash_area_write @0x%x +%zu: %d", offset, len, rc);
		return -EIO;
	}
	return 0;
}

int fw_update_close(void)
{
	if (update_state != FW_OPEN) {
		return -ENODEV;
	}
	flash_area_close(update_fa);
	update_fa = NULL;
	update_state = FW_CLOSED;
	LOG_INF("fw_update: flash area closed");
	return 0;
}

int fw_update_set_pending(void)
{
	int rc = storage_fw_pending_set();
	if (rc) {
		LOG_ERR("fw_update: failed to write pending sentinel: %d", rc);
	}

	rc = boot_request_upgrade(BOOT_UPGRADE_TEST);
	if (rc) {
		LOG_ERR("fw_update: boot_request_upgrade: %d", rc);
		(void)storage_fw_pending_clear();
		return rc;
	}

	update_state = FW_IDLE;
	LOG_INF("fw_update: MCUboot upgrade pending — reboot to install");
	return 0;
}

void fw_update_abort(void)
{
	if (update_state == FW_IDLE) {
		return;
	}
	if (update_state == FW_OPEN && update_fa != NULL) {
		LOG_INF("fw_update: aborting — erasing secondary slot");
		(void)flash_area_erase(update_fa, 0, update_fa->fa_size);
		flash_area_close(update_fa);
		update_fa = NULL;
	}
	update_state = FW_IDLE;
}

/* ── Boot-time outcome check ───────────────────────────────────────────────── */

static K_SEM_DEFINE(boot_confirm_sem, 0, 1);
static cantil_confirm_result_t boot_confirm_result;

static void boot_confirm_cb(cantil_confirm_result_t result, void *user_data)
{
	ARG_UNUSED(user_data);
	boot_confirm_result = result;
	k_sem_give(&boot_confirm_sem);
}

static void erase_secondary(void)
{
	const struct flash_area *fa;

	if (flash_area_open(FIXED_PARTITION_ID(mcuboot_secondary), &fa) == 0) {
		(void)flash_area_erase(fa, 0, fa->fa_size);
		flash_area_close(fa);
	}
}

void fw_update_boot_check(void)
{
	int pending = storage_fw_pending_check();

	if (pending <= 0) {
		return;
	}

	/* Sentinel is present — we rebooted to install a new image. */
	storage_fw_pending_clear();

	if (!boot_is_img_confirmed()) {
		/* MCUboot swapped in the new image and it's running now. Confirm
		 * it so it becomes permanent (no revert on next reboot). */
		(void)boot_write_img_confirmed();
		LOG_INF("fw_update: new image confirmed");
		led_play_oneshot(LED_PATTERN_FW_APPLIED);
		return;
	}

	/* Current image is already confirmed — MCUboot did not swap, meaning
	 * it rejected the staged image (bad signature or header). */
	LOG_WRN("fw_update: staged image rejected by MCUboot — prompting user");
	led_set_idle(LED_PATTERN_FW_INVALID);

	int rc = gesture_request_confirm(boot_confirm_cb, NULL);
	if (rc == -EBUSY || rc == -EALREADY) {
		LOG_WRN("fw_update: gesture busy, treating as denied");
		goto denied;
	}

	k_sem_take(&boot_confirm_sem,
		   K_SECONDS(CONFIG_CANTIL_FW_INVALID_CONFIRM_TIMEOUT_SEC));

	led_set_idle(LED_PATTERN_OFF);

	if (boot_confirm_result != CANTIL_CONFIRM_OK) {
		goto denied;
	}

	/* User confirmed installing the rejected image anyway. */
	LOG_WRN("fw_update: user confirmed invalid image install");

#if IS_ENABLED(CONFIG_CANTIL_FW_UPDATE_WIPE_ON_INVALID)
	LOG_WRN("fw_update: wiping storage before forced install");
	led_set_idle(LED_PATTERN_RESET_WIPING);
	(void)storage_secure_wipe();
#endif

	/* Force-install: set pending again and reboot. */
	(void)storage_fw_pending_set();
	rc = boot_request_upgrade(BOOT_UPGRADE_TEST);
	if (rc) {
		LOG_ERR("fw_update: boot_request_upgrade (force): %d — aborting", rc);
		erase_secondary();
		(void)storage_fw_pending_clear();
	} else {
		LOG_WRN("fw_update: rebooting to force-install rejected image");
		k_msleep(100);
		sys_reboot(SYS_REBOOT_COLD);
	}
	return;

denied:
	LOG_INF("fw_update: rejected image install denied/timed-out — erasing secondary");
	erase_secondary();
}
