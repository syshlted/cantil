/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

/*
 * Step-1 factory image.
 *
 * Creates the LittleFS volume on the Cantil storage partition, writes its
 * identity marker, and stops. It generates no keys and holds no secrets.
 *
 * Why this is a separate binary at all: production is built with
 * CONFIG_FILE_SYSTEM_MKFS=n, so lfs_format is not linked into it and no bug,
 * error path, or compromised command handler can format the volume that holds
 * an unexportable CA key. The ability to format has to live somewhere, so it
 * lives here — in an image an operator flashes deliberately, once, at a bench.
 *
 * ── The refusal policy ────────────────────────────────────────────────────
 *
 * Three defects in this codebase have now had the same shape: an ambiguous
 * signal treated as licence to destroy data. A partition that failed to mount
 * was read as "corrupt, reformat". An empty key slot was read as "new device,
 * provision". A second mount returning -EBUSY was read as "broken filesystem".
 * Each was a guess, and each guess destroyed keys that cannot be recovered.
 *
 * This image formats flash for a living, so it gets the strictest version of
 * the rule. It proceeds on exactly one state:
 *
 *   mount FAILS          → nothing readable is there. Format, write marker.
 *
 * and refuses on every other, because each is either evidence of live data or
 * ambiguous between live data and blankness:
 *
 *   mount OK, VALID      → already initialised. Formatting discards live keys.
 *   mount OK, UNMARKED   → AMBIGUOUS. This is what a fresh volume looks like
 *                          and equally what a fully provisioned pre-marker
 *                          device looks like. Nothing on the volume separates
 *                          them, so this image must not guess.
 *   mount OK, MISMATCH   → wrong partition, or another die's volume. Whatever
 *                          is really there, formatting is the worst response.
 *
 * CONFIG_CANTIL_FACTORY_FORCE overrides the refusals for an operator who has
 * decided the contents are expendable. It is not needed for a new device.
 */

#include <zephyr/kernel.h>
#include <zephyr/fs/fs.h>
#include <zephyr/fs/littlefs.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/drivers/led.h>
#include <errno.h>

#include "storage/volume_marker.h"
#include "storage/storage_partition.h"
#include "crypto/device_id.h"

LOG_MODULE_REGISTER(factory, LOG_LEVEL_INF);

FS_LITTLEFS_DECLARE_DEFAULT_CONFIG(lfs_data);

/* Status LED — the board's gpio-leds, re-enabled in the app overlay. Indices
 * follow child order: 0 = Red, 1 = Green, 2 = Blue (all active-low). */
#define LED_RED   0
#define LED_GREEN 1
#define LED_BLUE  2
static const struct device *const leds = DEVICE_DT_GET(DT_PARENT(DT_NODELABEL(led0)));

static void led_only(int which)
{
	if (!device_is_ready(leds)) {
		return;
	}
	led_off(leds, LED_RED);
	led_off(leds, LED_GREEN);
	led_off(leds, LED_BLUE);
	if (which >= 0) {
		led_on(leds, which);
	}
}

/*
 * The image's final, human-readable verdict — blink one channel forever so an
 * operator with no console still learns the outcome:
 *   green, slow heartbeat → volume created and marker verified (done)
 *   red, fast             → refused or failed (nothing written / not usable)
 */
static FUNC_NORETURN void park_blink(int which, int on_ms, int off_ms)
{
	led_only(-1);
	while (1) {
		if (device_is_ready(leds)) {
			led_on(leds, which);
		}
		k_sleep(K_MSEC(on_ms));
		if (device_is_ready(leds)) {
			led_off(leds, which);
		}
		k_sleep(K_MSEC(off_ms));
	}
}

#define park_ok()     park_blink(LED_GREEN, 150, 850)
#define park_failed() park_blink(LED_RED, 150, 250)

/*
 * FS_MOUNT_FLAG_NO_FORMAT is not optional here. Zephyr's littlefs backend
 * formats from inside fs_mount() when the mount fails and this flag is clear —
 * which would erase the volume before this image had decided whether it was
 * allowed to. The whole policy above depends on a mount attempt being a
 * read-only probe, and only this flag makes it one.
 */
static struct fs_mount_t factory_mount = {
	.type = FS_LITTLEFS,
	.mnt_point = MOUNT_POINT,
	.fs_data = &lfs_data,
	.storage_dev = (void *)LFS_PARTITION,
	.flags = FS_MOUNT_FLAG_NO_FORMAT,
};

static void banner(void)
{
	uint8_t id[8];

	crypto_device_id(id);

	LOG_INF("Cantil factory image (step 1 of 2)");
	LOG_INF("device  %02x%02x%02x%02x%02x%02x%02x%02x", id[0], id[1], id[2], id[3], id[4],
		id[5], id[6], id[7]);
	LOG_INF("target  offset 0x%08x  size 0x%08x", (unsigned int)LFS_PARTITION_OFF,
		(unsigned int)LFS_PARTITION_SIZE);
}

/* Log the refusal in a form the operator can act on, then park. */
static void refuse(const char *what, const char *why)
{
	LOG_ERR("refusing to format: %s", what);
	LOG_ERR("%s", why);
	if (!IS_ENABLED(CONFIG_CANTIL_FACTORY_FORCE)) {
		LOG_ERR("if the contents really are expendable, rebuild with");
		LOG_ERR("CONFIG_CANTIL_FACTORY_FORCE=y and flash again");
	}
}

/* Create the volume and its marker. The only path that writes to flash. */
static int initialise(void)
{
	int ret;

	LOG_WRN("formatting %s (offset 0x%08x, size 0x%08x)", MOUNT_POINT,
		(unsigned int)LFS_PARTITION_OFF, (unsigned int)LFS_PARTITION_SIZE);

	ret = fs_mkfs(FS_LITTLEFS, (uintptr_t)LFS_PARTITION, NULL, 0);
	if (ret) {
		LOG_ERR("fs_mkfs failed: %d", ret);
		return ret;
	}

	ret = fs_mount(&factory_mount);
	if (ret) {
		LOG_ERR("mount after format failed: %d", ret);
		return ret;
	}

	ret = storage_volume_marker_write();
	if (ret) {
		LOG_ERR("marker write failed: %d", ret);
		return ret;
	}

	/*
	 * Verify by reading back rather than trusting the write. A volume that
	 * leaves the bench with a marker production will reject is worse than
	 * one with no marker at all — the latter can still be adopted.
	 */
	if (storage_volume_verify() != STORAGE_VOLUME_VALID) {
		LOG_ERR("marker did not verify after writing — not usable");
		return -EIO;
	}

	return 0;
}

int main(void)
{
	/* The USB console enumerates a moment after boot; without this the
	 * entire report is emitted into a port nobody is attached to yet.
	 * RTT sees it either way. */
	k_sleep(K_SECONDS(3));

	led_only(LED_BLUE); /* blue = image running / working */
	banner();

	int ret = fs_mount(&factory_mount);
	bool may_format = false;

	if (ret == -ENODEV) {
		LOG_ERR("storage device not found — check the board's QSPI "
			"configuration; nothing was written");
		park_failed();
	}

	if (ret) {
		/*
		 * The one unambiguous state. Note this is still not proof of a
		 * blank part — a misdeclared partition also fails to mount —
		 * which is why the offset and size go into the log above and
		 * into the marker below.
		 */
		LOG_INF("volume does not mount (%d) — treating as uninitialised", ret);
		may_format = true;
	} else {
		switch (storage_volume_verify()) {
		case STORAGE_VOLUME_VALID:
			LOG_INF("volume is already initialised and its marker "
				"verifies");
			refuse("this device is already provisioned",
			       "reformatting would discard live key material");
			break;
		case STORAGE_VOLUME_UNMARKED:
			refuse("volume mounts but carries no identity marker",
			       "that is ambiguous — it is what a fresh volume "
			       "looks like AND what a provisioned pre-marker "
			       "device looks like; nothing here can tell them "
			       "apart");
			LOG_ERR("to adopt an existing known-good volume instead,");
			LOG_ERR("flash production with CONFIG_CANTIL_VOLUME_MARKER_ADOPT=y");
			break;
		case STORAGE_VOLUME_MISMATCH:
			refuse("volume marker does not match this build",
			       "wrong partition, or a volume belonging to "
			       "another device (detail logged above)");
			break;
		}
	}

	if (!may_format && IS_ENABLED(CONFIG_CANTIL_FACTORY_FORCE)) {
		LOG_WRN("CANTIL_FACTORY_FORCE is set — overriding the refusal");
		LOG_WRN("existing contents, including any CA key, will be lost");
		if (ret == 0) {
			(void)fs_unmount(&factory_mount);
		}
		may_format = true;
	}

	if (!may_format) {
		LOG_ERR("nothing was written");
		park_failed();
	}

	if (initialise()) {
		LOG_ERR("initialisation FAILED — do not ship this device");
		park_failed();
	}

	LOG_INF("volume initialised and marker verified");
	LOG_INF("step 1 complete — flash the Cantil firmware to continue");
	park_ok();
}
