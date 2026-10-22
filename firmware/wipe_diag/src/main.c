/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Cantil sparse secure-wipe diagnostic (firmware/wipe_diag).
 *
 * Walks the external QSPI part (p25q16h, 2 MB) block by block. A block that is
 * already all-zero is skipped ("sparse"); any block with nonzero content is
 * erased and programmed to 0x00, then read back to verify. Every block's
 * outcome — and every error code — is appended to a RAM log which is written
 * periodically to a FIXED region of INTERNAL flash (0xE6000).
 *
 * Retrieval needs no USB: enter the UF2 bootloader (double-tap) and read
 * CURRENT.UF2, which dumps internal flash 0x1000..0xEA000. The log region is
 * inside that range, so scripts/decode_wipe_log.py can pull the text straight
 * out of CURRENT.UF2. This deliberately removes USB enumeration (the thing that
 * is unreliable on unit #1) from the diagnostic path entirely.
 *
 * Purpose: unit #1's QSPI can be READ (the factory image mounts it and brings
 * up a console) but the production image faults on it and a factory-force
 * reformat did not recover it. This tool answers the open question directly —
 * do erase and program actually succeed on that part, and if not, at exactly
 * which block/offset do they fail, and with what errno.
 *
 * The RAM log is flushed to internal flash every 32 blocks and on every
 * anomaly, so even if a QSPI operation hard-hangs, CURRENT.UF2 still shows how
 * far the wipe got before it stalled.
 */
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/sys/reboot.h>
#include <hal/nrf_power.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>

/* Adafruit nRF52 UF2 bootloader: GPREGRET == 0x57 on reset stays in UF2 DFU
 * mode. Setting it and resetting makes the device present its DFU drive with
 * no user action — so the drive appearing IS the "wipe complete" signal, and
 * the read no longer has to interrupt the run. The bootloader clears GPREGRET
 * after reading it, so this does not loop. */
#define UF2_DFU_MAGIC 0x57u

#define QSPI_NODE   DT_NODELABEL(p25q16h)
/* Internal flash: the driver binds to the flash-controller, not the
 * soc-nv-flash (flash0) child. flash_erase/flash_write take absolute internal
 * flash offsets on this device, so LOG_OFF is used directly. */
#define IFLASH_NODE DT_CHOSEN(zephyr_flash_controller)

#define QSPI_SIZE 0x200000u /* 2 MB p25q16h                                */
#define BLK       0x1000u   /* 4 KB erase sector                           */

#define LOG_OFF  0xE6000u /* internal flash — inside CURRENT.UF2 dump    */
#define LOG_SIZE 0x4000u  /* 16 KB                                       */

static const struct device *qspi = DEVICE_DT_GET(QSPI_NODE);
static const struct device *iflash = DEVICE_DT_GET(IFLASH_NODE);

/* Large buffers are static so CONFIG_MAIN_STACK_SIZE can stay small. */
static uint8_t logbuf[LOG_SIZE];
static size_t loglen;
static uint8_t blkbuf[BLK];
static const uint8_t zeros[BLK]; /* all-zero, .bss — the program-to-zero source */

static void logf(const char *fmt, ...)
{
	/* Stop appending once nearly full rather than risk a truncated tail. */
	if (loglen + 96u >= LOG_SIZE) {
		return;
	}
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf((char *)logbuf + loglen, LOG_SIZE - loglen, fmt, ap);
	va_end(ap);
	if (n > 0) {
		size_t room = LOG_SIZE - loglen - 1u;
		loglen += ((size_t)n < room) ? (size_t)n : room;
	}
}

/* Rewrite the whole 16 KB log region: erase, then program the bytes we have.
 * nRF internal-flash writes must be 4-byte aligned, so round the length up. */
static int flush_log(void)
{
	int r = flash_erase(iflash, LOG_OFF, LOG_SIZE);
	if (r) {
		return r;
	}
	size_t wl = (loglen + 3u) & ~((size_t)3u);
	if (wl == 0u) {
		wl = 4u;
	}
	if (wl > LOG_SIZE) {
		wl = LOG_SIZE;
	}
	return flash_write(iflash, LOG_OFF, logbuf, wl);
}

int main(void)
{
	uint32_t skipped = 0, zeroed = 0;
	uint32_t read_err = 0, erase_err = 0, write_err = 0, verify_err = 0;

	logf("==CANTIL-WIPE-DIAG==\n");
	logf("qspi_ready=%d iflash_ready=%d\n", (int)device_is_ready(qspi),
	     (int)device_is_ready(iflash));
	logf("qspi_size=0x%x blk=0x%x log@0x%x/0x%x\n", QSPI_SIZE, BLK, LOG_OFF, LOG_SIZE);
	(void)flush_log();

	if (!device_is_ready(qspi) || !device_is_ready(iflash)) {
		logf("FATAL device not ready — aborting\n");
		(void)flush_log();
		while (1) {
			k_sleep(K_SECONDS(5));
		}
	}

	for (uint32_t off = 0; off < QSPI_SIZE; off += BLK) {
		uint32_t blk = off / BLK;

		int r = flash_read(qspi, off, blkbuf, BLK);
		if (r) {
			logf("blk %u @0x%06x READ err=%d\n", blk, off, r);
			read_err++;
			(void)flush_log();
			continue;
		}

		bool allzero = true;
		for (uint32_t i = 0; i < BLK; i++) {
			if (blkbuf[i] != 0x00) {
				allzero = false;
				break;
			}
		}
		if (allzero) {
			skipped++;
			if ((blk & 0x3fu) == 0u) {
				logf("blk %u @0x%06x already-zero (skip)\n", blk, off);
			}
			if ((blk & 0x1fu) == 0u) {
				(void)flush_log();
			}
			continue;
		}

		int re = flash_erase(qspi, off, BLK);
		int rw = (re == 0) ? flash_write(qspi, off, zeros, BLK) : -1;

		bool vok = false;
		if (re == 0 && rw == 0) {
			if (flash_read(qspi, off, blkbuf, BLK) == 0) {
				vok = true;
				for (uint32_t i = 0; i < BLK; i++) {
					if (blkbuf[i] != 0x00) {
						vok = false;
						break;
					}
				}
			}
		}

		if (re != 0 || rw != 0 || !vok) {
			logf("blk %u @0x%06x erase=%d write=%d verify=%s\n", blk, off, re, rw,
			     vok ? "ok" : "FAIL");
			if (re) {
				erase_err++;
			}
			if (rw) {
				write_err++;
			}
			if (!vok) {
				verify_err++;
			}
			(void)flush_log(); /* capture every anomaly at once */
		} else {
			zeroed++;
			if ((blk & 0x3fu) == 0u) {
				logf("blk %u @0x%06x zeroed ok\n", blk, off);
			}
		}

		if ((blk & 0x1fu) == 0u) {
			(void)flush_log(); /* checkpoint every 32 blocks */
		}
	}

	logf("DONE skip=%u zeroed=%u read_err=%u erase_err=%u write_err=%u verify_err=%u\n",
	     skipped, zeroed, read_err, erase_err, write_err, verify_err);
	logf("wipe complete — entering UF2 DFU so the log can be read\n");
	(void)flush_log();

	/* Let the last internal-flash write settle, then hand ourselves to the
	 * UF2 bootloader. The DFU drive appearing on the host is the completion
	 * signal; the log is already durable in internal flash. */
	k_sleep(K_MSEC(250));
	nrf_power_gpregret_set(NRF_POWER, 0, UF2_DFU_MAGIC);
	sys_reboot(SYS_REBOOT_COLD);

	/* Only reached if the reboot request is refused. */
	while (1) {
		k_sleep(K_SECONDS(5));
	}
}
