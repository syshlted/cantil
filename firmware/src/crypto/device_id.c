/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

#include <zephyr/kernel.h>
#include <string.h>

#include "device_id.h"

/*
 * FICR registers — device unique ID.
 *
 * On non-nRF builds (e.g. native_sim ztests) FICR is not memory-mapped, so we
 * fall back to a fixed test UID.
 */
#if defined(CONFIG_SOC_FAMILY_NORDIC_NRF)
#define FICR_BASE      0x10000000UL
#define FICR_DEVICEID0 (*(volatile uint32_t *)(FICR_BASE + 0x060))
#define FICR_DEVICEID1 (*(volatile uint32_t *)(FICR_BASE + 0x064))
#else
#define FICR_DEVICEID0 0xDEADBEEFu
#define FICR_DEVICEID1 0xCAFEF00Du
#endif

void crypto_device_id(uint8_t out[8])
{
	uint32_t d0 = FICR_DEVICEID0;
	uint32_t d1 = FICR_DEVICEID1;

	memcpy(out, &d0, 4);
	memcpy(out + 4, &d1, 4);
}
