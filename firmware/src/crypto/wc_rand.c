/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/entropy.h>
#include <zephyr/logging/log.h>
#include <errno.h>

#include "crypto/wc_rand.h"

LOG_MODULE_REGISTER(wc_rand, LOG_LEVEL_INF);

int cantil_wc_trng(uint8_t *buf, size_t len)
{
	static const struct device *rng;

	if (!rng) {
		rng = DEVICE_DT_GET(DT_CHOSEN(zephyr_entropy));
	}
	if (!device_is_ready(rng)) {
		LOG_ERR("entropy device not ready");
		return -EIO;
	}
	return entropy_get_entropy(rng, buf, len);
}

int cantil_wc_rand_block(unsigned char *output, unsigned int sz)
{
	/*
	 * Non-zero on failure rather than an errno: wolfCrypt only tests
	 * against zero, and returning -EIO here would read as "success" to
	 * nothing and as a wolfCrypt error code to anything that logged it.
	 */
	return cantil_wc_trng(output, sz) ? -1 : 0;
}
