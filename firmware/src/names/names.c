#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "names.h"
#include "names_data.h"
#include "crypto/crypto.h"

LOG_MODULE_REGISTER(names, LOG_LEVEL_DBG);

#define SEPARATOR 0xFFU

int names_get_random_batch(uint16_t count, uint8_t *out, size_t out_size)
{
	if (count == 0 || !out || out_size == 0) {
		return 0;
	}
	if (count > NAMES_BATCH_MAX) {
		count = NAMES_BATCH_MAX;
	}

	/*
	 * Generate count × 2 random bytes to produce uint16 indices.
	 * Modulo bias is negligible for NAMES_COUNT = 1919 with a 16-bit
	 * range (65536): bias < 0.05%.
	 */
	uint8_t rand_buf[NAMES_BATCH_MAX * 2];

	if (crypto_trng(rand_buf, count * 2u)) {
		LOG_ERR("TRNG failed");
		return -EIO;
	}

	size_t pos = 0;
	for (uint16_t i = 0; i < count; i++) {
		uint16_t r   = ((uint16_t)rand_buf[i * 2] << 8) | rand_buf[i * 2 + 1];
		uint16_t idx = r % NAMES_COUNT;

		uint16_t offset = names_byte_offsets[idx];
		uint8_t  len    = names_byte_lengths[idx];

		if (pos + len + 1u > out_size) {
			LOG_WRN("output buffer full after %u names", i);
			break;
		}

		memcpy(out + pos, names_data + offset, len);
		pos += len;
		out[pos++] = SEPARATOR;
	}

	return (int)pos;
}
