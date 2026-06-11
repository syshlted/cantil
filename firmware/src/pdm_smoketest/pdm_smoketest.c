/*
 * PDM microphone smoke-test.
 *
 * Continuously captures 16 kHz mono audio via the nRF PDM peripheral
 * (msm261d3526hicpm-c MEMS mic on the XIAO BLE Sense), computes peak
 * absolute sample and RMS per 100 ms block, and reports both over USB
 * CDC ACM. Drives the RGB LED as a level meter: blue (idle), green
 * (sound detected), red (read failure).
 *
 * Intended as an A/B diagnostic across two physical XIAO units after
 * one unit's LSM6DS3TR-C went silent on I2C — confirms whether the
 * rest of the analog/digital sensor frontend is intact.
 */

#include <math.h>
#include <stdint.h>
#include <stdlib.h>

#include <zephyr/audio/dmic.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/regulator.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(pdm_smoketest, LOG_LEVEL_INF);

#define SAMPLE_RATE_HZ   16000
#define SAMPLE_BIT_WIDTH 16
#define READ_TIMEOUT_MS  1000

/* 100 ms blocks, mono, 16-bit signed. */
#define BLOCK_SAMPLES    (SAMPLE_RATE_HZ / 10)
#define BLOCK_SIZE       (BLOCK_SAMPLES * sizeof(int16_t))
#define BLOCK_COUNT      4

K_MEM_SLAB_DEFINE_STATIC(pdm_slab, BLOCK_SIZE, BLOCK_COUNT, 4);

/* Peak threshold above which we light the green LED. ~3% of full scale.
 * Quiet room noise floor on this mic sits around 200–500; a hand clap
 * at 30 cm hits 8000+. 1000 picks a confident "audible event". */
#define LEVEL_THRESHOLD  1000

static const struct gpio_dt_spec led_r =
	GPIO_DT_SPEC_GET(DT_ALIAS(cantil_led_r), gpios);
static const struct gpio_dt_spec led_g =
	GPIO_DT_SPEC_GET(DT_ALIAS(cantil_led_g), gpios);
static const struct gpio_dt_spec led_b =
	GPIO_DT_SPEC_GET(DT_ALIAS(cantil_led_b), gpios);

/* RGB LEDs on XIAO BLE Sense are active-low (common anode); use the dt-spec
 * helpers which honour GPIO_ACTIVE_LOW from devicetree. */
static void leds_init(void)
{
	gpio_pin_configure_dt(&led_r, GPIO_OUTPUT_INACTIVE);
	gpio_pin_configure_dt(&led_g, GPIO_OUTPUT_INACTIVE);
	gpio_pin_configure_dt(&led_b, GPIO_OUTPUT_INACTIVE);
}

static void leds_set(int r, int g, int b)
{
	gpio_pin_set_dt(&led_r, r);
	gpio_pin_set_dt(&led_g, g);
	gpio_pin_set_dt(&led_b, b);
}

/* Power up the MEMS mic via its regulator-fixed node. The DTS gives the
 * node no label, so reference it by path. */
static int mic_power_on(void)
{
	const struct device *reg =
		DEVICE_DT_GET(DT_PATH(msm261d3526hicpm_c_en));

	if (!device_is_ready(reg)) {
		LOG_ERR("mic regulator not ready");
		return -ENODEV;
	}
	return regulator_enable(reg);
}

struct block_stats {
	int16_t peak;
	uint32_t rms;
};

static struct block_stats compute_stats(const int16_t *samples, size_t count)
{
	struct block_stats s = {0};
	uint64_t sum_sq = 0;

	for (size_t i = 0; i < count; i++) {
		int16_t v = samples[i];
		int16_t a = (v < 0) ? (int16_t)(-v) : v;

		if (a > s.peak) {
			s.peak = a;
		}
		sum_sq += (uint64_t)((int32_t)v * v);
	}

	s.rms = (uint32_t)sqrt((double)sum_sq / (double)count);
	return s;
}

static int run_capture_loop(const struct device *dmic_dev)
{
	struct pcm_stream_cfg stream = {
		.pcm_width = SAMPLE_BIT_WIDTH,
		.pcm_rate  = SAMPLE_RATE_HZ,
		.block_size = BLOCK_SIZE,
		.mem_slab  = &pdm_slab,
	};
	struct dmic_cfg cfg = {
		.io = {
			.min_pdm_clk_freq = 1000000,
			.max_pdm_clk_freq = 3500000,
			.min_pdm_clk_dc   = 40,
			.max_pdm_clk_dc   = 60,
		},
		.streams = &stream,
		.channel = {
			.req_num_streams = 1,
			.req_num_chan    = 1,
			.req_chan_map_lo = dmic_build_channel_map(0, 0, PDM_CHAN_LEFT),
		},
	};
	int ret;

	ret = dmic_configure(dmic_dev, &cfg);
	if (ret < 0) {
		LOG_ERR("dmic_configure failed: %d", ret);
		return ret;
	}

	ret = dmic_trigger(dmic_dev, DMIC_TRIGGER_START);
	if (ret < 0) {
		LOG_ERR("dmic START failed: %d", ret);
		return ret;
	}

	LOG_INF("capture started — %u Hz mono, %u samples/block, threshold=%d",
		SAMPLE_RATE_HZ, BLOCK_SAMPLES, LEVEL_THRESHOLD);

	uint32_t block_num = 0;

	while (1) {
		void *buffer;
		uint32_t size;

		ret = dmic_read(dmic_dev, 0, &buffer, &size, READ_TIMEOUT_MS);
		if (ret < 0) {
			LOG_ERR("dmic_read failed: %d", ret);
			leds_set(1, 0, 0);
			k_msleep(200);
			continue;
		}

		struct block_stats s =
			compute_stats((const int16_t *)buffer, size / sizeof(int16_t));

		k_mem_slab_free(&pdm_slab, buffer);

		bool above = (s.peak >= LEVEL_THRESHOLD);

		leds_set(0, above ? 1 : 0, above ? 0 : 1);

		LOG_INF("block %u: peak=%5d rms=%5u %s",
			block_num++, s.peak, s.rms, above ? "AUDIO" : "");
	}
}

int main(void)
{
	LOG_INF("PDM smoke-test starting");

	leds_init();

	/* Boot indicator: white flash so it's distinguishable from the
	 * production firmware's red 3-blink. */
	leds_set(1, 1, 1);
	k_msleep(300);
	leds_set(0, 0, 0);

	if (mic_power_on() < 0) {
		LOG_ERR("failed to power on mic — halting");
		while (1) {
			leds_set(1, 0, 0);
			k_msleep(100);
			leds_set(0, 0, 0);
			k_msleep(100);
		}
	}

	/* MEMS mic startup time: datasheet quotes ~10 ms typ after VDD
	 * reaches level; give it a generous margin before we clock it. */
	k_msleep(50);

	const struct device *const dmic_dev =
		DEVICE_DT_GET(DT_NODELABEL(pdm0));

	if (!device_is_ready(dmic_dev)) {
		LOG_ERR("%s not ready", dmic_dev->name);
		while (1) {
			leds_set(1, 0, 0);
			k_msleep(500);
		}
	}

	leds_set(0, 0, 1);

	(void)run_capture_loop(dmic_dev);
	return 0;
}
