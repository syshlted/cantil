/*
 * PDM microphone tap detection.
 *
 * Streams audio from the onboard MEMS mic in short blocks, runs a per-block
 * peak detector with a refractory window, and emits onset events. Onset
 * events are funneled through the same single-/double-tap timing logic as
 * tap_button.c so the gesture parser is unaware of the input source.
 *
 * Design notes:
 *   - Block size CONFIG_CANTIL_MIC_BLOCK_MS (default 32 ms) keeps DMIC
 *     latency low without exhausting the PDM mem-slab — a tap onset is
 *     detected within ~1 block.
 *   - Onset rule: peak(block) >= THRESHOLD AND now - last_onset_ms >=
 *     REFRACTORY_MS. The refractory window prevents the broadband decay
 *     of a single impulse from firing multiple onsets.
 *   - DOUBLE_TAP_WINDOW_MS matches tap_button.c so the gesture state
 *     machine sees identical timing regardless of which input is active.
 */

#include <math.h>
#include <stdint.h>

#include <zephyr/audio/dmic.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/regulator.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "gesture.h"

LOG_MODULE_REGISTER(tap_mic, LOG_LEVEL_INF);

#define SAMPLE_RATE_HZ   16000
#define SAMPLE_BIT_WIDTH 16
#define READ_TIMEOUT_MS  1000

#define BLOCK_MS         CONFIG_CANTIL_MIC_BLOCK_MS
#define BLOCK_SAMPLES    ((SAMPLE_RATE_HZ * BLOCK_MS) / 1000)
#define BLOCK_SIZE       (BLOCK_SAMPLES * sizeof(int16_t))
#define BLOCK_COUNT      8

#define REFRACTORY_MS         CONFIG_CANTIL_MIC_REFRACTORY_MS
#define DOUBLE_TAP_WINDOW_MS  300
#define ONSET_THRESHOLD       CONFIG_CANTIL_MIC_THRESHOLD

K_MEM_SLAB_DEFINE_STATIC(tap_mic_slab, BLOCK_SIZE, BLOCK_COUNT, 4);

static K_THREAD_STACK_DEFINE(tap_mic_stack, 4096);
static struct k_thread tap_mic_thread;

static struct k_timer flush_timer;
static int64_t last_onset_ms;
static int64_t pending_release_ms;
static bool    pending_single;

static void flush_single_tap_timer_fn(struct k_timer *timer)
{
	ARG_UNUSED(timer);
	if (pending_single) {
		pending_single = false;
		gesture_report_tap(CANTIL_TAP_SINGLE);
	}
}

/* Translate an onset (sharp audio impulse) into the same single/double-tap
 * stream tap_button.c produces. Onset-only — we have no "release" event from
 * the mic, so the impulse itself is treated as both press and release. */
static void on_onset(int64_t now)
{
	if (pending_single &&
	    (now - pending_release_ms) <= DOUBLE_TAP_WINDOW_MS) {
		pending_single = false;
		k_timer_stop(&flush_timer);
		gesture_report_tap(CANTIL_TAP_DOUBLE);
	} else {
		pending_single = true;
		pending_release_ms = now;
		k_timer_start(&flush_timer,
			      K_MSEC(DOUBLE_TAP_WINDOW_MS), K_NO_WAIT);
	}
}

struct block_stats {
	int16_t peak;
	int16_t min;
	int16_t max;
	uint32_t nonzero;
};

static struct block_stats block_analyze(const int16_t *samples, size_t count)
{
	struct block_stats s = { .peak = 0, .min = INT16_MAX, .max = INT16_MIN, .nonzero = 0 };

	for (size_t i = 0; i < count; i++) {
		int16_t v = samples[i];

		if (v != 0) {
			s.nonzero++;
		}
		if (v < s.min) {
			s.min = v;
		}
		if (v > s.max) {
			s.max = v;
		}
		int16_t a = (v < 0) ? (int16_t)(-v) : v;

		if (a > s.peak) {
			s.peak = a;
		}
	}
	return s;
}

/* The mic regulator (msm261d3526hicpm-c-en) is a regulator-fixed on
 * gpio1 P1.10 active-high.  Going through the regulator framework has
 * proven unreliable here — the rail comes up for ~700 ms then something
 * pulls P1.10 back low and the PDM stream goes constant-7 forever.  Drive
 * the GPIO directly (belt-and-braces, same workaround tap_imu.c uses for
 * its own power-gate). */
static const struct gpio_dt_spec mic_power_pin = GPIO_DT_SPEC_GET(
	DT_PATH(msm261d3526hicpm_c_en), enable_gpios);

static int mic_power_on(void)
{
	const struct device *reg =
		DEVICE_DT_GET(DT_PATH(msm261d3526hicpm_c_en));

	if (!device_is_ready(reg)) {
		LOG_ERR("mic regulator not ready");
		return -ENODEV;
	}
	if (!gpio_is_ready_dt(&mic_power_pin)) {
		LOG_ERR("mic power pin not ready");
		return -ENODEV;
	}

	int ret = regulator_enable(reg);

	if (ret) {
		LOG_WRN("regulator_enable: %d (continuing via direct GPIO)", ret);
	}

	/* Configure pin as OUTPUT + INPUT so we can read back actual pad state. */
	ret = gpio_pin_configure_dt(&mic_power_pin, GPIO_OUTPUT_INACTIVE | GPIO_INPUT);
	if (ret) {
		LOG_ERR("mic_power_pin configure: %d", ret);
		return ret;
	}

	/* Hard power-cycle the mic: the UF2 bootloader does not clear this
	 * rail across resets, so the chip can be carried over from a prior
	 * boot in a state that produces constant-value output even though
	 * PDM is correctly clocked.  Drive low for 500 ms so any rail
	 * capacitance discharges below the chip's POR threshold, then back
	 * high.  (Same workaround tap_imu.c applies to the IMU rail.) */
	gpio_pin_set_dt(&mic_power_pin, 0);
	LOG_INF("mic: power-cycle, rail LOW for 500 ms");
	k_msleep(500);
	gpio_pin_set_dt(&mic_power_pin, 1);
	LOG_INF("mic: rail HIGH, pin readback=%d",
		gpio_pin_get_dt(&mic_power_pin));
	return 0;
}

static int dmic_start(const struct device *dmic_dev)
{
	struct pcm_stream_cfg stream = {
		.pcm_width  = SAMPLE_BIT_WIDTH,
		.pcm_rate   = SAMPLE_RATE_HZ,
		.block_size = BLOCK_SIZE,
		.mem_slab   = &tap_mic_slab,
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
	int ret = dmic_configure(dmic_dev, &cfg);

	if (ret < 0) {
		LOG_ERR("dmic_configure: %d", ret);
		return ret;
	}
	ret = dmic_trigger(dmic_dev, DMIC_TRIGGER_START);
	if (ret < 0) {
		LOG_ERR("dmic START: %d", ret);
		return ret;
	}
	return 0;
}

static void tap_mic_loop(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1); ARG_UNUSED(p2); ARG_UNUSED(p3);

	/* Give USB CDC time to enumerate so the PDM stream isn't capturing
	 * into an undrainable queue while the consumer is blocked on log I/O. */
	k_msleep(5000);
	LOG_INF("tap_mic: waking after enumeration window");

	const struct device *const dmic_dev = DEVICE_DT_GET(DT_NODELABEL(pdm0));

	if (!device_is_ready(dmic_dev)) {
		LOG_ERR("DMIC %s not ready", dmic_dev->name);
		return;
	}

	int rc = mic_power_on();

	if (rc < 0) {
		LOG_ERR("mic_power_on: %d", rc);
		return;
	}
	/* MEMS startup time after VDD rises (datasheet ~10 ms typ, give margin). */
	k_msleep(100);

	rc = dmic_start(dmic_dev);
	if (rc < 0) {
		return;
	}

	LOG_INF("tap_mic: %u Hz, %d ms blocks, %u buf, thresh=%d, refr=%d ms",
		SAMPLE_RATE_HZ, BLOCK_MS, (unsigned)BLOCK_COUNT,
		ONSET_THRESHOLD, REFRACTORY_MS);

	/* Discard the mic power-on transient (~500 ms saturates to full-scale
	 * as the bias settles).  Otherwise the first block fires a false tap. */
	const int warmup_blocks = (500 + BLOCK_MS - 1) / BLOCK_MS;
	int blocks_seen = 0;
	uint32_t consec_err = 0;
	uint32_t total_blocks = 0;
	int16_t  hb_peak_max = 0;
	int64_t  last_heartbeat = k_uptime_get();

	while (1) {
		void *buffer;
		uint32_t size;

		int ret = dmic_read(dmic_dev, 0, &buffer, &size, READ_TIMEOUT_MS);

		if (ret < 0) {
			consec_err++;
			if (consec_err == 1 || (consec_err % 50) == 0) {
				LOG_WRN("dmic_read ret=%d (consec=%u)",
					ret, consec_err);
			}
			/* If the stream wedges (slab exhaustion from a
			 * consumer stall), restart it. */
			if (consec_err == 10) {
				LOG_WRN("restarting DMIC stream");
				dmic_trigger(dmic_dev, DMIC_TRIGGER_STOP);
				k_msleep(20);
				if (dmic_trigger(dmic_dev,
						 DMIC_TRIGGER_START) == 0) {
					consec_err = 0;
					blocks_seen = 0;
				}
			}
			continue;
		}
		consec_err = 0;

		struct block_stats stats = block_analyze((const int16_t *)buffer,
							 size / sizeof(int16_t));
		int16_t peak = stats.peak;

		k_mem_slab_free(&tap_mic_slab, buffer);

		total_blocks++;
		if (peak > hb_peak_max) {
			hb_peak_max = peak;
		}
		int64_t now_hb = k_uptime_get();

		if (now_hb - last_heartbeat >= 5000) {
			int pin = gpio_pin_get_dt(&mic_power_pin);

			LOG_INF("tap_mic: hb %u blks min=%d max=%d nonzero=%u/%u peak_max=%d pwr=%d",
				total_blocks, stats.min, stats.max,
				stats.nonzero, (unsigned)(size / sizeof(int16_t)),
				hb_peak_max, pin);
			/* If something flipped the pin low, force it back high. */
			if (pin == 0) {
				LOG_WRN("mic power pin went LOW — re-asserting");
				gpio_pin_set_dt(&mic_power_pin, 1);
			}
			total_blocks  = 0;
			hb_peak_max   = 0;
			last_heartbeat = now_hb;
		}

		if (blocks_seen < warmup_blocks) {
			blocks_seen++;
			continue;
		}

		if (peak < ONSET_THRESHOLD) {
			continue;
		}

		int64_t now = k_uptime_get();

		if ((now - last_onset_ms) < REFRACTORY_MS) {
			continue;
		}
		last_onset_ms = now;
		LOG_INF("onset peak=%d t=%lld", peak, (long long)now);
		on_onset(now);
	}
}

int tap_mic_init(void)
{
	k_timer_init(&flush_timer, flush_single_tap_timer_fn, NULL);

	k_thread_create(&tap_mic_thread, tap_mic_stack,
			K_THREAD_STACK_SIZEOF(tap_mic_stack),
			tap_mic_loop, NULL, NULL, NULL,
			K_PRIO_PREEMPT(7), 0, K_NO_WAIT);
	k_thread_name_set(&tap_mic_thread, "tap_mic");
	return 0;
}
