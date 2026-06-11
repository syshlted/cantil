#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>

#include "gesture.h"

LOG_MODULE_REGISTER(tap_button, LOG_LEVEL_INF);

#define TAP_NODE DT_ALIAS(cantil_tap)

static const struct gpio_dt_spec btn =
	GPIO_DT_SPEC_GET(TAP_NODE, gpios);

static const uint32_t DEBOUNCE_MS =
	DT_PROP(TAP_NODE, debounce_ms);

#if !defined(CONFIG_CANTIL_ALPHABET_COUNT_COLOR)
static const uint32_t DOUBLE_TAP_MS =
	DT_PROP(TAP_NODE, double_tap_ms);
#endif

static struct gpio_callback btn_cb;
static struct k_work_delayable debounce_work;

#if !defined(CONFIG_CANTIL_ALPHABET_COUNT_COLOR)
static int64_t last_release_ms;
static bool pending_single;
static void flush_single_tap_timer_fn(struct k_timer *timer);
static K_TIMER_DEFINE(flush_timer, flush_single_tap_timer_fn, NULL);
#endif

static void debounce_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	int val = gpio_pin_get_dt(&btn);

	if (val != 0) {
		return;
	}

#if defined(CONFIG_CANTIL_ALPHABET_COUNT_COLOR)
	/* COUNT_COLOR: each physical press is its own tap. No ST/DT
	 * classification, no double-tap window — fires immediately on
	 * debounced release. */
	gesture_report_raw_tap();
#else
	/* STDT_PLAIN / STDT_BINARY: classify ST vs DT in software.
	 * First release arms the flush timer; a second release within
	 * DOUBLE_TAP_MS upgrades to a DOUBLE. */
	int64_t now = k_uptime_get();

	if (pending_single &&
	    (now - last_release_ms) <= DOUBLE_TAP_MS) {
		pending_single = false;
		k_timer_stop(&flush_timer);
		gesture_report_tap(CANTIL_TAP_DOUBLE);
	} else {
		pending_single = true;
		last_release_ms = now;
		k_timer_start(&flush_timer, K_MSEC(DOUBLE_TAP_MS), K_NO_WAIT);
	}
#endif
}

static void btn_isr(const struct device *port, struct gpio_callback *cb,
		    gpio_port_pins_t pins)
{
	ARG_UNUSED(port);
	ARG_UNUSED(cb);
	ARG_UNUSED(pins);
	k_work_reschedule(&debounce_work, K_MSEC(DEBOUNCE_MS));
}

#if !defined(CONFIG_CANTIL_ALPHABET_COUNT_COLOR)
static void flush_single_tap_timer_fn(struct k_timer *timer)
{
	ARG_UNUSED(timer);
	if (pending_single) {
		pending_single = false;
		gesture_report_tap(CANTIL_TAP_SINGLE);
	}
}
#endif

static int tap_button_init(void)
{
	if (!gpio_is_ready_dt(&btn)) {
		return -ENODEV;
	}

	int ret;

	ret = gpio_pin_configure_dt(&btn, GPIO_INPUT);
	if (ret) {
		return ret;
	}

	ret = gpio_pin_interrupt_configure_dt(&btn, GPIO_INT_EDGE_BOTH);
	if (ret) {
		return ret;
	}

	gpio_init_callback(&btn_cb, btn_isr, BIT(btn.pin));
	gpio_add_callback(btn.port, &btn_cb);

	k_work_init_delayable(&debounce_work, debounce_handler);

	return 0;
}

SYS_INIT(tap_button_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
