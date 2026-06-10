#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <hal/nrf_gpio.h>

/*
 * Crash locator: blinks the red LED (P0.26, active LOW) at different init
 * stages so we can tell how far boot gets without serial output.
 *
 *   PRE_KERNEL_1 priority 0  → 1 short blink
 *   PRE_KERNEL_1 priority 99 → 2 short blinks
 *   POST_KERNEL  priority 0  → 1 long blink
 *   POST_KERNEL  priority 99 → 2 long blinks
 *   main()                   → 3 rapid blinks (early_boot_blink in main.c)
 */
#define DIAG_LED_PIN NRF_GPIO_PIN_MAP(0, 26) /* P0.26, active LOW */

/* Busy-loop delay usable before k_busy_wait is available (PRE_KERNEL_1).
 * ~4 cycles per iteration on Cortex-M4 at 64 MHz → 3.2M iters ≈ 200 ms. */
#define LOOP_200MS 3200000UL

static void loop_delay(uint32_t iters)
{
	for (volatile uint32_t i = 0; i < iters; i++) {
	}
}

static void blink_short(int count)
{
	for (int i = 0; i < count; i++) {
		nrf_gpio_pin_clear(DIAG_LED_PIN);
		loop_delay(LOOP_200MS);
		nrf_gpio_pin_set(DIAG_LED_PIN);
		loop_delay(LOOP_200MS);
	}
	loop_delay(LOOP_200MS * 3);
}

static void blink_long(int count)
{
	for (int i = 0; i < count; i++) {
		nrf_gpio_pin_clear(DIAG_LED_PIN);
		k_busy_wait(500000);
		nrf_gpio_pin_set(DIAG_LED_PIN);
		k_busy_wait(300000);
	}
	k_busy_wait(800000);
}

static int diag_pk1_early(void)
{
	nrf_gpio_cfg_output(DIAG_LED_PIN);
	nrf_gpio_pin_set(DIAG_LED_PIN);
	blink_short(1);
	return 0;
}
SYS_INIT(diag_pk1_early, PRE_KERNEL_1, 0);

static int diag_pk1_late(void)
{
	blink_short(2);
	return 0;
}
SYS_INIT(diag_pk1_late, PRE_KERNEL_1, 99);

static int diag_pk_early(void)
{
	blink_long(1);
	return 0;
}
SYS_INIT(diag_pk_early, POST_KERNEL, 0);

static int diag_pk_late(void)
{
	blink_long(2);
	return 0;
}
SYS_INIT(diag_pk_late, POST_KERNEL, 99);
