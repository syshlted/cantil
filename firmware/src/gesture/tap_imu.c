/* LSM6DS3TR-C tap detection via direct I2C register access.
 *
 * The upstream Zephyr LSM6DSL driver only supports SENSOR_TRIG_DATA_READY,
 * so SENSOR_TRIG_TAP / SENSOR_TRIG_DOUBLE_TAP cannot be routed through it.
 * This module bypasses the sensor abstraction: I2C bus comes from the
 * lsm6ds3tr_c node's parent, the IRQ line comes from its irq-gpios.
 * The Zephyr LSM6DSL driver is disabled in builds that use this module
 * to avoid fighting over the chip's config registers.
 *
 * Register values follow ST AN4650 "LSM6DS3 tap and double-tap" guidance.
 * Accelerometer is run at 416 Hz / ±2 g; all three axes participate, so
 * orientation does not matter.
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/regulator.h>
#include <zephyr/logging/log.h>
#include <hal/nrf_gpio.h>

#include "gesture.h"
#include "led/led.h"

LOG_MODULE_REGISTER(tap_imu, LOG_LEVEL_INF);

#define IMU_NODE DT_NODELABEL(lsm6ds3tr_c)
BUILD_ASSERT(DT_NODE_EXISTS(IMU_NODE), "lsm6ds3tr_c node missing from devicetree");

static const struct i2c_dt_spec  imu_i2c = I2C_DT_SPEC_GET(IMU_NODE);
static const struct gpio_dt_spec imu_irq = GPIO_DT_SPEC_GET(IMU_NODE, irq_gpios);

/* The LSM6DS3TR-C is gated by a regulator on gpio1 P1.08. Refer to it by
 * device-tree path since the board DTS gave it no label. */
#define IMU_REG_NODE DT_PATH(lsm6ds3tr_c_en)
BUILD_ASSERT(DT_NODE_EXISTS(IMU_REG_NODE), "lsm6ds3tr-c-en regulator missing");
static const struct device *imu_regulator = DEVICE_DT_GET(IMU_REG_NODE);

/* Also keep a direct handle on the enable pin so we can force-drive it
 * regardless of what the regulator framework did. */
static const struct gpio_dt_spec imu_power_pin =
	GPIO_DT_SPEC_GET(IMU_REG_NODE, enable_gpios);

/* Brief WHITE flash indicating "step N reached". Use 1..7 for the steps
 * in tap_imu_init. */
static void step(uint8_t n)
{
	led_diag_flash(LED_COLOR_WHITE, 80);
	k_msleep(500);
	for (uint8_t i = 0; i < n; i++) {
		led_diag_flash(LED_COLOR_WHITE, 200);
		k_msleep(400);
	}
	k_msleep(600);
}

/* LSM6DS3TR-C registers */
#define REG_WHO_AM_I    0x0F
#define REG_TAP_SRC     0x1C
#define REG_CTRL1_XL    0x10
#define REG_TAP_CFG     0x58
#define REG_TAP_THS_6D  0x59
#define REG_INT_DUR2    0x5A
#define REG_WAKE_UP_THS 0x5B
#define REG_MD1_CFG     0x5E

/* WHO_AM_I: LSM6DS3TR-C = 0x6A per datasheet DS11791. Some early XIAO
 * variants ship with the original LSM6DS3 (0x69). Accept either. */
#define WHO_AM_I_LSM6DS3   0x69
#define WHO_AM_I_LSM6DS3TR 0x6A

#define TAP_SRC_TAP_IA      BIT(6)
#define TAP_SRC_SINGLE_TAP  BIT(5)
#define TAP_SRC_DOUBLE_TAP  BIT(4)

static struct gpio_callback irq_cb;
static struct k_work        tap_work;

static void tap_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);

	/* DIAG: brief WHITE flash for every IRQ, so a missing flash means the
	 * IRQ line isn't being asserted (chip config / pin wiring), and a
	 * white flash without a state change means TAP_SRC didn't show
	 * TAP_IA (register config). */
	led_diag_flash(LED_COLOR_WHITE, 60);

	uint8_t src;
	int ret = i2c_reg_read_byte_dt(&imu_i2c, REG_TAP_SRC, &src);
	if (ret) {
		LOG_ERR("TAP_SRC read failed: %d", ret);
		led_diag_flash(LED_COLOR_RED, 300);
		return;
	}

	if (!(src & TAP_SRC_TAP_IA)) {
		/* IRQ fired but it wasn't a tap — make it visible (blue flash). */
		led_diag_flash(LED_COLOR_BLUE, 200);
		return;
	}

	if (src & TAP_SRC_DOUBLE_TAP) {
		LOG_INF("tap: DT (src=0x%02x)", src);
		gesture_report_tap(CANTIL_TAP_DOUBLE);
	} else if (src & TAP_SRC_SINGLE_TAP) {
		LOG_INF("tap: ST (src=0x%02x)", src);
		gesture_report_tap(CANTIL_TAP_SINGLE);
	}
}

static void imu_irq_handler(const struct device *port,
			    struct gpio_callback *cb, uint32_t pins)
{
	ARG_UNUSED(port);
	ARG_UNUSED(cb);
	ARG_UNUSED(pins);
	k_work_submit(&tap_work);
}

/* Diagnostic LED codes at boot so we can tell what went wrong without serial.
 * Each is shown for ~3 s before returning so it's clearly visible. */
#define DIAG_OK_MS         800
#define DIAG_FAIL_MS      3000

static void diag_fail(uint8_t blinks)
{
	/* Yellow start marker so the user knows where counting begins,
	 * then N slow red blinks (impossible to miscount), then a yellow
	 * end marker, then the long red hold. */
	led_diag_flash(LED_COLOR_YELLOW, 800);
	k_msleep(600);
	for (uint8_t i = 0; i < blinks; i++) {
		led_diag_flash(LED_COLOR_RED, 250);
		k_msleep(500);
	}
	led_diag_flash(LED_COLOR_YELLOW, 800);
	k_msleep(400);
	led_diag_flash(LED_COLOR_RED, DIAG_FAIL_MS);
}

int tap_imu_init(void)
{
	int ret;
	uint8_t who;

	/* DIAGNOSTIC: report whether the upstream Zephyr LSM6DSL driver
	 * succeeded its own init. Its init reads WHO_AM_I; if device_is_ready
	 * returns true the chip is alive on I2C and our scan failure must be
	 * a subtle config bug. If false, the upstream driver agrees with our
	 * scan that the chip is silent. */
	{
		const struct device *upstream = DEVICE_DT_GET_ONE(st_lsm6dsl);
		if (upstream == NULL) {
			LOG_WRN("upstream lsm6dsl device not in DT");
		} else {
			bool ready = device_is_ready(upstream);
			LOG_INF("upstream LSM6DSL device_is_ready -> %s",
				ready ? "TRUE (chip is alive)" : "FALSE (chip silent)");
		}
	}

	if (!device_is_ready(imu_i2c.bus)) {
		LOG_ERR("I2C bus %s not ready", imu_i2c.bus->name);
		diag_fail(1);  /* 1 short red + long red */
		return -ENODEV;
	}
	if (!gpio_is_ready_dt(&imu_irq)) {
		LOG_ERR("IRQ GPIO not ready");
		diag_fail(2);
		return -ENODEV;
	}
	if (!device_is_ready(imu_regulator)) {
		LOG_ERR("IMU regulator device not ready");
		diag_fail(2);
		return -ENODEV;
	}

	step(1);  /* readiness checks passed */

	/* PRE-power SDA/SCL pad read. If pull-ups are on the always-on rail
	 * they'll already read HIGH; if pull-ups are downstream of the IMU
	 * load switch they'll read LOW until we enable. Framed in BLUE to
	 * distinguish from the post-power yellow-framed read later.
	 *   blue, SDA, blue, SCL, blue */
	{
		uint32_t sda0 = nrf_gpio_pin_read(7);
		uint32_t scl0 = nrf_gpio_pin_read(27);
		LOG_INF("PRE-power SDA=%u SCL=%u", sda0, scl0);
		led_diag_flash(LED_COLOR_BLUE, 1000); k_msleep(600);
		led_diag_flash(sda0 ? LED_COLOR_GREEN : LED_COLOR_RED, 700);
		k_msleep(600);
		led_diag_flash(LED_COLOR_BLUE, 1000); k_msleep(600);
		led_diag_flash(scl0 ? LED_COLOR_GREEN : LED_COLOR_RED, 700);
		k_msleep(600);
		led_diag_flash(LED_COLOR_BLUE, 1000); k_msleep(600);
	}

	/* Explicitly enable the IMU power-gate regulator AND directly drive
	 * its enable pin high — belt-and-braces. */
	ret = regulator_enable(imu_regulator);
	if (ret) {
		LOG_ERR("regulator_enable failed: %d", ret);
		diag_fail(2);
		return ret;
	}
	step(2);  /* regulator_enable returned OK */

	if (gpio_is_ready_dt(&imu_power_pin)) {
		/* Force a power-cycle: the UF2 bootloader does not clear the IMU
		 * rail across resets, so the chip can be stuck in a prior state.
		 *
		 * 500 ms LOW window — long enough for any rail-side capacitance
		 * to actually discharge through chip leakage current. The
		 * previous 100 ms window may have been too short to drop VDD
		 * below the chip's POR threshold, leaving it in a wedged state
		 * indistinguishable from "chip not present." This is the one
		 * variable left untested after conversation_006's verdict.
		 *
		 * GPIO_INPUT is OR'd in so gpio_pin_get_dt() below can read the
		 * actual pin state. Without it, the nRF IN register is
		 * disconnected from the pad and reads 0 regardless of OUT. */
		ret = gpio_pin_configure_dt(&imu_power_pin,
					    GPIO_OUTPUT_INACTIVE | GPIO_INPUT);
		if (ret) {
			LOG_ERR("force-drive imu_power_pin configure (low) failed: %d", ret);
		}
		gpio_pin_set_dt(&imu_power_pin, 0);
		LOG_INF("power-cycle: rail LOW, waiting 500 ms for discharge");
		k_msleep(500);
		gpio_pin_set_dt(&imu_power_pin, 1);
		LOG_INF("power-cycle: rail HIGH, waiting 50 ms for chip boot");
		k_msleep(50);  /* datasheet Tboot_max = 35 ms */
	}
	step(3);  /* power pin power-cycled to active */

	/* Read back the pin to confirm it actually went high. If it reads
	 * LOW, another consumer (regulator framework, another driver) is
	 * fighting us and the chip is still unpowered — flash RED for
	 * DIAG_FAIL_MS so the failure is obvious. GREEN otherwise. */
	if (gpio_is_ready_dt(&imu_power_pin)) {
		int level = gpio_pin_get_dt(&imu_power_pin);
		LOG_INF("imu_power_pin readback = %d", level);
		if (level == 1) {
			led_diag_flash(LED_COLOR_GREEN, 600);
		} else {
			led_diag_flash(LED_COLOR_RED, DIAG_FAIL_MS);
		}
		k_msleep(400);
	}

	k_msleep(300);  /* generous chip boot wait */

	/* Read the SDA / SCL pad levels through the nRF GPIO HAL. TWIM has the
	 * pins muxed, but the underlying pads' input buffers are enabled (TWIM
	 * needs to read SDA for ACK detection), so nrf_gpio_pin_read returns
	 * the actual line level. Both HIGH = bus idle correctly (pull-ups
	 * present, chip silent). Either LOW = no pull-ups or stuck.
	 *
	 * P0.07 = SDA (pin 7), P0.27 = SCL (pin 27) per xiao_ble-pinctrl.dtsi. */
	{
		uint32_t sda = nrf_gpio_pin_read(7);
		uint32_t scl = nrf_gpio_pin_read(27);
		LOG_INF("SDA=%u SCL=%u after power-on", sda, scl);

		/* GREEN for HIGH, RED for LOW, on each line in turn:
		 *   long yellow, SDA blink, long yellow, SCL blink, long yellow. */
		led_diag_flash(LED_COLOR_YELLOW, 1000); k_msleep(600);
		led_diag_flash(sda ? LED_COLOR_GREEN : LED_COLOR_RED, 700);
		k_msleep(600);
		led_diag_flash(LED_COLOR_YELLOW, 1000); k_msleep(600);
		led_diag_flash(scl ? LED_COLOR_GREEN : LED_COLOR_RED, 700);
		k_msleep(600);
		led_diag_flash(LED_COLOR_YELLOW, 1000); k_msleep(600);
	}

	step(4);  /* about to scan I2C bus */

	/* Drop to standard mode (100 kHz). The board DTS sets I2C_BITRATE_FAST
	 * (400 kHz); slower clock rules out signal-integrity / pull-up timing
	 * problems. If 100 kHz works and 400 kHz didn't, we'd add stronger
	 * pull-ups or stay at standard mode. */
	ret = i2c_configure(imu_i2c.bus,
			    I2C_SPEED_SET(I2C_SPEED_STANDARD) | I2C_MODE_CONTROLLER);
	if (ret) {
		LOG_WRN("i2c_configure -> 100 kHz failed: %d (continuing)", ret);
	} else {
		LOG_INF("i2c bus reconfigured to 100 kHz");
	}

	/* Direct probe at 0x6A: capture the error code so we can distinguish
	 *   -ENXIO       (6, address NACK)    → chip not on bus / unpowered / wrong mode
	 *   -EIO         (5, bus error)       → electrical fault, contention
	 *   -ETIMEDOUT   (110, line stuck)    → SDA or SCL held low somewhere
	 *
	 * Display as: long YELLOW → |err| red blinks (capped 12) → long YELLOW. */
	{
		uint8_t probe;
		struct i2c_dt_spec at6a = imu_i2c;
		at6a.addr = 0x6A;
		int e = i2c_reg_read_byte_dt(&at6a, REG_WHO_AM_I, &probe);
		LOG_INF("direct probe 0x6A WHO_AM_I -> %d (val=0x%02x)", e, probe);

		uint8_t mag = (e < 0) ? (uint8_t)(-e) : 0;
		if (mag > 12) mag = 12;
		led_diag_flash(LED_COLOR_YELLOW, 1200); k_msleep(800);
		for (uint8_t i = 0; i < mag; i++) {
			led_diag_flash(LED_COLOR_RED, 350);
			k_msleep(550);
		}
		led_diag_flash(LED_COLOR_YELLOW, 1200); k_msleep(800);

		if (e == 0) {
			/* Chip actually responded at 100 kHz — flash GREEN as a win
			 * and short-circuit the scan loop's failure path by setting
			 * found_addr/found_count. */
			LOG_INF("0x6A responded at 100 kHz (WHO_AM_I=0x%02x)", probe);
			led_diag_flash(LED_COLOR_GREEN, 1500);
		}
	}

	/* Scan the I2C bus with a real 1-byte register read (probing register
	 * 0x0F = WHO_AM_I). Nordic TWIM doesn't always NACK on zero-length
	 * writes, which produces phantom hits; a real read forces full
	 * START/ADDR/RESTART/READ/STOP traffic and either ACKs or NACKs honestly. */
	uint8_t found_addr = 0xFF;
	int found_count = 0;
	for (uint8_t addr = 0x08; addr <= 0x77; addr++) {
		uint8_t probe = 0;
		uint8_t reg = REG_WHO_AM_I;
		int s = i2c_write_read(imu_i2c.bus, addr, &reg, 1, &probe, 1);
		if (s == 0) {
			if (found_count == 0) found_addr = addr;
			found_count++;
			LOG_INF("I2C scan: device at 0x%02x (WHO_AM_I=0x%02x)", addr, probe);
		}
	}
	LOG_INF("I2C scan: %d device(s) found", found_count);

	/* Show found_count first as MAGENTA blinks (bookended by yellow). Zero
	 * blinks = nothing responded → "no slaves" failure. Anything other than
	 * 1 = bus is in a weird state or wrong driver. */
	led_diag_flash(LED_COLOR_YELLOW, 1200); k_msleep(800);
	for (int i = 0; i < (found_count < 16 ? found_count : 16); i++) {
		led_diag_flash(LED_COLOR_MAGENTA, 400);
		k_msleep(800);
	}
	led_diag_flash(LED_COLOR_YELLOW, 1200); k_msleep(800);

	if (found_count == 0) {
		/* No device on bus — chip unpowered, wrong bus, no pull-ups, etc. */
		led_diag_flash(LED_COLOR_RED, DIAG_FAIL_MS);
		return -ENODEV;
	}
	/* Show the responding I2C address using two clearly different colours:
	 *   long YELLOW (1.2 s) → GREEN blinks (high nibble) →
	 *   long YELLOW (1.2 s) → BLUE  blinks (low nibble)  →
	 *   long YELLOW (1.2 s)
	 * Each blink is 400 ms on / 800 ms off so they're easy to count.
	 * Expected 0x6A on the XIAO BLE Sense = 6 green + 10 blue. */
	led_diag_flash(LED_COLOR_YELLOW, 1200); k_msleep(800);
	for (uint8_t i = 0; i < (found_addr >> 4); i++) {
		led_diag_flash(LED_COLOR_GREEN, 400); k_msleep(800);
	}
	led_diag_flash(LED_COLOR_YELLOW, 1200); k_msleep(800);
	for (uint8_t i = 0; i < (found_addr & 0x0F); i++) {
		led_diag_flash(LED_COLOR_BLUE, 400); k_msleep(800);
	}
	led_diag_flash(LED_COLOR_YELLOW, 1200); k_msleep(1500);

	/* Now read WHO_AM_I from the device we found. */
	struct i2c_dt_spec found = imu_i2c;
	found.addr = found_addr;
	ret = i2c_reg_read_byte_dt(&found, REG_WHO_AM_I, &who);
	if (ret) {
		LOG_ERR("WHO_AM_I read at 0x%02x failed: %d", found_addr, ret);
		diag_fail(3);
		return ret;
	}
	if (who != WHO_AM_I_LSM6DS3TR && who != WHO_AM_I_LSM6DS3) {
		LOG_ERR("WHO_AM_I = 0x%02x, expected 0x69 or 0x6A", who);
		diag_fail(4);  /* chip responded with wrong ID */
		return -ENODEV;
	}
	LOG_INF("LSM6DS3TR-C detected (WHO_AM_I=0x%02x)", who);

	/* Each write gets its own diag code so a failure tells us which
	 * register the chip rejected.  Codes 6..11 = step-numbered writes. */
#define WRITE_REG(reg, val, code) do { \
		ret = i2c_reg_write_byte_dt(&imu_i2c, (reg), (val)); \
		if (ret) { \
			LOG_ERR("write reg 0x%02x = 0x%02x failed: %d", \
				(reg), (val), ret); \
			diag_fail((code)); \
			return ret; \
		} \
	} while (0)

	/* CTRL1_XL: ODR_XL=0110 (416 Hz), FS_XL=00 (±2 g) -> 0x60 */
	WRITE_REG(REG_CTRL1_XL,    0x60, 6);
	/* TAP_CFG: INTERRUPTS_ENABLE | TAP_X_EN | TAP_Y_EN | TAP_Z_EN | LIR */
	WRITE_REG(REG_TAP_CFG,     0x8F, 7);
	/* TAP_THS_6D: TAP_THS = 9 (~562 mg at ±2 g) */
	WRITE_REG(REG_TAP_THS_6D,  0x09, 8);
	/* INT_DUR2: DUR=7, QUIET=3, SHOCK=3 -> 0x7F */
	WRITE_REG(REG_INT_DUR2,    0x7F, 9);
	/* WAKE_UP_THS: SINGLE_DOUBLE_TAP=1 */
	WRITE_REG(REG_WAKE_UP_THS, 0x80, 10);
	/* MD1_CFG: INT1_SINGLE_TAP | INT1_DOUBLE_TAP */
	WRITE_REG(REG_MD1_CFG,     0x48, 11);

#undef WRITE_REG

	k_work_init(&tap_work, tap_work_fn);

	ret = gpio_pin_configure_dt(&imu_irq, GPIO_INPUT);
	if (ret) {
		LOG_ERR("IRQ GPIO configure failed: %d", ret);
		return ret;
	}
	ret = gpio_pin_interrupt_configure_dt(&imu_irq, GPIO_INT_EDGE_TO_ACTIVE);
	if (ret) {
		LOG_ERR("IRQ GPIO interrupt configure failed: %d", ret);
		return ret;
	}
	gpio_init_callback(&irq_cb, imu_irq_handler, BIT(imu_irq.pin));
	ret = gpio_add_callback(imu_irq.port, &irq_cb);
	if (ret) {
		LOG_ERR("IRQ GPIO add_callback failed: %d", ret);
		return ret;
	}

	LOG_INF("IMU tap detection active (single + double on X/Y/Z)");
	led_diag_flash(LED_COLOR_GREEN, DIAG_OK_MS);
	return 0;
}
