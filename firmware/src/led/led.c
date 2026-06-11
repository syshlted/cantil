/* LED layer — pattern animator.
 *
 * Two concepts: an *idle* pattern (one of the device-state loops, e.g. LOCKED
 * heartbeat / UNLOCKED rainbow) and a *one-shot* pattern (transient feedback
 * — TAP_ACK, FAIL, CONFIRMED, etc.). One-shots preempt the active idle; on
 * completion the idle resumes from the start of its next period.
 *
 * Rendering backends:
 *   - PWM-RGB  (xiao_ble overlay): full 8-bit HSV via pwm-leds children.
 *   - GPIO-RGB (other 3-LED boards): degraded on/off per channel.
 *   - GPIO mono: any non-OFF color turns the single LED on.
 *
 * Patterns come in two shapes:
 *   - STEPS  : list of (color, duration) frames.
 *   - PROC   : a render fn (t_ms → r,g,b) — used for smooth crossfades
 *              (LOCKED orange↔red) and the UNLOCKED rainbow HSV sweep.
 *
 * All scheduling runs on a single delayable work item; nothing blocks the
 * caller. The previous pulse_train()-based code blocked the gesture thread
 * long enough to drop logs and miss back-to-back taps.
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/led.h>
#include <zephyr/drivers/pwm.h>
#include <zephyr/logging/log.h>
#include <stdbool.h>
#include <string.h>

#include "led.h"

LOG_MODULE_REGISTER(led, LOG_LEVEL_INF);

/* -------------------------------------------------------------------- */
/* Backend selection                                                     */
/* -------------------------------------------------------------------- */

#define LED_R_NODE DT_ALIAS(cantil_led_r)
#define LED_G_NODE DT_ALIAS(cantil_led_g)
#define LED_B_NODE DT_ALIAS(cantil_led_b)
#define LED_MONO_NODE DT_ALIAS(cantil_led)

/* PWM mode iff the R alias points at a pwm-leds child. */
#if DT_NODE_EXISTS(LED_R_NODE) && DT_NODE_HAS_COMPAT(DT_PARENT(LED_R_NODE), pwm_leds)
#define HAVE_RGB_PWM 1
#else
#define HAVE_RGB_PWM 0
#endif

#if !HAVE_RGB_PWM && (DT_NODE_EXISTS(LED_R_NODE) || DT_NODE_EXISTS(LED_G_NODE) || DT_NODE_EXISTS(LED_B_NODE))
#define HAVE_RGB_GPIO 1
#else
#define HAVE_RGB_GPIO 0
#endif

#if !HAVE_RGB_PWM && !HAVE_RGB_GPIO
BUILD_ASSERT(DT_NODE_EXISTS(LED_MONO_NODE),
	     "Need cantil-led-{r,g,b} (PWM or GPIO) or cantil-led mono alias");
#define HAVE_MONO 1
#else
#define HAVE_MONO 0
#endif

#if HAVE_RGB_PWM
static const struct device *pwm_dev;
#define LED_IDX_R DT_NODE_CHILD_IDX(LED_R_NODE)
#define LED_IDX_G DT_NODE_CHILD_IDX(LED_G_NODE)
#define LED_IDX_B DT_NODE_CHILD_IDX(LED_B_NODE)
#elif HAVE_RGB_GPIO
#define HAVE_R DT_NODE_EXISTS(LED_R_NODE)
#define HAVE_G DT_NODE_EXISTS(LED_G_NODE)
#define HAVE_B DT_NODE_EXISTS(LED_B_NODE)
static const struct gpio_dt_spec led_r =
	COND_CODE_1(DT_NODE_EXISTS(LED_R_NODE), (GPIO_DT_SPEC_GET(LED_R_NODE, gpios)), ({0}));
static const struct gpio_dt_spec led_g =
	COND_CODE_1(DT_NODE_EXISTS(LED_G_NODE), (GPIO_DT_SPEC_GET(LED_G_NODE, gpios)), ({0}));
static const struct gpio_dt_spec led_b =
	COND_CODE_1(DT_NODE_EXISTS(LED_B_NODE), (GPIO_DT_SPEC_GET(LED_B_NODE, gpios)), ({0}));
#else
static const struct gpio_dt_spec led_mono = GPIO_DT_SPEC_GET(LED_MONO_NODE, gpios);
#endif

/* -------------------------------------------------------------------- */
/* RGB rendering                                                         */
/* -------------------------------------------------------------------- */

static void render_rgb8(uint8_t r, uint8_t g, uint8_t b)
{
#if HAVE_RGB_PWM
	/* led-pwm driver scales 0–255 → duty. Inverted polarity (set in DT)
	 * means brightness=255 → LED fully on. */
	if (pwm_dev) {
		led_set_brightness(pwm_dev, LED_IDX_R, (r * 100) / 255);
		led_set_brightness(pwm_dev, LED_IDX_G, (g * 100) / 255);
		led_set_brightness(pwm_dev, LED_IDX_B, (b * 100) / 255);
	}
#elif HAVE_RGB_GPIO
#if HAVE_R
	gpio_pin_set_dt(&led_r, r > 127);
#endif
#if HAVE_G
	gpio_pin_set_dt(&led_g, g > 127);
#endif
#if HAVE_B
	gpio_pin_set_dt(&led_b, b > 127);
#endif
#else
	gpio_pin_set_dt(&led_mono, (r | g | b) ? 1 : 0);
#endif
}

/* Semantic colour → 8-bit RGB triplet. Approximations chosen so GPIO-only
 * boards (>127 threshold) still light up the right primary channels. */
static void color_to_rgb8(led_color_t c, uint8_t *r, uint8_t *g, uint8_t *b)
{
	switch (c) {
	case LED_COLOR_OFF:       *r=0;   *g=0;   *b=0;   break;
	case LED_COLOR_RED:       *r=255; *g=0;   *b=0;   break;
	case LED_COLOR_ORANGE:    *r=255; *g=128; *b=0;   break;
	case LED_COLOR_YELLOW:    *r=255; *g=255; *b=0;   break;
	case LED_COLOR_GREEN:     *r=0;   *g=255; *b=0;   break;
	case LED_COLOR_CYAN:      *r=0;   *g=255; *b=255; break;
	case LED_COLOR_BLUE:      *r=0;   *g=0;   *b=255; break;
	case LED_COLOR_PURPLE:    *r=160; *g=0;   *b=255; break;
	case LED_COLOR_MAGENTA:   *r=255; *g=0;   *b=255; break;
	case LED_COLOR_WHITE:     *r=255; *g=255; *b=255; break;
	case LED_COLOR_DIM_WHITE: *r=26;  *g=26;  *b=26;  break;
	default:                  *r=0;   *g=0;   *b=0;   break;
	}
}

static void render_color(led_color_t c)
{
	uint8_t r, g, b;
	color_to_rgb8(c, &r, &g, &b);
	render_rgb8(r, g, b);
}

/* HSV → RGB. h in 0–359, s and v in 0–255. Used by rainbow + crossfade. */
static void hsv_to_rgb8(uint16_t h, uint8_t s, uint8_t v,
			uint8_t *r, uint8_t *g, uint8_t *b)
{
	if (s == 0) { *r = *g = *b = v; return; }

	uint8_t  region = (h / 60) % 6;
	uint32_t f      = ((h % 60) * 255) / 60;
	uint8_t  p = (v * (255 - s)) / 255;
	uint8_t  q = (v * (255 - ((s * f) / 255))) / 255;
	uint8_t  t = (v * (255 - ((s * (255 - f)) / 255))) / 255;

	switch (region) {
	case 0: *r = v; *g = t; *b = p; break;
	case 1: *r = q; *g = v; *b = p; break;
	case 2: *r = p; *g = v; *b = t; break;
	case 3: *r = p; *g = q; *b = v; break;
	case 4: *r = t; *g = p; *b = v; break;
	default:*r = v; *g = p; *b = q; break;
	}
}

/* -------------------------------------------------------------------- */
/* Pattern table                                                         */
/* -------------------------------------------------------------------- */

typedef struct {
	led_color_t color;
	uint16_t    duration_ms;
} step_t;

typedef void (*proc_render_fn)(uint32_t t_ms,
			       uint8_t *r, uint8_t *g, uint8_t *b);

typedef struct {
	bool                 loop;        /* true → idle (replays forever)   */
	/* step list (NULL if procedural) */
	const step_t        *steps;
	uint16_t             n_steps;
	/* procedural (NULL if step-based) */
	proc_render_fn       proc;
	uint16_t             proc_period_ms; /* one period; tick cadence too */
} pattern_def_t;

/* ------------ procedural renderers ----------------------------------- */

/* Triangle wave 0..255..0 over `period_ms`. */
static uint8_t tri_wave(uint32_t t_ms, uint32_t period_ms)
{
	uint32_t half = period_ms / 2;
	uint32_t t    = t_ms % period_ms;
	if (t < half) return (t * 255) / half;
	return ((period_ms - t) * 255) / half;
}

/* LOCKED: red → orange → yellow → orange → red, over 4 s.
 * R stays full (255); G triangle-waves 0..255..0. The natural midpoint
 * (G≈128) reads as orange; the peak (G=255) reads as yellow. */
static void proc_locked(uint32_t t_ms, uint8_t *r, uint8_t *g, uint8_t *b)
{
	*r = 255;
	*g = tri_wave(t_ms, 4000);
	*b = 0;
}

static void proc_locked_default_seq(uint32_t t_ms, uint8_t *r, uint8_t *g, uint8_t *b)
{
	*r = 255;
	*g = tri_wave(t_ms, 2000);
	*b = 0;
}

/* LOCKED_CONNECTED: orange↔red plus an 80 ms cyan blip every 3 s. */
static void proc_locked_connected(uint32_t t_ms, uint8_t *r, uint8_t *g, uint8_t *b)
{
	if ((t_ms % 3000) < 80) {
		*r = 0; *g = 255; *b = 255;
		return;
	}
	proc_locked(t_ms, r, g, b);
}

/* UNLOCKED: smooth rainbow HSV sweep, 10 s period, 25% brightness. */
static void proc_unlocked(uint32_t t_ms, uint8_t *r, uint8_t *g, uint8_t *b)
{
	uint16_t h = (t_ms % 10000) * 360 / 10000;
	hsv_to_rgb8(h, 255, 64, r, g, b);  /* V=64 ≈ 25% */
}

/* -------- step tables ------------------------------------------------ */

/* Step macros: STEP(color, ms) */
#define STEPS(name, ...) \
	static const step_t name[] = { __VA_ARGS__ }

STEPS(steps_tap_ack,        {LED_COLOR_DIM_WHITE, 30});
STEPS(steps_digit_ack,      {LED_COLOR_WHITE, 80});
STEPS(steps_locking,        {LED_COLOR_WHITE, 150});
STEPS(steps_ready,          {LED_COLOR_YELLOW, 500});
STEPS(steps_verify,         {LED_COLOR_YELLOW, 250}, {LED_COLOR_OFF, 250},
			    {LED_COLOR_YELLOW, 250});
STEPS(steps_must_change_seq,{LED_COLOR_YELLOW, 100}, {LED_COLOR_OFF, 100},
			    {LED_COLOR_YELLOW, 100}, {LED_COLOR_OFF, 100},
			    {LED_COLOR_YELLOW, 100}, {LED_COLOR_OFF, 100});
STEPS(steps_unlocked_blink, {LED_COLOR_GREEN, 100}, {LED_COLOR_OFF, 100},
			    {LED_COLOR_GREEN, 100}, {LED_COLOR_OFF, 100},
			    {LED_COLOR_GREEN, 100}, {LED_COLOR_OFF, 100},
			    {LED_COLOR_GREEN, 100}, {LED_COLOR_OFF, 100});
STEPS(steps_pairing_success,{LED_COLOR_GREEN, 300}, {LED_COLOR_OFF, 150},
			    {LED_COLOR_GREEN, 300}, {LED_COLOR_OFF, 150},
			    {LED_COLOR_GREEN, 300}, {LED_COLOR_OFF, 150});
STEPS(steps_confirmed,      {LED_COLOR_GREEN, 800});
STEPS(steps_fw_applied,     {LED_COLOR_ORANGE, 1000});
STEPS(steps_reset_complete, {LED_COLOR_WHITE, 500}, {LED_COLOR_OFF, 500},
			    {LED_COLOR_WHITE, 500}, {LED_COLOR_OFF, 500},
			    {LED_COLOR_WHITE, 500}, {LED_COLOR_OFF, 500});
STEPS(steps_fail,           {LED_COLOR_RED, 80}, {LED_COLOR_OFF, 80},
			    {LED_COLOR_RED, 80}, {LED_COLOR_OFF, 80},
			    {LED_COLOR_RED, 80}, {LED_COLOR_OFF, 80});
STEPS(steps_seq_error,      {LED_COLOR_RED, 375}, {LED_COLOR_YELLOW, 375},
			    {LED_COLOR_RED, 375}, {LED_COLOR_YELLOW, 375});
STEPS(steps_busy_reject,    {LED_COLOR_RED, 80}, {LED_COLOR_OFF, 80},
			    {LED_COLOR_RED, 80});
STEPS(steps_post,           {LED_COLOR_BLUE, 250}, {LED_COLOR_GREEN, 250});

STEPS(steps_pairing_loop,         {LED_COLOR_MAGENTA, 100}, {LED_COLOR_OFF, 100});
STEPS(steps_pairing_prompt_loop,  {LED_COLOR_CYAN, 200},    {LED_COLOR_OFF, 200});
STEPS(steps_passkey_prompt_loop,  {LED_COLOR_PURPLE, 150},  {LED_COLOR_OFF, 150});
STEPS(steps_confirm_prompt_loop,  {LED_COLOR_YELLOW, 400},  {LED_COLOR_OFF, 600});
STEPS(steps_reset_prompt_loop,   {LED_COLOR_RED, 100},     {LED_COLOR_OFF, 300});
STEPS(steps_reset_wiping_loop,   {LED_COLOR_RED, 1000});  /* solid (re-fires) */
STEPS(steps_thinking_loop,       {LED_COLOR_RED, 100},
				 {LED_COLOR_GREEN, 100},
				 {LED_COLOR_BLUE, 100});
/* Recovery mode (T-03): sustained red↔yellow, slower and steadier than the
 * 375 ms SEQ_ERROR one-shot so it reads as a persistent alarm. */
STEPS(steps_identity_mismatch_loop, {LED_COLOR_RED, 500}, {LED_COLOR_YELLOW, 500});
/* Firmware update: MCUboot rejected the pushed image — magenta↔red alarm. */
STEPS(steps_fw_invalid_loop, {LED_COLOR_MAGENTA, 500}, {LED_COLOR_RED, 500});

#define STEP_DEF(arr, loop_)  { .loop = (loop_), .steps = (arr), \
				.n_steps = ARRAY_SIZE(arr) }
#define PROC_DEF(fn, period_)  { .loop = true, .proc = (fn), \
				 .proc_period_ms = (period_) }

static const pattern_def_t pattern_defs[] = {
	[LED_PATTERN_OFF]               = { .loop = true, .steps = NULL, .n_steps = 0 },

	[LED_PATTERN_LOCKED]             = PROC_DEF(proc_locked, 4000),
	[LED_PATTERN_LOCKED_DEFAULT_SEQ] = PROC_DEF(proc_locked_default_seq, 2000),
	[LED_PATTERN_LOCKED_CONNECTED]   = PROC_DEF(proc_locked_connected, 3000),
	[LED_PATTERN_UNLOCKED]           = PROC_DEF(proc_unlocked, 10000),
	[LED_PATTERN_PAIRING]            = STEP_DEF(steps_pairing_loop, true),
	[LED_PATTERN_PAIRING_PROMPT]     = STEP_DEF(steps_pairing_prompt_loop, true),
	[LED_PATTERN_PASSKEY_PROMPT]     = STEP_DEF(steps_passkey_prompt_loop, true),
	[LED_PATTERN_CONFIRM_PROMPT]     = STEP_DEF(steps_confirm_prompt_loop, true),
	[LED_PATTERN_RESET_PROMPT]       = STEP_DEF(steps_reset_prompt_loop, true),
	[LED_PATTERN_RESET_WIPING]       = STEP_DEF(steps_reset_wiping_loop, true),
	[LED_PATTERN_THINKING]           = STEP_DEF(steps_thinking_loop, true),
	[LED_PATTERN_IDENTITY_MISMATCH]  = STEP_DEF(steps_identity_mismatch_loop, true),
	[LED_PATTERN_FW_INVALID]         = STEP_DEF(steps_fw_invalid_loop, true),

	[LED_PATTERN_POST]               = STEP_DEF(steps_post, false),
	[LED_PATTERN_TAP_ACK]            = STEP_DEF(steps_tap_ack, false),
	[LED_PATTERN_DIGIT_ACK]          = STEP_DEF(steps_digit_ack, false),
	[LED_PATTERN_LOCKING]            = STEP_DEF(steps_locking, false),
	[LED_PATTERN_READY]              = STEP_DEF(steps_ready, false),
	[LED_PATTERN_VERIFY]             = STEP_DEF(steps_verify, false),
	[LED_PATTERN_MUST_CHANGE_SEQ]    = STEP_DEF(steps_must_change_seq, false),
	[LED_PATTERN_UNLOCKED_BLINK]     = STEP_DEF(steps_unlocked_blink, false),
	[LED_PATTERN_PAIRING_SUCCESS]    = STEP_DEF(steps_pairing_success, false),
	[LED_PATTERN_CONFIRMED]          = STEP_DEF(steps_confirmed, false),
	[LED_PATTERN_RESET_COMPLETE]     = STEP_DEF(steps_reset_complete, false),
	[LED_PATTERN_FAIL]               = STEP_DEF(steps_fail, false),
	[LED_PATTERN_SEQ_ERROR]          = STEP_DEF(steps_seq_error, false),
	[LED_PATTERN_BUSY_REJECT]        = STEP_DEF(steps_busy_reject, false),
	[LED_PATTERN_FW_APPLIED]         = STEP_DEF(steps_fw_applied, false),
};

/* -------------------------------------------------------------------- */
/* Animator                                                              */
/* -------------------------------------------------------------------- */

/* Procedural patterns tick at this cadence for smooth animation. */
#define PROC_TICK_MS 33  /* ~30 Hz */

static struct k_mutex anim_mutex;
static struct k_work_delayable tick_work;

static led_pattern_t active_idle    = LED_PATTERN_OFF;
static led_pattern_t active_oneshot = LED_PATTERN_OFF;

/* Current animator state, owned by tick_work_fn under anim_mutex. */
static int64_t   anim_start_ms;
static uint16_t  step_idx;

static const pattern_def_t *active_def(void)
{
	led_pattern_t p = (active_oneshot != LED_PATTERN_OFF)
				? active_oneshot : active_idle;
	if (p >= ARRAY_SIZE(pattern_defs)) return &pattern_defs[LED_PATTERN_OFF];
	return &pattern_defs[p];
}

static void anim_reset(void)
{
	anim_start_ms = k_uptime_get();
	step_idx      = 0;
}

static void schedule_tick(uint32_t delay_ms)
{
	k_work_reschedule(&tick_work, K_MSEC(delay_ms));
}

static void tick_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);
	k_mutex_lock(&anim_mutex, K_FOREVER);

	const pattern_def_t *def = active_def();

	if (!def || (def->steps == NULL && def->proc == NULL)) {
		render_color(LED_COLOR_OFF);
		goto out;
	}

	int64_t  now    = k_uptime_get();
	uint32_t t_ms   = (uint32_t)(now - anim_start_ms);

	if (def->proc) {
		/* Procedural (rainbow / crossfade). Check completion first so
		 * we never call the renderer with t outside its design range. */
		if (!def->loop && def->proc_period_ms &&
		    t_ms >= def->proc_period_ms) {
			goto pattern_done;
		}
		uint32_t t_mod = def->loop && def->proc_period_ms
				   ? (t_ms % def->proc_period_ms) : t_ms;
		uint8_t r, g, b;
		def->proc(t_mod, &r, &g, &b);
		render_rgb8(r, g, b);
		schedule_tick(PROC_TICK_MS);
		goto out;
	}

	/* Step-based. Find the active step. */
	uint32_t acc = 0;
	uint16_t i;
	uint32_t total = 0;
	for (i = 0; i < def->n_steps; i++) total += def->steps[i].duration_ms;

	if (def->loop && total > 0) t_ms %= total;

	if (!def->loop && t_ms >= total) goto pattern_done;

	for (i = 0; i < def->n_steps; i++) {
		uint32_t step_end = acc + def->steps[i].duration_ms;
		if (t_ms < step_end) {
			step_idx = i;
			render_color(def->steps[i].color);
			schedule_tick(step_end - t_ms);
			goto out;
		}
		acc = step_end;
	}
	/* fell off the end of a loop=false pattern */
	goto pattern_done;

pattern_done:
	if (active_oneshot != LED_PATTERN_OFF) {
		active_oneshot = LED_PATTERN_OFF;
		anim_reset();
		k_mutex_unlock(&anim_mutex);
		/* re-enter to render the resumed idle immediately */
		tick_work_fn(NULL);
		return;
	}
	/* idle finished and didn't loop — go dark */
	render_color(LED_COLOR_OFF);

out:
	k_mutex_unlock(&anim_mutex);
}

/* -------------------------------------------------------------------- */
/* Public API                                                            */
/* -------------------------------------------------------------------- */

int led_init(void)
{
	k_mutex_init(&anim_mutex);
	k_work_init_delayable(&tick_work, tick_work_fn);

#if HAVE_RGB_PWM
	pwm_dev = DEVICE_DT_GET(DT_PARENT(LED_R_NODE));
	if (!device_is_ready(pwm_dev)) {
		LOG_ERR("pwm-leds device not ready");
		return -ENODEV;
	}
#elif HAVE_RGB_GPIO
#if HAVE_R
	if (!gpio_is_ready_dt(&led_r) ||
	    gpio_pin_configure_dt(&led_r, GPIO_OUTPUT_INACTIVE)) return -ENODEV;
#endif
#if HAVE_G
	if (!gpio_is_ready_dt(&led_g) ||
	    gpio_pin_configure_dt(&led_g, GPIO_OUTPUT_INACTIVE)) return -ENODEV;
#endif
#if HAVE_B
	if (!gpio_is_ready_dt(&led_b) ||
	    gpio_pin_configure_dt(&led_b, GPIO_OUTPUT_INACTIVE)) return -ENODEV;
#endif
#else
	if (!gpio_is_ready_dt(&led_mono) ||
	    gpio_pin_configure_dt(&led_mono, GPIO_OUTPUT_INACTIVE)) return -ENODEV;
#endif

	render_color(LED_COLOR_OFF);
	return 0;
}

void led_set_idle(led_pattern_t pattern)
{
	k_mutex_lock(&anim_mutex, K_FOREVER);
	if (pattern != active_idle) {
		active_idle = pattern;
		if (active_oneshot == LED_PATTERN_OFF) {
			anim_reset();
			k_work_reschedule(&tick_work, K_NO_WAIT);
		}
		/* If a one-shot is running we don't disturb it; the new idle
		 * will take effect when the one-shot completes. */
	}
	k_mutex_unlock(&anim_mutex);
}

void led_play_oneshot(led_pattern_t pattern)
{
	k_mutex_lock(&anim_mutex, K_FOREVER);
	active_oneshot = pattern;
	anim_reset();
	k_work_reschedule(&tick_work, K_NO_WAIT);
	k_mutex_unlock(&anim_mutex);
}

/* Heuristic dispatcher for legacy call sites. */
static bool is_loop_pattern(led_pattern_t p)
{
	switch (p) {
	case LED_PATTERN_OFF:
	case LED_PATTERN_LOCKED:
	case LED_PATTERN_LOCKED_DEFAULT_SEQ:
	case LED_PATTERN_LOCKED_CONNECTED:
	case LED_PATTERN_UNLOCKED:
	case LED_PATTERN_PAIRING:
	case LED_PATTERN_PAIRING_PROMPT:
	case LED_PATTERN_PASSKEY_PROMPT:
	case LED_PATTERN_CONFIRM_PROMPT:
	case LED_PATTERN_RESET_PROMPT:
	case LED_PATTERN_RESET_WIPING:
	case LED_PATTERN_THINKING:
	case LED_PATTERN_IDENTITY_MISMATCH:
	case LED_PATTERN_FW_INVALID:
		return true;
	default:
		return false;
	}
}

void led_set_pattern(led_pattern_t pattern)
{
	if (is_loop_pattern(pattern)) {
		led_set_idle(pattern);
	} else {
		led_play_oneshot(pattern);
	}
}

/* Blocking helpers (diag only; not on the gesture path). ----------------*/

void led_diag_flash(uint8_t color, uint32_t ms)
{
	/* Pause the animator so we own the LED for the duration. */
	k_mutex_lock(&anim_mutex, K_FOREVER);
	k_work_cancel_delayable(&tick_work);
	render_color((led_color_t)color);
	k_msleep(ms);
	render_color(LED_COLOR_OFF);
	/* Restart the animator from the start of the active idle (if any). */
	anim_reset();
	if (active_idle != LED_PATTERN_OFF || active_oneshot != LED_PATTERN_OFF) {
		k_work_reschedule(&tick_work, K_NO_WAIT);
	}
	k_mutex_unlock(&anim_mutex);
}

void led_blink_digit(uint8_t digit)
{
	k_mutex_lock(&anim_mutex, K_FOREVER);
	k_work_cancel_delayable(&tick_work);
	for (uint8_t i = 0; i < digit; i++) {
		render_color(LED_COLOR_WHITE);
		k_msleep(100);
		render_color(LED_COLOR_OFF);
		if (i < digit - 1) k_msleep(100);
	}
	k_msleep(500);
	anim_reset();
	if (active_idle != LED_PATTERN_OFF || active_oneshot != LED_PATTERN_OFF) {
		k_work_reschedule(&tick_work, K_NO_WAIT);
	}
	k_mutex_unlock(&anim_mutex);
}
