#pragma once

#include <stdint.h>

/* Semantic colours. On PWM-RGB boards these resolve to HSV values rendered via
 * PWM duty cycle. On GPIO-only RGB boards they degrade to on/off combinations.
 * On mono boards any non-OFF colour turns the LED on. */
typedef enum {
	LED_COLOR_OFF,
	LED_COLOR_RED,
	LED_COLOR_ORANGE,
	LED_COLOR_YELLOW,
	LED_COLOR_GREEN,
	LED_COLOR_CYAN,
	LED_COLOR_BLUE,
	LED_COLOR_PURPLE,
	LED_COLOR_MAGENTA,
	LED_COLOR_WHITE,
	LED_COLOR_DIM_WHITE,   /* ~10% brightness — TAP_ACK */
} led_color_t;

typedef enum {
	LED_PATTERN_OFF,

	/* --- Idle / loop patterns (set via led_set_idle) ----------------- */
	LED_PATTERN_LOCKED,            /* red→orange→yellow→orange, 4 s cycle  */
	LED_PATTERN_LOCKED_DEFAULT_SEQ,/* same cycle, 2× speed (2 s cycle)     */
	LED_PATTERN_LOCKED_CONNECTED,  /* LOCKED + cyan blip every 3 s         */
	LED_PATTERN_UNLOCKED,          /* rainbow HSV sweep, 10 s, 25% bright  */
	LED_PATTERN_PAIRING,           /* magenta 100/100 loop                 */
	LED_PATTERN_PAIRING_PROMPT,    /* cyan 200/200 loop — AWAITING_PAIR    */
	LED_PATTERN_PASSKEY_PROMPT,    /* purple 150/150 loop — passkey entry  */
	LED_PATTERN_CONFIRM_PROMPT,    /* yellow 400/600 loop                  */
	LED_PATTERN_RESET_PROMPT,      /* red 100/300 loop                     */
	LED_PATTERN_RESET_WIPING,      /* red solid                            */
	LED_PATTERN_THINKING,          /* red→green→blue 100 ms each, loop     */
	LED_PATTERN_IDENTITY_MISMATCH, /* red↔yellow 500/500 loop — recovery   */
	LED_PATTERN_FW_INVALID,        /* magenta↔red 500/500 loop — rejected image */

	/* --- One-shot patterns (set via led_play_oneshot) ---------------- */
	LED_PATTERN_POST,              /* blue 250 ms, green 250 ms            */
	LED_PATTERN_TAP_ACK,           /* dim white 30 ms                      */
	LED_PATTERN_DIGIT_ACK,         /* white 80 ms                          */
	LED_PATTERN_LOCKING,           /* white 150 ms                         */
	LED_PATTERN_READY,             /* yellow 500 ms                        */
	LED_PATTERN_VERIFY,            /* yellow 250/250/250                   */
	LED_PATTERN_MUST_CHANGE_SEQ,   /* yellow 3×(100/100)                   */
	LED_PATTERN_UNLOCKED_BLINK,    /* green 4×(100/100)                    */
	LED_PATTERN_PAIRING_SUCCESS,   /* green 3×(300/150)                    */
	LED_PATTERN_CONFIRMED,         /* green 800 ms                         */
	LED_PATTERN_RESET_COMPLETE,    /* white 3×(500/500)                    */
	LED_PATTERN_FAIL,              /* red 6×80 ms toggle                   */
	LED_PATTERN_SEQ_ERROR,         /* red↔yellow 4× over 1.5 s             */
	LED_PATTERN_BUSY_REJECT,       /* red 2×80 ms                          */
	LED_PATTERN_FW_APPLIED,        /* orange 1000 ms — pre-reboot after FW update */
} led_pattern_t;

int led_init(void);

/* Set the persistent "idle" pattern for the current device state. One-shots
 * preempt this; when a one-shot completes the idle pattern resumes from the
 * start of its next period. Passing LED_PATTERN_OFF clears the idle. */
void led_set_idle(led_pattern_t pattern);

/* Play a transient one-shot. Returns to the active idle pattern when done.
 * Non-blocking — driven by a delayable work item. */
void led_play_oneshot(led_pattern_t pattern);

/* Back-compat wrapper. Dispatches to set_idle for loop patterns and
 * play_oneshot for transient patterns. Kept so call sites that don't care
 * about the distinction stay short. New code should call the explicit form. */
void led_set_pattern(led_pattern_t pattern);

/* Blink digit N (1–9) as N flashes. Blocking. Used for BLE passkey display.
 * Caller is responsible for the 1000 ms inter-group pause. */
void led_blink_digit(uint8_t digit);

/* Show a solid colour for ms, then off. Blocking. Diagnostic-only — used by
 * tap_imu.c boot probes that run before the work queue is fully up. Do not
 * call from app code on the gesture path; use led_play_oneshot instead. */
void led_diag_flash(uint8_t color, uint32_t ms);
