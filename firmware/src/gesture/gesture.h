#pragma once

#include <stdint.h>
#include <stdbool.h>

typedef enum {
	CANTIL_STATE_LOCKED,
	CANTIL_STATE_UNLOCKED,
	CANTIL_STATE_PAIRING,
	CANTIL_STATE_CHANGE_SEQ_CONFIRM,
	CANTIL_STATE_CHANGE_SEQ_VERIFY,
	CANTIL_STATE_AWAITING_CONFIRM,  /* host issued PROTECT_SLOT/UNPROTECT_SLOT */
	CANTIL_STATE_AWAITING_RESET,    /* host issued RESET_DEVICE */
	CANTIL_STATE_AWAITING_PAIR,     /* unknown client — waiting tap-confirm to bond */
} cantil_state_t;

typedef enum {
	CANTIL_TAP_SINGLE = 1,
	CANTIL_TAP_DOUBLE = 2,
} cantil_tap_t;

/* Result of an awaiting-confirm flow, delivered to the requesting handler. */
typedef enum {
	CANTIL_CONFIRM_OK,
	CANTIL_CONFIRM_DENIED,   /* wrong gesture */
	CANTIL_CONFIRM_TIMEOUT,
} cantil_confirm_result_t;

typedef void (*cantil_confirm_cb_t)(cantil_confirm_result_t result, void *user_data);

int gesture_init(void);

/* Report a classified tap (ST or DT). Used by input drivers that distinguish
 * single from double tap. In the COUNT_COLOR alphabet a DOUBLE counts as two
 * physical taps inside the current digit. */
void gesture_report_tap(cantil_tap_t tap);

/* Report a single raw physical tap. Preferred for input drivers that don't
 * (or shouldn't) classify ST/DT — notably any driver feeding the COUNT_COLOR
 * alphabet, where every tap independently bumps the current digit's count. */
void gesture_report_raw_tap(void);

cantil_state_t gesture_get_state(void);
void gesture_reset_inactivity_timer(void);

/* Begin AWAITING_CONFIRM. Caller is invoked when the user taps the confirm
 * gesture (DT DT DT), enters a wrong sequence, or the timeout expires.
 * Returns 0 on success, -EBUSY if the device is not UNLOCKED, -EALREADY if
 * a confirm flow is already in flight. */
/*
 * Replace the unlock sequence from a host command (SET_UNLOCK_SEQ).
 * Device must be UNLOCKED. Persists to storage. Returns 0 on success,
 * -EBUSY if not UNLOCKED, -EINVAL if seq is empty or too long.
 */
int gesture_set_unlock_seq(const uint8_t *seq, uint8_t len);

int gesture_request_confirm(cantil_confirm_cb_t cb, void *user_data);

/* Begin AWAITING_RESET. Caller is invoked when the user re-enters the
 * current unlock sequence, enters a wrong sequence, or the timeout expires.
 * Returns 0 on success, -EBUSY if not UNLOCKED, -EALREADY if a confirm/reset
 * flow is already in flight. */
int gesture_request_reset(cantil_confirm_cb_t cb, void *user_data);

/* Begin AWAITING_PAIR. Caller is invoked when the user taps the pairing
 * trigger (Orange Orange), enters a wrong sequence, or the timeout expires.
 * Accepts LOCKED or UNLOCKED as the originating state (a client may connect
 * while the device is in either state).
 * Returns 0 on success, -EBUSY if in an incompatible state,
 * -EALREADY if any confirm flow is already in flight. */
int gesture_request_pair_confirm(cantil_confirm_cb_t cb, void *user_data);
