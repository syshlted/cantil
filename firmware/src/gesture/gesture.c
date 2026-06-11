#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <errno.h>
#include <string.h>

#include "gesture.h"
#include "led/led.h"
#include "storage/storage.h"

LOG_MODULE_REGISTER(gesture, LOG_LEVEL_INF);

#define SEQ_MAX_LEN   16

/*
 * Tap alphabets
 * =============
 * A "digit" in digit_buf[] is one element of the parsed sequence.
 *
 *   STDT_PLAIN:  digit = 1 (SINGLE) or 2 (DOUBLE).
 *   STDT_BINARY: digit = 0..6 color index. Triplet 1-1-1 yields DIGIT_INVALID.
 *                Triplets close implicitly every 3 taps (no per-digit silence).
 *   COUNT_COLOR: digit = 1..PALETTE_SIZE. A tap_count exceeding PALETTE_SIZE
 *                yields DIGIT_INVALID. Digits are closed by DIGIT_TIMEOUT_MS
 *                of silence; the whole sequence by an additional SEQ_TIMEOUT_MS.
 *
 * The state machine matches digit_buf against fixed uint8_t arrays and is
 * alphabet-agnostic. Only the accumulator layer changes.
 */

#if defined(CONFIG_CANTIL_ALPHABET_COUNT_COLOR)
#  define PALETTE_SIZE        CONFIG_CANTIL_UNLOCK_PALETTE_SIZE
#  define DIGIT_INVALID       0xFF
static const uint8_t SEQ_UNLOCK_DEFAULT[]     = {1, 1, 1, 1}; /* Red x4 */
static const uint8_t SEQ_LOCK[]               = {1};          /* Red (1 tap) */
static const uint8_t SEQ_PAIRING_TRIGGER[]    = {2, 2};       /* Orange Orange */
static const uint8_t SEQ_CHANGE_SEQ_TRIGGER[] = {3, 3, 3};    /* Yellow x3 */
static const uint8_t SEQ_CONFIRM[]            = {3, 3, 3};    /* Purple x3 */
#  ifdef CONFIG_CANTIL_GESTURE_REHEARSAL
static const uint8_t SEQ_REHEARSE_PROTECT[]   = {4, 4};       /* Blue Blue */
static const uint8_t SEQ_REHEARSE_RESET[]     = {5, 5};       /* Cyan Cyan */
#  endif
#elif defined(CONFIG_CANTIL_ALPHABET_STDT_BINARY)
#  define DIGIT_INVALID       0xFF
static const uint8_t SEQ_UNLOCK_DEFAULT[]     = {0, 0, 0, 0}; /* Red x4 (000 x4) */
static const uint8_t SEQ_LOCK[]               = {0};          /* Red (000) */
static const uint8_t SEQ_PAIRING_TRIGGER[]    = {1, 1};       /* Orange Orange */
static const uint8_t SEQ_CHANGE_SEQ_TRIGGER[] = {2, 2, 2};    /* Yellow x3 */
static const uint8_t SEQ_CONFIRM[]            = {3, 3, 3};    /* Purple x3 */
#  ifdef CONFIG_CANTIL_GESTURE_REHEARSAL
static const uint8_t SEQ_REHEARSE_PROTECT[]   = {4, 4};
static const uint8_t SEQ_REHEARSE_RESET[]     = {5, 5};
#  endif
#else /* CONFIG_CANTIL_ALPHABET_STDT_PLAIN */
#  define DIGIT_INVALID       0xFF
static const uint8_t SEQ_UNLOCK_DEFAULT[]     = {1, 2, 1, 2}; /* ST DT ST DT */
static const uint8_t SEQ_LOCK[]               = {1};          /* ST (single tap) */
static const uint8_t SEQ_PAIRING_TRIGGER[]    = {2, 2, 1, 1}; /* DT DT ST ST */
static const uint8_t SEQ_CHANGE_SEQ_TRIGGER[] = {2, 1, 2, 1}; /* DT ST DT ST */
static const uint8_t SEQ_CONFIRM[]            = {2, 2, 2};    /* DT DT DT */
#  ifdef CONFIG_CANTIL_GESTURE_REHEARSAL
static const uint8_t SEQ_REHEARSE_PROTECT[]   = {2, 2, 2, 2};
static const uint8_t SEQ_REHEARSE_RESET[]     = {1, 1, 1, 1};
#  endif
#endif

#ifdef CONFIG_CANTIL_GESTURE_REHEARSAL
static void rehearsal_cb(cantil_confirm_result_t result, void *user_data)
{
	ARG_UNUSED(user_data);
	LOG_INF("rehearsal: confirm callback result=%d", result);
}
#endif

static cantil_state_t state = CANTIL_STATE_LOCKED;

/* Canonical parsed sequence: one digit per element. */
static uint8_t digit_buf[SEQ_MAX_LEN];
static uint8_t digit_count;

/* Accumulator state */
#if defined(CONFIG_CANTIL_ALPHABET_COUNT_COLOR)
static uint8_t cur_taps;  /* taps in the digit currently being entered */
/* Phase of the silence timer:
 *   1 = collecting a digit; next timer-fire closes the digit
 *   2 = digit closed, awaiting next digit or seq close; next timer-fire closes seq
 */
static uint8_t silence_phase;
#elif defined(CONFIG_CANTIL_ALPHABET_STDT_BINARY)
static uint8_t bit_buf[SEQ_MAX_LEN * 3];
static uint8_t bit_count;
#endif

static uint8_t unlock_seq[SEQ_MAX_LEN];
static uint8_t unlock_seq_len;
static bool using_default_seq;
static bool forced_change_active;

static uint8_t new_seq[SEQ_MAX_LEN];
static uint8_t new_seq_len;

static int64_t last_activity_ms;

/* Failed-unlock rate limiting. failure_count persists across reboot via
 * storage_unlock_attempts_*; lockout_until_ms is uptime-relative and lost
 * on reboot — but the next wrong attempt re-applies the same-tier lockout,
 * so power-cycling can only restart the current tier, not skip it. */
static uint32_t failure_count;
static int64_t  lockout_until_ms;

static uint32_t lockout_seconds_for_count(uint32_t c)
{
	/* c is the failure-count *after* incrementing. The first lockout fires
	 * at c == THRESHOLD + 1. Schedule: 10 s, 30 s, 2 min, 10 min, 1 h. */
	uint32_t over = c - CONFIG_CANTIL_UNLOCK_RATE_LIMIT_THRESHOLD;
	switch (over) {
	case 1: return 10;
	case 2: return 30;
	case 3: return 120;
	case 4: return 600;
	default: return 3600;
	}
}

static bool unlock_in_lockout(void)
{
	return lockout_until_ms != 0 && k_uptime_get() < lockout_until_ms;
}

static void note_unlock_failure(void)
{
	failure_count++;
	(void)storage_unlock_attempts_write(failure_count);
	if (failure_count > CONFIG_CANTIL_UNLOCK_RATE_LIMIT_THRESHOLD) {
		uint32_t s = lockout_seconds_for_count(failure_count);
		lockout_until_ms = k_uptime_get() + (int64_t)s * 1000;
		LOG_WRN("unlock lockout: %u failures, locked for %u s",
			failure_count, s);
	} else {
		LOG_INF("unlock failure %u (no lockout yet)", failure_count);
	}
}

static void note_unlock_success(void)
{
	if (failure_count != 0) {
		failure_count = 0;
		lockout_until_ms = 0;
		(void)storage_unlock_attempts_write(0);
	}
}

static cantil_confirm_cb_t pending_cb;
static void              *pending_cb_data;
static cantil_state_t      pre_await_state;

static K_MUTEX_DEFINE(gesture_mutex);

static void process_sequence(void);
static void confirm_timeout_fn(struct k_work *work);
static void reset_timeout_fn(struct k_work *work);
static void pair_timeout_fn(struct k_work *work);
static void silence_timeout_fn(struct k_work *work);

static K_WORK_DELAYABLE_DEFINE(silence_timeout_work, silence_timeout_fn);
static K_WORK_DELAYABLE_DEFINE(confirm_timeout_work, confirm_timeout_fn);
static K_WORK_DELAYABLE_DEFINE(reset_timeout_work,   reset_timeout_fn);
static K_WORK_DELAYABLE_DEFINE(pair_timeout_work,    pair_timeout_fn);

static void reset_accumulator(void)
{
	digit_count = 0;
#if defined(CONFIG_CANTIL_ALPHABET_COUNT_COLOR)
	cur_taps = 0;
	silence_phase = 0;
#elif defined(CONFIG_CANTIL_ALPHABET_STDT_BINARY)
	bit_count = 0;
#endif
}

static bool seq_match(const uint8_t *a, uint8_t a_len,
		      const uint8_t *b, uint8_t b_len)
{
	return (a_len == b_len) && (memcmp(a, b, a_len) == 0);
}

static bool is_factory_default(const uint8_t *seq, uint8_t len)
{
	return seq_match(seq, len, SEQ_UNLOCK_DEFAULT, sizeof(SEQ_UNLOCK_DEFAULT));
}

static bool seq_has_invalid(const uint8_t *seq, uint8_t len)
{
	for (uint8_t i = 0; i < len; i++) {
		if (seq[i] == DIGIT_INVALID) {
			return true;
		}
	}
	return false;
}

static led_pattern_t idle_for_state(cantil_state_t s)
{
	switch (s) {
	case CANTIL_STATE_LOCKED:
		return using_default_seq ? LED_PATTERN_LOCKED_DEFAULT_SEQ
					: LED_PATTERN_LOCKED;
	case CANTIL_STATE_UNLOCKED:            return LED_PATTERN_UNLOCKED;
	case CANTIL_STATE_PAIRING:             return LED_PATTERN_PAIRING;
	case CANTIL_STATE_AWAITING_PAIR:       return LED_PATTERN_PAIRING_PROMPT;
	case CANTIL_STATE_AWAITING_CONFIRM:    return LED_PATTERN_CONFIRM_PROMPT;
	case CANTIL_STATE_AWAITING_RESET:      return LED_PATTERN_RESET_PROMPT;
	case CANTIL_STATE_CHANGE_SEQ_CONFIRM:  return LED_PATTERN_UNLOCKED;
	case CANTIL_STATE_CHANGE_SEQ_VERIFY:   return LED_PATTERN_UNLOCKED;
	default:                              return LED_PATTERN_OFF;
	}
}

static void transition(cantil_state_t next)
{
	LOG_INF("state %d -> %d", state, next);
	state = next;
	led_set_idle(idle_for_state(next));
}

static void deliver_confirm(cantil_confirm_result_t result)
{
	cantil_confirm_cb_t cb   = pending_cb;
	void              *data = pending_cb_data;
	pending_cb      = NULL;
	pending_cb_data = NULL;

	if (cb) {
		k_mutex_unlock(&gesture_mutex);
		cb(result, data);
		k_mutex_lock(&gesture_mutex, K_FOREVER);
	}
}

static void confirm_timeout_fn(struct k_work *work)
{
	ARG_UNUSED(work);
	k_mutex_lock(&gesture_mutex, K_FOREVER);
	if (state == CANTIL_STATE_AWAITING_CONFIRM) {
		LOG_INF("confirm timeout");
		transition(CANTIL_STATE_UNLOCKED);
		led_play_oneshot(LED_PATTERN_FAIL);
		deliver_confirm(CANTIL_CONFIRM_TIMEOUT);
	}
	k_mutex_unlock(&gesture_mutex);
}

static void reset_timeout_fn(struct k_work *work)
{
	ARG_UNUSED(work);
	k_mutex_lock(&gesture_mutex, K_FOREVER);
	if (state == CANTIL_STATE_AWAITING_RESET) {
		LOG_INF("reset timeout");
		transition(pre_await_state);
		led_play_oneshot(LED_PATTERN_FAIL);
		deliver_confirm(CANTIL_CONFIRM_TIMEOUT);
	}
	k_mutex_unlock(&gesture_mutex);
}

static void pair_timeout_fn(struct k_work *work)
{
	ARG_UNUSED(work);
	k_mutex_lock(&gesture_mutex, K_FOREVER);
	if (state == CANTIL_STATE_AWAITING_PAIR) {
		LOG_INF("pairing prompt timeout");
		transition(pre_await_state);
		led_play_oneshot(LED_PATTERN_FAIL);
		deliver_confirm(CANTIL_CONFIRM_TIMEOUT);
	}
	k_mutex_unlock(&gesture_mutex);
}

#if defined(CONFIG_CANTIL_ALPHABET_COUNT_COLOR)
static void close_digit_locked(void)
{
	if (cur_taps == 0 || digit_count >= SEQ_MAX_LEN) {
		cur_taps = 0;
		return;
	}
	uint8_t digit = (cur_taps > PALETTE_SIZE) ? DIGIT_INVALID : cur_taps;
	digit_buf[digit_count++] = digit;
	cur_taps = 0;
	led_play_oneshot(LED_PATTERN_DIGIT_ACK);
}
#endif

#if defined(CONFIG_CANTIL_ALPHABET_STDT_BINARY)
static void close_sequence_binary_locked(void)
{
	/* Convert bit_buf (groups of 3) into digit_buf. Anything that isn't
	 * a clean multiple of 3 produces a sequence with DIGIT_INVALID so
	 * the matcher will fall through to the failure path. */
	digit_count = 0;
	if (bit_count == 0) {
		return;
	}
	uint8_t triples = bit_count / 3;
	uint8_t leftover = bit_count - (triples * 3);
	for (uint8_t i = 0; i < triples && digit_count < SEQ_MAX_LEN; i++) {
		uint8_t b0 = bit_buf[i * 3 + 0];
		uint8_t b1 = bit_buf[i * 3 + 1];
		uint8_t b2 = bit_buf[i * 3 + 2];
		uint8_t code = (uint8_t)((b0 << 2) | (b1 << 1) | b2);
		digit_buf[digit_count++] = (code == 0x7) ? DIGIT_INVALID : code;
	}
	if (leftover && digit_count < SEQ_MAX_LEN) {
		digit_buf[digit_count++] = DIGIT_INVALID;
	}
	bit_count = 0;
}
#endif

static void silence_timeout_fn(struct k_work *work)
{
	ARG_UNUSED(work);
	k_mutex_lock(&gesture_mutex, K_FOREVER);

#if defined(CONFIG_CANTIL_ALPHABET_COUNT_COLOR)
	if (silence_phase == 1) {
		/* Digit close. Record the digit, then arm seq-close. */
		close_digit_locked();
		silence_phase = 2;
		k_work_reschedule(&silence_timeout_work,
				  K_MSEC(CONFIG_CANTIL_SEQ_TIMEOUT_MS));
		k_mutex_unlock(&gesture_mutex);
		return;
	}
	/* phase == 2: sequence close. */
	silence_phase = 0;
	if (digit_count > 0) {
		process_sequence();
		reset_accumulator();
	}
#elif defined(CONFIG_CANTIL_ALPHABET_STDT_BINARY)
	close_sequence_binary_locked();
	if (digit_count > 0) {
		process_sequence();
	}
	reset_accumulator();
#else /* STDT_PLAIN */
	if (digit_count > 0) {
		process_sequence();
		reset_accumulator();
	}
#endif

	k_mutex_unlock(&gesture_mutex);
}

static void process_sequence(void)
{
	const bool has_invalid = seq_has_invalid(digit_buf, digit_count);

	/* Restore the current state's idle pattern (cleared by each tap so the
	 * LED stays dark during entry). If a transition() fires below, it will
	 * override with the new state's idle; otherwise the user sees the
	 * locked/unlocked loop resume after the FAIL/SEQ_ERROR one-shot. */
	led_set_idle(idle_for_state(state));

	switch (state) {
	case CANTIL_STATE_LOCKED:
		if (!has_invalid &&
		    seq_match(digit_buf, digit_count, unlock_seq, unlock_seq_len)) {
			note_unlock_success();
			if (using_default_seq) {
				LOG_INF("unlocked with factory default — forcing sequence change");
				forced_change_active = true;
				led_play_oneshot(LED_PATTERN_MUST_CHANGE_SEQ);
				transition(CANTIL_STATE_CHANGE_SEQ_CONFIRM);
			} else {
				transition(CANTIL_STATE_UNLOCKED);
				led_play_oneshot(LED_PATTERN_UNLOCKED_BLINK);
			}
		} else {
			note_unlock_failure();
			led_play_oneshot(has_invalid ? LED_PATTERN_SEQ_ERROR
						     : LED_PATTERN_FAIL);
		}
		break;

	case CANTIL_STATE_UNLOCKED:
		if (has_invalid) {
			led_play_oneshot(LED_PATTERN_SEQ_ERROR);
			break;
		}
		if (seq_match(digit_buf, digit_count,
			      SEQ_LOCK, sizeof(SEQ_LOCK))) {
			led_play_oneshot(LED_PATTERN_LOCKING);
			transition(CANTIL_STATE_LOCKED);
		} else if (seq_match(digit_buf, digit_count,
			      SEQ_PAIRING_TRIGGER, sizeof(SEQ_PAIRING_TRIGGER))) {
			transition(CANTIL_STATE_PAIRING);
		} else if (seq_match(digit_buf, digit_count,
				     SEQ_CHANGE_SEQ_TRIGGER,
				     sizeof(SEQ_CHANGE_SEQ_TRIGGER))) {
			transition(CANTIL_STATE_CHANGE_SEQ_CONFIRM);
			led_play_oneshot(LED_PATTERN_READY);
#ifdef CONFIG_CANTIL_GESTURE_REHEARSAL
		} else if (seq_match(digit_buf, digit_count,
				     SEQ_REHEARSE_PROTECT,
				     sizeof(SEQ_REHEARSE_PROTECT))) {
			LOG_INF("rehearsal: simulating PROTECT_SLOT");
			pending_cb      = rehearsal_cb;
			pending_cb_data = NULL;
			transition(CANTIL_STATE_AWAITING_CONFIRM);
			k_work_reschedule(&confirm_timeout_work,
				K_SECONDS(CONFIG_CANTIL_CONFIRM_TIMEOUT_SEC));
		} else if (seq_match(digit_buf, digit_count,
				     SEQ_REHEARSE_RESET,
				     sizeof(SEQ_REHEARSE_RESET))) {
			LOG_INF("rehearsal: simulating RESET_DEVICE");
			pending_cb      = rehearsal_cb;
			pending_cb_data = NULL;
			transition(CANTIL_STATE_AWAITING_RESET);
			k_work_reschedule(&reset_timeout_work,
				K_SECONDS(CONFIG_CANTIL_RESET_TIMEOUT_SEC));
#endif
		} else {
			led_play_oneshot(LED_PATTERN_FAIL);
		}
		break;

	case CANTIL_STATE_CHANGE_SEQ_CONFIRM:
		if (has_invalid) {
			led_play_oneshot(LED_PATTERN_SEQ_ERROR);
			break;
		}
		if (digit_count > 0 && digit_count <= SEQ_MAX_LEN) {
			memcpy(new_seq, digit_buf, digit_count);
			new_seq_len = digit_count;
			transition(CANTIL_STATE_CHANGE_SEQ_VERIFY);
			led_play_oneshot(LED_PATTERN_VERIFY);
		}
		break;

	case CANTIL_STATE_CHANGE_SEQ_VERIFY:
		if (!has_invalid &&
		    seq_match(digit_buf, digit_count, new_seq, new_seq_len)) {
			memcpy(unlock_seq, new_seq, new_seq_len);
			unlock_seq_len = new_seq_len;
			using_default_seq = is_factory_default(unlock_seq,
							       unlock_seq_len);
			forced_change_active = false;
			int wr = storage_unlock_seq_write(unlock_seq, unlock_seq_len);

			if (wr) {
				LOG_ERR("failed to persist unlock sequence: %d", wr);
			}
			transition(CANTIL_STATE_UNLOCKED);
			led_play_oneshot(LED_PATTERN_UNLOCKED_BLINK);
		} else if (forced_change_active) {
			forced_change_active = false;
			transition(CANTIL_STATE_LOCKED);
			led_play_oneshot(LED_PATTERN_FAIL);
		} else {
			transition(CANTIL_STATE_UNLOCKED);
			led_play_oneshot(LED_PATTERN_FAIL);
		}
		break;

	case CANTIL_STATE_AWAITING_CONFIRM:
		k_work_cancel_delayable(&confirm_timeout_work);
		if (!has_invalid &&
		    seq_match(digit_buf, digit_count, SEQ_CONFIRM, sizeof(SEQ_CONFIRM))) {
			transition(CANTIL_STATE_UNLOCKED);
			led_play_oneshot(LED_PATTERN_CONFIRMED);
			deliver_confirm(CANTIL_CONFIRM_OK);
		} else {
			transition(CANTIL_STATE_UNLOCKED);
			led_play_oneshot(LED_PATTERN_FAIL);
			deliver_confirm(CANTIL_CONFIRM_DENIED);
		}
		break;

	case CANTIL_STATE_AWAITING_RESET:
		k_work_cancel_delayable(&reset_timeout_work);
		if (!has_invalid &&
		    seq_match(digit_buf, digit_count, unlock_seq, unlock_seq_len)) {
			transition(pre_await_state);
			led_play_oneshot(LED_PATTERN_CONFIRMED);
			deliver_confirm(CANTIL_CONFIRM_OK);
		} else {
			transition(pre_await_state);
			led_play_oneshot(LED_PATTERN_FAIL);
			deliver_confirm(CANTIL_CONFIRM_DENIED);
		}
		break;

	case CANTIL_STATE_AWAITING_PAIR:
		k_work_cancel_delayable(&pair_timeout_work);
		if (!has_invalid &&
		    seq_match(digit_buf, digit_count,
			      SEQ_PAIRING_TRIGGER, sizeof(SEQ_PAIRING_TRIGGER))) {
			transition(pre_await_state);
			led_play_oneshot(LED_PATTERN_PAIRING_SUCCESS);
			deliver_confirm(CANTIL_CONFIRM_OK);
		} else {
			transition(pre_await_state);
			led_play_oneshot(LED_PATTERN_FAIL);
			deliver_confirm(CANTIL_CONFIRM_DENIED);
		}
		break;

	default:
		break;
	}
}

int gesture_init(void)
{
	memcpy(unlock_seq, SEQ_UNLOCK_DEFAULT, sizeof(SEQ_UNLOCK_DEFAULT));
	unlock_seq_len = sizeof(SEQ_UNLOCK_DEFAULT);

	size_t stored_len = sizeof(unlock_seq);
	int ret_seq = storage_unlock_seq_read(unlock_seq, &stored_len);

	if (ret_seq == 0 && stored_len > 0 && stored_len <= SEQ_MAX_LEN) {
		unlock_seq_len = (uint8_t)stored_len;
		LOG_INF("loaded persisted unlock sequence (%u digits)", unlock_seq_len);
	} else {
		memcpy(unlock_seq, SEQ_UNLOCK_DEFAULT, sizeof(SEQ_UNLOCK_DEFAULT));
		unlock_seq_len = sizeof(SEQ_UNLOCK_DEFAULT);
		if (ret_seq != -ENOENT) {
			LOG_WRN("unlock_seq_read failed (%d), using factory default",
				ret_seq);
		}
	}

	using_default_seq = is_factory_default(unlock_seq, unlock_seq_len);
	forced_change_active = false;

	/* Restore persisted failure counter. -ENOENT just means the file has
	 * never been written (fresh device or post-wipe). lockout_until_ms
	 * stays 0 — the active lockout timer is uptime-relative and is
	 * intentionally dropped across reboot; the next wrong attempt will
	 * re-apply the same-tier lockout based on the persisted count. */
	failure_count = 0;
	lockout_until_ms = 0;
	uint32_t persisted = 0;
	int ret_att = storage_unlock_attempts_read(&persisted);
	if (ret_att == 0) {
		failure_count = persisted;
		if (persisted) {
			LOG_WRN("restored unlock failure count from storage: %u",
				persisted);
		}
	} else if (ret_att != -ENOENT) {
		LOG_WRN("unlock_attempts_read failed (%d), starting at 0", ret_att);
	}

	last_activity_ms = k_uptime_get();
	reset_accumulator();

#if defined(CONFIG_CANTIL_INPUT_IMU)
	extern int tap_imu_init(void);
	int ret = tap_imu_init();

	if (ret) {
		LOG_WRN("tap_imu_init failed: %d (tap input unavailable)", ret);
	}
#endif

#if defined(CONFIG_CANTIL_INPUT_MIC)
	extern int tap_mic_init(void);
	int mret = tap_mic_init();

	if (mret) {
		LOG_WRN("tap_mic_init failed: %d (mic tap unavailable)", mret);
	}
#endif

	return 0;
}

void gesture_report_tap(cantil_tap_t tap)
{
	/* Rate-limit gate. Taps that arrive during an active unlock lockout
	 * are dropped before any accumulator state changes — they get a
	 * BUSY_REJECT blink instead of TAP_ACK so the user can see the
	 * device is intentionally ignoring them. The locked-loop idle is
	 * left intact so the colour cycle keeps running. */
	k_mutex_lock(&gesture_mutex, K_FOREVER);
	bool dropped = (state == CANTIL_STATE_LOCKED && unlock_in_lockout());
	k_mutex_unlock(&gesture_mutex);
	if (dropped) {
		LOG_INF("tap dropped: unlock lockout active");
		led_play_oneshot(LED_PATTERN_BUSY_REJECT);
		return;
	}

	/* Per-tap visual ack — fires before logging so the user sees the tap
	 * land even when the USB CDC log backend drops messages.
	 *
	 * Clear the cycling idle first so the LED goes dark after the white
	 * blink instead of resuming the colour loop. The idle is restored at
	 * sequence-close (process_sequence) so the user sees the locked
	 * indicator again after they finish entering. */
	led_set_idle(LED_PATTERN_OFF);
	led_play_oneshot(LED_PATTERN_TAP_ACK);

	k_mutex_lock(&gesture_mutex, K_FOREVER);

#if defined(CONFIG_CANTIL_ALPHABET_COUNT_COLOR)
	/* COUNT_COLOR ignores the ST/DT distinction. A DOUBLE arriving here
	 * (e.g. from a board that still classifies) counts as two physical
	 * taps; SINGLE counts as one. */
	uint8_t inc = (tap == CANTIL_TAP_DOUBLE) ? 2 : 1;
	if ((uint16_t)cur_taps + inc <= 0xFF) {
		cur_taps += inc;
	}
	silence_phase = 1;
	LOG_INF("tap +%u (cur=%u, digits=%u, state=%d)",
		inc, cur_taps, digit_count, state);
	k_work_reschedule(&silence_timeout_work,
			  K_MSEC(CONFIG_CANTIL_DIGIT_TIMEOUT_MS));
#elif defined(CONFIG_CANTIL_ALPHABET_STDT_BINARY)
	if (bit_count < (uint8_t)(SEQ_MAX_LEN * 3)) {
		bit_buf[bit_count++] = (tap == CANTIL_TAP_DOUBLE) ? 1 : 0;
	}
	LOG_INF("tap %s (bits=%u, state=%d)",
		tap == CANTIL_TAP_DOUBLE ? "1" : "0", bit_count, state);
	k_work_reschedule(&silence_timeout_work,
			  K_MSEC(CONFIG_CANTIL_SEQ_TIMEOUT_MS));
#else /* STDT_PLAIN */
	if (digit_count < SEQ_MAX_LEN) {
		digit_buf[digit_count++] = (uint8_t)tap;
	}
	LOG_INF("tap %s (buf=%u, state=%d)",
		tap == CANTIL_TAP_DOUBLE ? "DOUBLE" : "SINGLE",
		digit_count, state);
	k_work_reschedule(&silence_timeout_work,
			  K_MSEC(CONFIG_CANTIL_SEQ_TIMEOUT_MS));
#endif

	k_mutex_unlock(&gesture_mutex);
}

void gesture_report_raw_tap(void)
{
	/* Raw physical-tap path. COUNT_COLOR consumes it natively; STDT_*
	 * alphabets receive each raw tap as a SINGLE so the parser still
	 * makes forward progress when the input driver can't classify. */
	gesture_report_tap(CANTIL_TAP_SINGLE);
}

cantil_state_t gesture_get_state(void)
{
	cantil_state_t s;

	k_mutex_lock(&gesture_mutex, K_FOREVER);
	s = state;

	if (s == CANTIL_STATE_UNLOCKED) {
		int64_t idle_ms = k_uptime_get() - last_activity_ms;

		if (idle_ms >= (int64_t)CONFIG_CANTIL_INACTIVITY_TIMEOUT_SEC * 1000) {
			LOG_INF("auto-lock: inactivity timeout");
			state = CANTIL_STATE_LOCKED;
			led_set_idle(LED_PATTERN_LOCKED);
			s = CANTIL_STATE_LOCKED;
		}
	}

	k_mutex_unlock(&gesture_mutex);
	return s;
}

void gesture_reset_inactivity_timer(void)
{
	k_mutex_lock(&gesture_mutex, K_FOREVER);
	last_activity_ms = k_uptime_get();
	k_mutex_unlock(&gesture_mutex);
}

int gesture_set_unlock_seq(const uint8_t *seq, uint8_t len)
{
	if (len == 0 || len > SEQ_MAX_LEN || !seq) {
		return -EINVAL;
	}

	int ret = 0;

	k_mutex_lock(&gesture_mutex, K_FOREVER);

	if (state != CANTIL_STATE_UNLOCKED) {
		ret = -EBUSY;
		goto out;
	}

	memcpy(unlock_seq, seq, len);
	unlock_seq_len = len;
	using_default_seq = is_factory_default(unlock_seq, unlock_seq_len);

	int wr = storage_unlock_seq_write(unlock_seq, unlock_seq_len);

	if (wr) {
		LOG_ERR("set_unlock_seq: persist failed: %d", wr);
		ret = wr;
		goto out;
	}

	LOG_INF("unlock sequence set via host command (%u digits)", len);

out:
	k_mutex_unlock(&gesture_mutex);
	return ret;
}

int gesture_request_confirm(cantil_confirm_cb_t cb, void *user_data)
{
	int ret = 0;

	k_mutex_lock(&gesture_mutex, K_FOREVER);
	if (state != CANTIL_STATE_UNLOCKED) {
		ret = -EBUSY;
		goto out;
	}
	if (pending_cb) {
		ret = -EALREADY;
		goto out;
	}
	pending_cb      = cb;
	pending_cb_data = user_data;
	reset_accumulator();
	transition(CANTIL_STATE_AWAITING_CONFIRM);
	k_work_reschedule(&confirm_timeout_work,
			  K_SECONDS(CONFIG_CANTIL_CONFIRM_TIMEOUT_SEC));
out:
	k_mutex_unlock(&gesture_mutex);
	return ret;
}

int gesture_request_reset(cantil_confirm_cb_t cb, void *user_data)
{
	int ret = 0;

	k_mutex_lock(&gesture_mutex, K_FOREVER);
	if (IS_ENABLED(CONFIG_CANTIL_RESET_REQUIRES_UNLOCK)) {
		if (state != CANTIL_STATE_UNLOCKED) {
			ret = -EBUSY;
			goto out;
		}
	} else {
		if (state != CANTIL_STATE_UNLOCKED &&
		    state != CANTIL_STATE_LOCKED) {
			ret = -EBUSY;
			goto out;
		}
	}
	if (pending_cb) {
		ret = -EALREADY;
		goto out;
	}
	pending_cb      = cb;
	pending_cb_data = user_data;
	pre_await_state = state;
	reset_accumulator();
	transition(CANTIL_STATE_AWAITING_RESET);
	k_work_reschedule(&reset_timeout_work,
			  K_SECONDS(CONFIG_CANTIL_RESET_TIMEOUT_SEC));
out:
	k_mutex_unlock(&gesture_mutex);
	return ret;
}

int gesture_request_pair_confirm(cantil_confirm_cb_t cb, void *user_data)
{
	int ret = 0;

	k_mutex_lock(&gesture_mutex, K_FOREVER);
	if (state != CANTIL_STATE_UNLOCKED && state != CANTIL_STATE_LOCKED) {
		ret = -EBUSY;
		goto out;
	}
	if (pending_cb) {
		ret = -EALREADY;
		goto out;
	}
	pending_cb      = cb;
	pending_cb_data = user_data;
	pre_await_state = state;
	reset_accumulator();
	transition(CANTIL_STATE_AWAITING_PAIR);
	k_work_reschedule(&pair_timeout_work,
			  K_SECONDS(CONFIG_CANTIL_PAIR_TIMEOUT_SEC));
out:
	k_mutex_unlock(&gesture_mutex);
	return ret;
}
