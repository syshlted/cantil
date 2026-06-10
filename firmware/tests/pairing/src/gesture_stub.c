/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

/*
 * Gesture stub for the pairing ztest suite (T-17).
 *
 * gesture_request_pair_confirm() is called by pairing.c (PAIRING_TAP_CONFIRM)
 * when an unknown client connects.  In this stub the callback fires
 * synchronously with whatever result pairing_test_set_gesture_result() loaded
 * — no real gesture hardware or work queue needed.
 *
 * The k_sem_give() inside the callback is called before gesture_request_pair_
 * confirm() returns, so the k_sem_take() in pairing.c sees count=1 and returns
 * immediately.
 */

#include "gesture/gesture.h"

static cantil_confirm_result_t stub_result = CANTIL_CONFIRM_OK;

void pairing_test_set_gesture_result(cantil_confirm_result_t r)
{
	stub_result = r;
}

int gesture_request_pair_confirm(cantil_confirm_cb_t cb, void *user_data)
{
	cb(stub_result, user_data);
	return 0;
}
