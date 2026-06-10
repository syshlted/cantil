/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

/*
 * Gesture stub for the pairing_passkey ztest suite (T-18).
 *
 * gesture_request_pair_confirm() is called by pairing.c (PAIRING_PASSKEY)
 * after the passkey is validated, to get user tap-confirmation.
 * The callback fires synchronously with whatever result was set via
 * pairing_passkey_test_set_gesture_result().
 */

#include "gesture/gesture.h"

static cantil_confirm_result_t stub_result = CANTIL_CONFIRM_OK;

void pairing_passkey_test_set_gesture_result(cantil_confirm_result_t r)
{
	stub_result = r;
}

int gesture_request_pair_confirm(cantil_confirm_cb_t cb, void *user_data)
{
	cb(stub_result, user_data);
	return 0;
}
