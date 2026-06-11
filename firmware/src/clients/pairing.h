/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

#pragma once

#include <stdint.h>
#include "session/session.h"

/*
 * pairing_check_and_bond() — device-side pairing gate (transport+pairing T-16–T-18).
 *
 * Called after Noise_XX completes, with the verified initiator static pubkey and
 * the established session (needed for PAIRING_PASSKEY passkey exchange).
 * Returns 0 to allow the session, negative errno to reject it.
 *
 * Behaviour is selected by CONFIG_CANTIL_PAIRING_METHOD:
 *   PAIRING_PROMISCUOUS  — always returns 0 (no bond stored).
 *   PAIRING_TOFU         — known client: 0; unknown + room: silently bonds + 0;
 *                          unknown + cap full: -EACCES.
 *   PAIRING_TAP_CONFIRM  — known client: 0; cap full: -EACCES (no prompt);
 *                          unknown + room: enters AWAITING_PAIR, blocks until
 *                          user taps Orange-Orange (OK) or timeout/wrong
 *                          sequence (EACCES); on OK bonds the client and
 *                          returns 0.
 *   PAIRING_PASSKEY      — known client: 0 (no re-prompt); cap full: -EACCES;
 *                          unknown + room: blinks 6-digit passkey on LED, waits
 *                          for CMD_PAIRING_PASSKEY_REPLY from client, validates
 *                          digits, tap-confirms, derives PSK, bonds, stores PSK.
 */
int pairing_check_and_bond(const uint8_t pub[32], cantil_session_t *session);
