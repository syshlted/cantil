/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

/* Pairing passkey reply — Method 3 client-side (transport + pairing T-18). */

#include <stdint.h>
#include <string.h>

#include "../include/cantil.h"
#include "internal.h"
#include "cantil_cbor.h"

/* Device blinks 6 digits then does a tap-confirm — we allow up to 90 s. */
#define PASSKEY_TIMEOUT_MS 90000

cantil_err_t cantil_pairing_passkey_reply(cantil_session_t *s, uint32_t digits)
{
    if (!s) return CANTIL_ERR_INVALID_ARG;
    if (digits == 0 || digits > 999999U) return CANTIL_ERR_INVALID_ARG;

    /* Encode the digits as a CBOR uint, then wrap in the request data bstr. */
    uint8_t digit_cbor[9];
    size_t  digit_cbor_len = 0;

    if (cantil_cbor_emit_uint(digit_cbor, sizeof(digit_cbor),
                              &digit_cbor_len, digits) != 0) {
        return CANTIL_ERR_INVALID_ARG;
    }

    uint8_t scratch[32];
    const uint8_t *resp_data = NULL;
    size_t resp_data_len = 0;

    return cantil_do_request_to(s,
                                CMD_PAIRING_PASSKEY_REPLY, 0x01,
                                digit_cbor, digit_cbor_len,
                                scratch, sizeof(scratch),
                                &resp_data, &resp_data_len,
                                PASSKEY_TIMEOUT_MS);
}
