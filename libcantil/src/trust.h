#pragma once

#include "../include/cantil.h"
#include <stddef.h>
#include <stdint.h>

/*
 * Internal layout of cantil_trust_store_t (opaque in the public header).
 *
 * A dynamic array of DER cert blobs — one blob per allowlisted CA. Used by
 * Tier 3/4 policy evaluation to walk the device's cert chain.
 */
struct cantil_trust_store {
    uint8_t **cert_der;   /* malloc'd DER blobs */
    size_t   *cert_len;   /* corresponding byte lengths */
    size_t    count;
    size_t    capacity;
};

/*
 * Evaluate the trust policy against the device identity chain already stored
 * in `s` (populated during the Noise_XX handshake, T-04).
 *
 * Called by cantil_session_open() after the handshake is complete.
 *
 * Returns CANTIL_OK on success, CANTIL_ERR_TRUST on policy rejection,
 * CANTIL_ERR_NOT_SUPPORTED for unimplemented tiers (T-13).
 */
cantil_err_t cantil_trust_check_policy(const cantil_trust_policy_t *policy,
                                       const struct cantil_session  *s);
