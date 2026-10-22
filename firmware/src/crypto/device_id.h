/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

#pragma once

#include <stdint.h>

/*
 * The device's 64-bit unique ID, little-endian.
 *
 * Deliberately a standalone module with no crypto dependency. Three callers
 * need it and only two of them want mbedtls or PSA linked:
 *
 *   - crypto.c / crypto_psa.c, as the IKM for the storage key. Both backends
 *     must derive bit-identical keys from it, which is why this lives in one
 *     place rather than being reimplemented per backend as it once was.
 *   - the volume identity marker, to bind a filesystem to the die that
 *     created it.
 *   - the step-1 factory image, which writes that marker and has no reason to
 *     carry a TLS stack.
 *
 * On non-nRF builds (native_sim ztests) this returns a fixed test value. The
 * contract that matters is that repeated calls agree; both the real FICR and
 * the host fallback satisfy it.
 *
 * This is an identifier, not a secret. It is readable by anything on the die
 * and is stored in plaintext in the volume marker. Never use it as key
 * material directly — crypto_storage_key_derive() runs it through HKDF.
 */
void crypto_device_id(uint8_t out[8]);
