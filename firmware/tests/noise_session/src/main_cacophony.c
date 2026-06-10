/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

/*
 * Cacophony-vector entry: drives session.c against xx_vector_cacophony.h,
 * which uses the keypairs from the published Cacophony reference vector
 * for Noise_XX_25519_ChaChaPoly_SHA256.  The published vector's prologue
 * and per-handshake payloads can't be driven through session.c directly
 * (session.c uses empty prologue + empty payloads), so the vector header
 * is re-derived with session.c's wire format using primitives that have
 * been independently validated against the full Cacophony trace — see
 * gen_cacophony_vector.py.
 *
 * Linking against the same loopback / inject / session sources as the
 * primary suite, this gives the full test pipeline a second key set
 * grounded in a published reference.
 */

#include "xx_vector_cacophony.h"

#define SUITE_NAME noise_session_cacophony

#include "noise_session_tests.inc"
