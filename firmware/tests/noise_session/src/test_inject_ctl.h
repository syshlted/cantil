/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

#pragma once

#include <stdint.h>
#include <stdbool.h>

void test_inject_arm(const uint8_t s_priv[32], const uint8_t s_pub[32],
		     const uint8_t e_priv[32], const uint8_t e_pub[32]);
void test_inject_disarm(void);
