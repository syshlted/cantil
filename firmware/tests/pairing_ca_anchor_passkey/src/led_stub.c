/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

#include <zephyr/kernel.h>
#include "led/led.h"

int led_init(void) { return 0; }

void led_set_idle(led_pattern_t pattern)     { ARG_UNUSED(pattern); }
void led_play_oneshot(led_pattern_t pattern) { ARG_UNUSED(pattern); }
void led_set_pattern(led_pattern_t pattern)  { ARG_UNUSED(pattern); }

void led_blink_digit(uint8_t digit) { ARG_UNUSED(digit); }

void led_diag_flash(uint8_t color, uint32_t ms)
{
	ARG_UNUSED(color);
	ARG_UNUSED(ms);
}
