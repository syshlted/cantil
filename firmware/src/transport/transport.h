/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct cantil_transport cantil_transport_t;

typedef int (*transport_send_fn)(cantil_transport_t *t, const uint8_t *buf, size_t len);
typedef int (*transport_recv_fn)(cantil_transport_t *t, uint8_t *buf, size_t max_len,
				 size_t *received);
/*
 * True while the peer is still attached (USB DTR asserted / BLE link up).
 * Optional: a NULL pointer means "assume always connected" (used by tests and
 * loopback transports). The session recv loop polls this so it can abort a
 * blocked receive the instant a client disconnects, rather than holding the
 * dead session open until the recv timeout — otherwise a fast-reconnecting
 * client's handshake bytes get consumed by the previous session (see
 * transport_usb.c and the RECV_TIMEOUT_MS note in session.c).
 */
typedef bool (*transport_connected_fn)(cantil_transport_t *t);

struct cantil_transport {
	transport_send_fn send;
	transport_recv_fn recv;
	transport_connected_fn connected;
	void *priv;
};

int transport_init(void);
void transport_usb_flush_rx(void);

/*
 * Returns the currently active transport (USB or BLE, whichever connected
 * most recently), or NULL if no client is connected.
 */
cantil_transport_t *transport_get_active(void);
