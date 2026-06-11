#pragma once

#include <stdint.h>
#include <stddef.h>

typedef struct cantil_transport cantil_transport_t;

typedef int (*transport_send_fn)(cantil_transport_t *t,
				 const uint8_t *buf, size_t len);
typedef int (*transport_recv_fn)(cantil_transport_t *t,
				 uint8_t *buf, size_t max_len, size_t *received);

struct cantil_transport {
	transport_send_fn send;
	transport_recv_fn recv;
	void *priv;
};

int  transport_init(void);
void transport_usb_flush_rx(void);

/*
 * Returns the currently active transport (USB or BLE, whichever connected
 * most recently), or NULL if no client is connected.
 */
cantil_transport_t *transport_get_active(void);
