/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <zephyr/kernel.h>

#include "transport/transport.h"

/*
 * In-memory loopback transport pair used to drive session.c on native_sim.
 *
 * Two pipes (A→B, B→A), each backed by a fixed-size byte buffer protected by
 * a mutex + semaphore.  send() copies bytes into the peer's inbox and posts
 * the sem; recv() drains whatever is currently buffered and blocks on the sem
 * when the inbox is empty.  This matches the contract session.c expects from
 * a real transport (recv may return short, including 0 with a spin from
 * raw_recv_exact while waiting for more bytes).
 *
 * The pair supports two driving styles:
 *   - Pre-staged: caller fills a pipe via loopback_stage_rx() before invoking
 *     session.c, then reads the responder's output via loopback_drain_tx().
 *     No second thread needed.  Used by the vector-replay tests.
 *   - Live duplex: a peer thread runs the initiator concurrently with the
 *     responder.  Used by the round-trip test.
 */

#define LOOPBACK_BUF_LEN 4096

struct loopback_pipe {
	uint8_t buf[LOOPBACK_BUF_LEN];
	size_t head;
	size_t tail;
	struct k_mutex lock;
	struct k_sem data_avail;
};

struct loopback_pair {
	struct loopback_pipe a_to_b;
	struct loopback_pipe b_to_a;
	cantil_transport_t side_a;  /* writes a_to_b, reads b_to_a */
	cantil_transport_t side_b;  /* writes b_to_a, reads a_to_b */
};

void loopback_pair_init(struct loopback_pair *pair);

/* Pre-staged helpers — operate on either pipe directly. */
void loopback_stage_rx(struct loopback_pipe *p, const uint8_t *data, size_t len);
size_t loopback_drain_tx(struct loopback_pipe *p, uint8_t *out, size_t max_len);
size_t loopback_pending(struct loopback_pipe *p);
