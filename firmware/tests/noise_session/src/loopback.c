/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

#include <string.h>
#include <errno.h>
#include <zephyr/kernel.h>

#include "loopback.h"

static void pipe_init(struct loopback_pipe *p)
{
	p->head = 0;
	p->tail = 0;
	k_mutex_init(&p->lock);
	k_sem_init(&p->data_avail, 0, K_SEM_MAX_LIMIT);
}

static int pipe_write(struct loopback_pipe *p, const uint8_t *buf, size_t len)
{
	k_mutex_lock(&p->lock, K_FOREVER);
	if (p->tail + len > LOOPBACK_BUF_LEN) {
		k_mutex_unlock(&p->lock);
		return -ENOBUFS;
	}
	memcpy(p->buf + p->tail, buf, len);
	p->tail += len;
	k_mutex_unlock(&p->lock);
	k_sem_give(&p->data_avail);
	return 0;
}

/*
 * Non-blocking drain: copy out whatever is currently buffered (up to max_len),
 * return immediately even if buffer is empty.  session.c's raw_recv_exact
 * handles the spin-wait via k_msleep when recv reports 0 bytes.
 */
static int pipe_read_nonblock(struct loopback_pipe *p, uint8_t *out,
			      size_t max_len, size_t *received)
{
	k_mutex_lock(&p->lock, K_FOREVER);
	size_t avail = p->tail - p->head;
	size_t n = avail < max_len ? avail : max_len;

	if (n > 0) {
		memcpy(out, p->buf + p->head, n);
		p->head += n;
		/* Compact when fully drained to keep buffer usable for next msg. */
		if (p->head == p->tail) {
			p->head = 0;
			p->tail = 0;
		}
	}
	k_mutex_unlock(&p->lock);
	*received = n;
	return 0;
}

/* ── cantil_transport_t vtable ───────────────────────────────────────────── */

static int side_a_send(cantil_transport_t *t, const uint8_t *buf, size_t len)
{
	struct loopback_pair *pair = (struct loopback_pair *)t->priv;

	return pipe_write(&pair->a_to_b, buf, len);
}

static int side_a_recv(cantil_transport_t *t, uint8_t *buf,
		       size_t max_len, size_t *received)
{
	struct loopback_pair *pair = (struct loopback_pair *)t->priv;

	return pipe_read_nonblock(&pair->b_to_a, buf, max_len, received);
}

static int side_b_send(cantil_transport_t *t, const uint8_t *buf, size_t len)
{
	struct loopback_pair *pair = (struct loopback_pair *)t->priv;

	return pipe_write(&pair->b_to_a, buf, len);
}

static int side_b_recv(cantil_transport_t *t, uint8_t *buf,
		       size_t max_len, size_t *received)
{
	struct loopback_pair *pair = (struct loopback_pair *)t->priv;

	return pipe_read_nonblock(&pair->a_to_b, buf, max_len, received);
}

void loopback_pair_init(struct loopback_pair *pair)
{
	pipe_init(&pair->a_to_b);
	pipe_init(&pair->b_to_a);

	pair->side_a.send = side_a_send;
	pair->side_a.recv = side_a_recv;
	pair->side_a.priv = pair;

	pair->side_b.send = side_b_send;
	pair->side_b.recv = side_b_recv;
	pair->side_b.priv = pair;
}

void loopback_stage_rx(struct loopback_pipe *p, const uint8_t *data, size_t len)
{
	(void)pipe_write(p, data, len);
}

size_t loopback_drain_tx(struct loopback_pipe *p, uint8_t *out, size_t max_len)
{
	size_t n = 0;
	(void)pipe_read_nonblock(p, out, max_len, &n);
	return n;
}

size_t loopback_pending(struct loopback_pipe *p)
{
	k_mutex_lock(&p->lock, K_FOREVER);
	size_t avail = p->tail - p->head;
	k_mutex_unlock(&p->lock);
	return avail;
}
