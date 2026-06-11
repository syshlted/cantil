/* SPDX-License-Identifier: GPL-3.0-or-later WITH cantil-additional-permissions */
/* See LICENSE and LICENSE-EXCEPTIONS.md at the repo root. */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <string.h>
#include <errno.h>

#include "client_bond.h"
#include "storage/storage.h"
#include "cantil_cbor.h"

LOG_MODULE_REGISTER(client_bond, LOG_LEVEL_INF);

/* Resolve collision: verify that pubkey.bin under this ID matches pub exactly. */
static int id_matches_pub(const uint8_t id[4], const uint8_t pub[32])
{
	uint8_t stored[32];
	int rc = storage_client_bond_pubkey_read(id, stored);

	if (rc) return rc;
	return (memcmp(stored, pub, 32) == 0) ? 1 : 0;
}

int client_bond_exists(const uint8_t pub[32])
{
	uint8_t id[4];

	client_bond_id(pub, id);
	if (storage_client_bond_exists(id) != 1) return 0;
	int rc = id_matches_pub(id, pub);
	if (rc < 0) return rc;
	return rc; /* 1 if match, 0 on mismatch (collision slot for a different key) */
}

int client_bond_meta_read(const uint8_t pub[32], client_meta_t *meta)
{
	uint8_t id[4];

	client_bond_id(pub, id);

	int rc = id_matches_pub(id, pub);
	if (rc < 0) return rc;
	if (rc == 0) return -ENOENT;

	uint8_t buf[sizeof(client_meta_t)];
	size_t len = sizeof(buf);

	rc = storage_client_bond_meta_read(id, buf, &len);
	if (rc) return rc;
	if (len != sizeof(client_meta_t)) return -EINVAL;
	memcpy(meta, buf, sizeof(client_meta_t));
	return 0;
}

int client_bond_add(const uint8_t pub[32], client_kind_t kind, uint32_t now_unix)
{
	uint8_t id[4];

	client_bond_id(pub, id);

	/* Already bonded? */
	if (storage_client_bond_exists(id) == 1) {
		int rc = id_matches_pub(id, pub);
		if (rc < 0) return rc;
		if (rc == 1) return -EEXIST;
		/* Collision with a different key — this shouldn't happen in practice
		 * (only the first 4 bytes collide), log and fail rather than silently
		 * overwriting the existing bond. */
		LOG_ERR("client_bond_add: pubkey prefix collision for %02x%02x%02x%02x",
			id[0], id[1], id[2], id[3]);
		return -EADDRINUSE;
	}

	/* Check bond cap. */
	uint32_t host_count = 0, peer_count = 0;
	int rc = client_bond_count(&host_count, &peer_count);

	if (rc) return rc;

	if (kind == CLIENT_KIND_HOST &&
	    host_count >= CONFIG_CANTIL_MAX_CLIENT_BONDS) {
		LOG_WRN("client_bond_add: host bond cap (%d) reached",
			CONFIG_CANTIL_MAX_CLIENT_BONDS);
		return -ENOSPC;
	}
	if (kind == CLIENT_KIND_PEER_DEVICE &&
	    peer_count >= CONFIG_CANTIL_MAX_PEER_BONDS) {
		LOG_WRN("client_bond_add: peer bond cap (%d) reached",
			CONFIG_CANTIL_MAX_PEER_BONDS);
		return -ENOSPC;
	}

	/* Write pubkey.bin first (existence marker). */
	rc = storage_client_bond_pubkey_write(id, pub);
	if (rc) return rc;

	/* Write meta.bin. */
	client_meta_t meta = {
		.version        = CLIENT_META_VERSION,
		.kind           = (uint8_t)kind,
		._pad           = {0, 0},
		.created_at_be  = __builtin_bswap32(now_unix),
		.last_seen_be   = __builtin_bswap32(now_unix),
	};
	memset(meta.friendly_name, 0, sizeof(meta.friendly_name));

	rc = storage_client_bond_meta_write(id, (const uint8_t *)&meta,
					    sizeof(meta));
	if (rc) {
		/* Best-effort cleanup — don't leave a partial bond. */
		(void)storage_client_bond_delete(id);
		return rc;
	}

	LOG_INF("client_bond_add: bonded %02x%02x%02x%02x kind=%u",
		id[0], id[1], id[2], id[3], (unsigned)kind);
	return 0;
}

int client_bond_remove(const uint8_t pub[32])
{
	uint8_t id[4];

	client_bond_id(pub, id);

	/* Verify the stored pubkey really is this one before deleting. */
	if (storage_client_bond_exists(id) == 1) {
		int rc = id_matches_pub(id, pub);
		if (rc < 0) return rc;
		if (rc == 0) return -ENOENT; /* collision slot, not our key */
	}

	int rc = storage_client_bond_delete(id);

	if (rc == 0)
		LOG_INF("client_bond_remove: removed %02x%02x%02x%02x",
			id[0], id[1], id[2], id[3]);
	return rc;
}

int client_bond_set_name(const uint8_t pub[32], const char *name)
{
	if (!name || strlen(name) >= CLIENT_META_NAME_MAX) return -EINVAL;

	client_meta_t meta;
	int rc = client_bond_meta_read(pub, &meta);

	if (rc) return rc;

	memset(meta.friendly_name, 0, sizeof(meta.friendly_name));
	strncpy(meta.friendly_name, name, CLIENT_META_NAME_MAX - 1);

	uint8_t id[4];
	client_bond_id(pub, id);
	return storage_client_bond_meta_write(id, (const uint8_t *)&meta,
					      sizeof(meta));
}

/* Iterator context for client_bond_count. */
struct count_ctx {
	uint32_t host;
	uint32_t peer;
};

static int count_cb(const uint8_t id[4], void *user)
{
	struct count_ctx *ctx = user;
	uint8_t buf[sizeof(client_meta_t)];
	size_t len = sizeof(buf);

	if (storage_client_bond_meta_read(id, buf, &len) != 0 ||
	    len < 2) {
		/* Unreadable meta — skip rather than abort the walk. */
		return 0;
	}
	client_meta_t *m = (client_meta_t *)buf;

	if (m->kind == CLIENT_KIND_HOST)
		ctx->host++;
	else if (m->kind == CLIENT_KIND_PEER_DEVICE)
		ctx->peer++;
	return 0;
}

int client_bond_count(uint32_t *host_count, uint32_t *peer_count)
{
	struct count_ctx ctx = {0, 0};
	int rc = storage_client_bonds_iter(count_cb, &ctx);

	if (rc) return rc;
	if (host_count) *host_count = ctx.host;
	if (peer_count) *peer_count = ctx.peer;
	return 0;
}

/* Iterator context for client_bond_list_cbor. */
struct list_ctx {
	uint8_t *out;
	size_t   cap;
	size_t   off;
	uint32_t count;
	int      err;
};

static int list_cb(const uint8_t id[4], void *user)
{
	struct list_ctx *ctx = user;

	uint8_t pub[32];

	if (storage_client_bond_pubkey_read(id, pub) != 0) return 0;

	uint8_t meta_buf[sizeof(client_meta_t)];
	size_t meta_len = sizeof(meta_buf);
	client_meta_t meta = {0};

	if (storage_client_bond_meta_read(id, meta_buf, &meta_len) == 0 &&
	    meta_len == sizeof(client_meta_t)) {
		memcpy(&meta, meta_buf, sizeof(meta));
	}

	uint32_t created_at = __builtin_bswap32(meta.created_at_be);
	const char *name = meta.friendly_name;
	/* friendly_name is always null-terminated (zeroed at write-time). */
	size_t name_len = strlen(name);
	if (name_len >= CLIENT_META_NAME_MAX)
		name_len = CLIENT_META_NAME_MAX - 1;

	/* Map: { "k": uint, "n": uint32, "p": bstr(32), "t": tstr } */
	int e = cantil_cbor_emit_map(ctx->out, ctx->cap, &ctx->off, 4);
	if (!e) e = cantil_cbor_emit_tstr(ctx->out, ctx->cap, &ctx->off, "k", 1);
	if (!e) e = cantil_cbor_emit_uint(ctx->out, ctx->cap, &ctx->off, meta.kind);
	if (!e) e = cantil_cbor_emit_tstr(ctx->out, ctx->cap, &ctx->off, "n", 1);
	if (!e) e = cantil_cbor_emit_uint(ctx->out, ctx->cap, &ctx->off, created_at);
	if (!e) e = cantil_cbor_emit_tstr(ctx->out, ctx->cap, &ctx->off, "p", 1);
	if (!e) e = cantil_cbor_emit_bstr(ctx->out, ctx->cap, &ctx->off, pub, 32);
	if (!e) e = cantil_cbor_emit_tstr(ctx->out, ctx->cap, &ctx->off, "t", 1);
	if (!e) e = cantil_cbor_emit_tstr(ctx->out, ctx->cap, &ctx->off, name, name_len);
	if (e) { ctx->err = -ENOMEM; return 1; }

	ctx->count++;
	return 0;
}

int client_bond_list_cbor(uint8_t *out, size_t *len)
{
	if (!out || !len || *len < 4) return -EINVAL;

	/* Pass 1: count bonds so we can emit the CBOR array header. */
	uint32_t total = 0;
	int rc = storage_count_client_bonds(&total);

	if (rc) { *len = 0; return rc; }

	size_t off = 0;

	rc = cantil_cbor_emit_array(out, *len, &off, total);
	if (rc) { *len = 0; return -ENOMEM; }

	struct list_ctx ctx = { .out = out, .cap = *len, .off = off, .count = 0, .err = 0 };

	rc = storage_client_bonds_iter(list_cb, &ctx);
	if (rc || ctx.err) { *len = 0; return ctx.err ? ctx.err : rc; }

	*len = ctx.off;
	return 0;
}
