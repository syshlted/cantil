#pragma once

#include <stdint.h>
#include <stddef.h>
#include "transport/transport.h"

typedef struct cantil_session cantil_session_t;

/*
 * Perform Noise_XX handshake over the given transport and return an
 * established session.  The device is always the responder.
 *
 * expected_client_pub: if non-NULL, reject any initiator whose static public
 * key doesn't match (pass NULL for TOFU mode — accept any client, pin their
 * key via session_get_remote_pubkey after the first successful handshake).
 */
int session_open(cantil_transport_t *transport,
		 const uint8_t *expected_client_pub,  /* 32 bytes or NULL */
		 cantil_session_t **session_out);

void session_close(cantil_session_t *session);

/* Send/receive length-prefixed, encrypted frames inside the Noise session. */
int session_send(cantil_session_t *session, const uint8_t *buf, size_t len);
int session_recv(cantil_session_t *session, uint8_t *buf,
		 size_t max_len, size_t *received);

/* Remote (client) static Curve25519 public key, learned during handshake. */
int session_get_remote_pubkey(cantil_session_t *session, uint8_t pubkey[32]);

/* Local (device) static Curve25519 public key — share with client for TOFU. */
int session_get_local_pubkey(cantil_session_t *session, uint8_t pubkey[32]);

/*
 * Client identity cert chain parsed from msg3 payload (T-19, Method 4).
 * session_get_client_cert() returns the Nth cert (0 = leaf) as a borrowed
 * pointer into the session's internal buffer; valid until session_close().
 * Returns -ENOENT if idx >= count, -EINVAL on bad args.
 * session_get_client_cert_count() returns 0 if no chain was presented.
 */
int    session_get_client_cert(const cantil_session_t *session, size_t idx,
			       const uint8_t **der, size_t *len);
size_t session_get_client_cert_count(const cantil_session_t *session);
