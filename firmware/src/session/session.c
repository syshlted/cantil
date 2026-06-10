/*
 * Transport security model — read before modifying this file.
 *
 * The wire protocol is Noise_XX_25519_ChaChaPoly_SHA256. Mutual
 * authentication, forward secrecy, and confidentiality come from the Noise
 * handshake, not from TLS or any PKI library. The session slot's X.509
 * certificate is metadata about the device's Noise static key, not a TLS
 * credential. Certificate validation is performed by libcantil against an
 * application-supplied trust policy (TOFU pin, fingerprint pin, or allowlisted
 * root). It is not delegated to a standard X.509 path-validation library, does
 * not involve a system trust store, and does not consult OCSP or
 * network-distributed CRLs. The certificate binds an identity to the static
 * key for client-side policy decisions; handshake security does not depend on
 * the certificate at all.
 *
 * Full design: docs/transport-and-pairing.md
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <string.h>
#include <errno.h>

#include <mbedtls/asn1.h>

#include "session.h"
#include "noise_crypto.h"
#include "cantil_cbor.h"
#ifdef CONFIG_CANTIL_TEST_INJECT_NOISE_KEYS
#include "test_inject.h"
#else
#include "storage/storage.h"
#include "session_slot.h"
#include "crypto/crypto.h"
#endif

LOG_MODULE_REGISTER(session, LOG_LEVEL_INF);

#define NOISE_KEY_LEN      32
#define NOISE_TAG_LEN      16
#define FRAME_LEN_BYTES     2
#define RECV_TIMEOUT_MS   2000
#define MAX_FRAME_PAYLOAD 4096

/*
 * Transport-identity cert chain on the Noise handshake (transport+pairing T-04).
 *
 * msg2 carries a CBOR map { 1: [ <leaf_der>, <issuer_der>, ... ] } encrypted as
 * the responder's final handshake payload — the device's session-slot identity
 * chain, leaf-first. A self-signed device sends a single-element array. msg3
 * carries the initiator's reciprocal payload (an empty CBOR map {} until
 * CA-anchored client certs land in Method 4). The chain is integrity-protected
 * by the Noise AEAD, not by its own signatures — tampering fails the next
 * decrypt. Length-prefixed framing already handles the variable message sizes,
 * so the old fixed-96/64-byte handshake sizes are gone.
 */
#define SESSION_CBOR_KEY_CHAIN   1
#define SESSION_LEAF_DER_MAX     1024
#define SESSION_CHAIN_DER_MAX    1536   /* /session/chain.der (issuer chain) */
#define SESSION_CHAIN_MAX_CERTS  4
#define SESSION_CHAIN_PT_MAX     2048   /* CBOR chain payload (plaintext) */
#define SESSION_HS_MSG_MAX       (32 + 48 + SESSION_CHAIN_PT_MAX + NOISE_TAG_LEN)
#define SESSION_CLIENT_CHAIN_MAX 2048   /* max client cert chain (msg3 payload) */

/*
 * Noise_XX_25519_ChaChaPoly_SHA256 — exactly 32 bytes, so per the Noise spec
 * the initial hash h = protocol_name (no SHA-256 needed, no padding needed).
 */
static const uint8_t PROTOCOL_NAME[32] = "Noise_XX_25519_ChaChaPoly_SHA256";

/* ── Symmetric state ────────────────────────────────────────────────────── */

struct sym_state {
	uint8_t h[32];
	uint8_t ck[32];
	uint8_t k[32];
	uint64_t n;
	bool has_key;
};

static void sym_init(struct sym_state *s)
{
	memcpy(s->h, PROTOCOL_NAME, 32);
	memcpy(s->ck, PROTOCOL_NAME, 32);
	memset(s->k, 0, 32);
	s->n = 0;
	s->has_key = false;
}

static int sym_mix_hash(struct sym_state *s, const uint8_t *data, size_t len)
{
	return noise_crypto_hash(s->h, s->h, 32, data, len);
}

static int sym_mix_key(struct sym_state *s, const uint8_t *ikm, size_t ikm_len)
{
	uint8_t new_ck[32], temp_k[32];

	int ret = noise_crypto_hkdf2(new_ck, temp_k, s->ck, ikm, ikm_len);

	if (!ret) {
		memcpy(s->ck, new_ck, 32);
		memcpy(s->k, temp_k, 32);
		s->n = 0;
		s->has_key = true;
		memset(temp_k, 0, 32);
	}
	return ret;
}

/*
 * EncryptAndHash: encrypt pt with AEAD(k, n, h, pt) → ct, then MixHash(ct).
 * When unkeyed: ct = pt (pass-through), still MixHash(ct).
 */
static int sym_encrypt_and_hash(struct sym_state *s,
				const uint8_t *pt, size_t pt_len,
				uint8_t *ct_out, size_t ct_buf_len,
				size_t *ct_len_out)
{
	int ret;

	if (!s->has_key) {
		if (ct_buf_len < pt_len) {
			return -ENOBUFS;
		}
		memcpy(ct_out, pt, pt_len);
		*ct_len_out = pt_len;
		return sym_mix_hash(s, ct_out, pt_len);
	}

	ret = noise_crypto_encrypt(ct_out, ct_buf_len, ct_len_out,
				   s->k, s->n, s->h, 32, pt, pt_len);
	if (ret) {
		return ret;
	}
	s->n++;
	return sym_mix_hash(s, ct_out, *ct_len_out);
}

/*
 * DecryptAndHash: decrypt ct with AEAD(k, n, h, ct) → pt, then MixHash(ct).
 * When unkeyed: pt = ct (pass-through), still MixHash(ct).
 * Returns -EBADMSG on AEAD authentication failure.
 */
static int sym_decrypt_and_hash(struct sym_state *s,
				const uint8_t *ct, size_t ct_len,
				uint8_t *pt_out, size_t pt_buf_len,
				size_t *pt_len_out)
{
	int ret;

	if (!s->has_key) {
		if (pt_buf_len < ct_len) {
			return -ENOBUFS;
		}
		memcpy(pt_out, ct, ct_len);
		*pt_len_out = ct_len;
		return sym_mix_hash(s, ct, ct_len);
	}

	ret = noise_crypto_decrypt(pt_out, pt_buf_len, pt_len_out,
				   s->k, s->n, s->h, 32, ct, ct_len);
	if (ret) {
		return ret;
	}
	s->n++;
	return sym_mix_hash(s, ct, ct_len);
}

/* Split: derive two session keys from the final chaining key. */
static int sym_split(struct sym_state *s, uint8_t k1[32], uint8_t k2[32])
{
	/* ikm = empty for Split() */
	return noise_crypto_hkdf2(k1, k2, s->ck, (const uint8_t *)"", 0);
}

/* ── Session pool ───────────────────────────────────────────────────────── */

struct cantil_session {
	cantil_transport_t *transport;
	uint8_t rx_key[NOISE_KEY_LEN];  /* initiator→responder decrypt key */
	uint8_t tx_key[NOISE_KEY_LEN];  /* responder→initiator encrypt key */
	uint64_t rx_nonce;
	uint64_t tx_nonce;
	uint8_t remote_s_pub[NOISE_KEY_LEN];  /* initiator static public key */
	uint8_t local_s_pub[NOISE_KEY_LEN];   /* our static public key */
	bool established;

	/* Client identity chain from msg3 (leaf-first, T-19 Method 4).
	 * Parsed after the handshake; available to pairing_check_and_bond(). */
	uint8_t  client_chain[SESSION_CLIENT_CHAIN_MAX];
	size_t   client_chain_total;
	size_t   client_cert_off[SESSION_CHAIN_MAX_CERTS];
	size_t   client_cert_len[SESSION_CHAIN_MAX_CERTS];
	size_t   client_cert_count;
};

static struct cantil_session session_pool[1];
static bool session_pool_used;

static struct cantil_session *session_alloc(void)
{
	if (!session_pool_used) {
		session_pool_used = true;
		return &session_pool[0];
	}
	return NULL;
}

static void session_free(struct cantil_session *s)
{
	if (s == &session_pool[0]) {
		session_pool_used = false;
	}
}

/* ── Transport framing ──────────────────────────────────────────────────── */

static int raw_send(cantil_transport_t *t, const uint8_t *buf, size_t len)
{
	return t->send(t, buf, len);
}

static int raw_recv_exact(cantil_transport_t *t, uint8_t *buf, size_t len)
{
	size_t received = 0;
	int64_t deadline = k_uptime_get() + RECV_TIMEOUT_MS;

	while (received < len) {
		size_t n = 0;
		int ret = t->recv(t, buf + received, len - received, &n);

		if (ret) {
			return ret;
		}
		received += n;
		if (n == 0) {
			if (k_uptime_get() >= deadline) {
				LOG_WRN("recv timeout");
				return -ETIMEDOUT;
			}
			k_msleep(1);
		}
	}
	return 0;
}

/* Send a length-prefixed frame (big-endian 16-bit length). */
static int send_frame(cantil_transport_t *t, const uint8_t *buf, size_t len)
{
	uint8_t hdr[2] = {(uint8_t)(len >> 8), (uint8_t)(len & 0xFF)};
	int ret = raw_send(t, hdr, 2);

	if (ret) {
		return ret;
	}
	return raw_send(t, buf, len);
}

/* Receive a length-prefixed frame. */
static int recv_frame(cantil_transport_t *t, uint8_t *buf,
		      size_t max_len, size_t *recv_len)
{
	uint8_t hdr[2];
	int ret = raw_recv_exact(t, hdr, 2);

	if (ret) {
		return ret;
	}

	size_t frame_len = ((size_t)hdr[0] << 8) | hdr[1];

	if (frame_len > max_len) {
		return -ENOBUFS;
	}
	ret = raw_recv_exact(t, buf, frame_len);
	if (!ret) {
		*recv_len = frame_len;
	}
	return ret;
}

/* ── Static keypair management ─────────────────────────────────────────── */

/*
 * Load the X25519 Noise static keypair from the session slot (/session/key.bin
 * + meta). session_slot_init() owns first-boot generation and persistence, so
 * by the time a handshake runs the slot is guaranteed present; the former
 * /noise/ store is retired (T-04). The encrypted scalar is unwrapped here under
 * the FICR-derived storage key.
 */
static int load_static_keypair(uint8_t priv[32], uint8_t pub[32])
{
#ifdef CONFIG_CANTIL_TEST_INJECT_NOISE_KEYS
	return cantil_test_inject_static_keypair(priv, pub);
#else
	uint8_t blob[12 + 32 + 16];   /* AES-256-GCM: nonce + ct + tag */
	size_t  blob_len = sizeof(blob);
	uint8_t storage_key[32];
	size_t  pt_len = 32;
	int ret = storage_session_key_read(blob, &blob_len);

	if (ret) {
		LOG_ERR("session key.bin read=%d (slot not initialized?)", ret);
		return ret;
	}

	ret = crypto_storage_key_derive(storage_key);
	if (ret) {
		return ret;
	}
	ret = crypto_decrypt_blob(storage_key, blob, blob_len, priv, &pt_len);
	memset(storage_key, 0, sizeof(storage_key));
	if (ret || pt_len != 32) {
		LOG_ERR("session key decrypt=%d len=%zu", ret, pt_len);
		return ret ? ret : -EINVAL;
	}
	return session_slot_get_pubkey(pub);
#endif
}

static int gen_ephemeral_keypair(uint8_t priv[32], uint8_t pub[32])
{
#ifdef CONFIG_CANTIL_TEST_INJECT_NOISE_KEYS
	return cantil_test_inject_ephemeral_keypair(priv, pub);
#else
	return noise_crypto_dh_keygen(priv, pub);
#endif
}

/*
 * Collect the local identity cert chain (leaf-first) as borrowed ptr/len pairs.
 * Production reads the session slot's self-signed cert into `scratch`; test
 * builds draw an injected chain. Returns the cert count (0..max) or -errno.
 * A count of 0 yields an empty handshake payload (legacy / no-identity).
 */
static int collect_local_certs(const uint8_t *certs[], size_t lens[], size_t max,
			       uint8_t *scratch, size_t scratch_cap)
{
#ifdef CONFIG_CANTIL_TEST_INJECT_NOISE_KEYS
	ARG_UNUSED(scratch);
	ARG_UNUSED(scratch_cap);
	return cantil_test_inject_local_chain(certs, lens, max);
#else
	size_t cl = scratch_cap;
	int ret = session_slot_get_cert(scratch, &cl);

	if (ret == -ENOENT) {
		return 0;   /* no identity yet -> empty chain */
	}
	if (ret) {
		return ret;
	}
	if (max < 1) {
		return -ENOBUFS;
	}
	certs[0] = scratch;
	lens[0]  = cl;

	/*
	 * Append the issuer chain (T-07) if a CA-signed cert was pushed. The
	 * stored blob is concatenated DER; split it into individual certs so
	 * each rides as its own CBOR bstr, leaf-first order preserved. The
	 * scratch is a file-scope static (borrowed by certs[1..]); the single-
	 * session responder is single-threaded, like hs_msg / leaf_scratch.
	 */
	static uint8_t chain_scratch[SESSION_CHAIN_DER_MAX];
	size_t chl = sizeof(chain_scratch);
	size_t n = 1;

	if (storage_session_chain_read(chain_scratch, &chl) == 0 && chl > 0) {
		size_t off = 0;

		while (off + 1 < chl && n < max) {
			const unsigned char *p = chain_scratch + off;
			unsigned char *q = (unsigned char *)p;
			size_t inner;

			if (mbedtls_asn1_get_tag(&q, p + (chl - off), &inner,
						 MBEDTLS_ASN1_CONSTRUCTED |
						 MBEDTLS_ASN1_SEQUENCE) != 0) {
				break;
			}

			size_t this_len = (size_t)(q - p) + inner;

			if (off + this_len > chl) {
				break;
			}
			certs[n] = p;
			lens[n]  = this_len;
			n++;
			off += this_len;
		}
	}
	return (int)n;
#endif
}

/*
 * Encode the cert chain as CBOR { SESSION_CBOR_KEY_CHAIN: [ bstr, ... ] }.
 * Always compiled (production + chain test); the legacy noise vector test never
 * reaches it because collect_local_certs returns 0 there.
 */
static int encode_chain_cbor(uint8_t *buf, size_t cap, size_t *out_len,
			     const uint8_t *const certs[], const size_t lens[],
			     size_t n)
{
	size_t off = 0;
	int rc = cantil_cbor_emit_map(buf, cap, &off, 1);

	if (rc) {
		return rc;
	}
	rc = cantil_cbor_emit_uint(buf, cap, &off, SESSION_CBOR_KEY_CHAIN);
	if (rc) {
		return rc;
	}
	rc = cantil_cbor_emit_array(buf, cap, &off, (uint32_t)n);
	if (rc) {
		return rc;
	}
	for (size_t i = 0; i < n; i++) {
		rc = cantil_cbor_emit_bstr(buf, cap, &off, certs[i], lens[i]);
		if (rc) {
			return rc;
		}
	}
	*out_len = off;
	return 0;
}

/*
 * Parse the client identity CBOR { 1: [ <leaf_der>, ... ] } from the msg3
 * decrypted payload and store the chain in the session (T-19). Best-effort:
 * a missing or unrecognized payload leaves client_cert_count == 0, which
 * pairing_check_and_bond() uses to reject Method 4 connections without a cert.
 */
static void parse_client_chain(struct cantil_session *s,
				const uint8_t *pt, size_t pt_len)
{
	s->client_chain_total = 0;
	s->client_cert_count  = 0;

	if (pt_len == 0) {
		return;
	}

	size_t   off = 0;
	uint8_t  major;
	uint64_t val;

	if (cantil_cbor_read_head(pt, pt_len, &off, &major, &val) != 0) {
		return;
	}
	if (major != CANTIL_CBOR_MT_MAP) {
		return;
	}

	size_t pairs = (size_t)val;

	for (size_t p = 0; p < pairs; p++) {
		uint32_t key;

		if (cantil_cbor_read_uint32(pt, pt_len, &off, &key) != 0) {
			return;
		}
		if (key != SESSION_CBOR_KEY_CHAIN) {
			return;
		}

		uint8_t  amaj;
		uint64_t acount;

		if (cantil_cbor_read_head(pt, pt_len, &off, &amaj, &acount) != 0) {
			return;
		}
		if (amaj != CANTIL_CBOR_MT_ARRAY) {
			return;
		}

		for (size_t i = 0; i < (size_t)acount; i++) {
			const uint8_t *cert;
			size_t cl;

			if (cantil_cbor_read_bstr(pt, pt_len, &off, &cert, &cl) != 0) {
				return;
			}
			if (s->client_cert_count >= SESSION_CHAIN_MAX_CERTS) {
				return;
			}
			if (s->client_chain_total + cl > SESSION_CLIENT_CHAIN_MAX) {
				return;
			}
			memcpy(s->client_chain + s->client_chain_total, cert, cl);
			s->client_cert_off[s->client_cert_count] = s->client_chain_total;
			s->client_cert_len[s->client_cert_count] = cl;
			s->client_cert_count++;
			s->client_chain_total += cl;
		}
		return;   /* chain consumed */
	}
}

/* ── Public API ─────────────────────────────────────────────────────────── */

/*
 * Noise_XX responder handshake (3-message, mutual authentication).
 *
 * Wire sizes (msg2/msg3 carry a variable CBOR cert-chain payload, T-04):
 *   Message 1  → e                     32 bytes
 *   Message 2  ← e, ee, s, es          80 + (chain_cbor + 16) bytes
 *   Message 3  → s, se                 48 + (client_cbor + 16) bytes
 * An empty payload collapses msg2 to 96 / msg3 to 64 bytes (legacy sizes).
 *
 * expected_client_pub: if non-NULL, reject any initiator whose static public
 * key doesn't match.  Pass NULL to accept any client (TOFU mode).
 */
int session_open(cantil_transport_t *transport,
		 const uint8_t *expected_client_pub,
		 cantil_session_t **session_out)
{
	struct cantil_session *s = session_alloc();

	if (!s) {
		return -ENOMEM;
	}
	memset(s, 0, sizeof(*s));
	s->transport = transport;

	uint8_t s_priv[32], s_pub[32];
	uint8_t e_priv[32], e_pub[32];
	struct sym_state sym;
	static const uint8_t empty[1];

	int ret = load_static_keypair(s_priv, s_pub);

	if (ret) {
		LOG_ERR("static keypair load failed: %d", ret);
		goto fail;
	}
	memcpy(s->local_s_pub, s_pub, 32);

	ret = gen_ephemeral_keypair(e_priv, e_pub);
	if (ret) {
		LOG_ERR("ephemeral keygen failed: %d", ret);
		goto fail;
	}

	/* Initialize symmetric state: h = ck = PROTOCOL_NAME. */
	sym_init(&sym);

	/* MixHash(prologue) — empty prologue per spec: h = SHA-256(h). */
	ret = sym_mix_hash(&sym, empty, 0);
	if (ret) {
		goto fail;
	}

	/* ── Message 1: receive "e" ── */

	uint8_t msg1[32];
	size_t msg1_len;

	ret = recv_frame(transport, msg1, sizeof(msg1), &msg1_len);
	if (ret || msg1_len != 32) {
		ret = ret ? ret : -EPROTO;
		goto fail;
	}

	uint8_t eI_pub[32];

	memcpy(eI_pub, msg1, 32);

	ret = sym_mix_hash(&sym, eI_pub, 32);    /* MixHash(eI_pub) */
	if (ret) {
		goto fail;
	}
	/* Empty payload — unkeyed EncryptAndHash("") → MixHash(""). */
	ret = sym_mix_hash(&sym, empty, 0);
	if (ret) {
		goto fail;
	}

	/* ── Message 2: send "e, ee, s, es" ── */

	/*
	 * Layout: eR_pub(32) | EncryptAndHash(sR_pub)(48) |
	 *         EncryptAndHash(chain_cbor)(chain_cbor_len + 16)
	 * The handshake message buffer and the chain plaintext are file-scope
	 * statics — the single-session responder is single-threaded here, like
	 * session_send/recv below — to avoid putting kilobytes on the stack.
	 */
	/* msg2 (sent) and msg3 (received later) never overlap in time, so they
	 * share one handshake message buffer. */
	static uint8_t hs_msg[SESSION_HS_MSG_MAX];
	static uint8_t chain_pt[SESSION_CHAIN_PT_MAX];
	static uint8_t leaf_scratch[SESSION_LEAF_DER_MAX];
	uint8_t *const msg2 = hs_msg;
	const uint8_t *certs[SESSION_CHAIN_MAX_CERTS];
	size_t clens[SESSION_CHAIN_MAX_CERTS];
	size_t chain_pt_len = 0;
	size_t msg2_pos = 0;
	size_t enc_len;

	/* Assemble the local identity chain CBOR (empty payload if none). */
	int nc = collect_local_certs(certs, clens, SESSION_CHAIN_MAX_CERTS,
				     leaf_scratch, sizeof(leaf_scratch));
	if (nc < 0) {
		LOG_WRN("local chain collect=%d; sending empty payload", nc);
		nc = 0;
	}
	if (nc > 0) {
		ret = encode_chain_cbor(chain_pt, sizeof(chain_pt),
					&chain_pt_len, certs, clens, (size_t)nc);
		if (ret) {
			LOG_ERR("chain CBOR encode=%d", ret);
			goto fail;
		}
	}

	/* e token: include eR_pub in message, MixHash(eR_pub). */
	memcpy(msg2, e_pub, 32);
	msg2_pos = 32;
	ret = sym_mix_hash(&sym, e_pub, 32);
	if (ret) {
		goto fail;
	}

	/* ee token: DH(eR_priv, eI_pub), MixKey(ee). */
	{
		uint8_t ee[32];

		ret = noise_crypto_dh(ee, e_priv, eI_pub);
		if (ret) {
			goto fail;
		}
		ret = sym_mix_key(&sym, ee, 32);
		memset(ee, 0, 32);
		if (ret) {
			goto fail;
		}
	}

	/* s token: EncryptAndHash(sR_pub) → 48 bytes. */
	ret = sym_encrypt_and_hash(&sym, s_pub, 32,
				   msg2 + msg2_pos, sizeof(msg2) - msg2_pos,
				   &enc_len);
	if (ret) {
		goto fail;
	}
	msg2_pos += enc_len;  /* enc_len == 48 */

	/* es token: DH(sR_priv, eI_pub), MixKey(es). */
	{
		uint8_t es[32];

		ret = noise_crypto_dh(es, s_priv, eI_pub);
		if (ret) {
			goto fail;
		}
		ret = sym_mix_key(&sym, es, 32);
		memset(es, 0, 32);
		if (ret) {
			goto fail;
		}
	}

	/* Identity-chain payload: EncryptAndHash(chain_cbor) → chain + 16-byte
	 * tag. An empty chain (chain_pt_len == 0) yields just the tag, i.e. the
	 * legacy 16-byte token / 96-byte msg2. */
	ret = sym_encrypt_and_hash(&sym, chain_pt, chain_pt_len,
				   msg2 + msg2_pos, sizeof(msg2) - msg2_pos,
				   &enc_len);
	if (ret) {
		goto fail;
	}
	msg2_pos += enc_len;  /* enc_len == chain_pt_len + 16 */

	ret = send_frame(transport, msg2, msg2_pos);
	if (ret) {
		goto fail;
	}

	/* ── Message 3: receive "s, se" ── */

	/*
	 * Layout: EncryptAndHash(sI_pub)(48) |
	 *         EncryptAndHash(client_cbor)(client_cbor + 16)
	 * Minimum 64 bytes (empty client payload). The client payload is
	 * decrypted-and-authenticated but otherwise ignored until CA-anchored
	 * client certs land (Method 4 / T-19).
	 */
	uint8_t *const msg3 = hs_msg;   /* reuses the msg2 buffer */
	size_t msg3_len;

	ret = recv_frame(transport, msg3, sizeof(hs_msg), &msg3_len);
	if (ret || msg3_len < 64) {
		ret = ret ? ret : -EPROTO;
		goto fail;
	}

	/* s token: DecryptAndHash(enc_sI_pub) → 32 bytes. */
	{
		size_t dec_len;

		ret = sym_decrypt_and_hash(&sym, msg3, 48,
					   s->remote_s_pub, 32, &dec_len);
		if (ret) {
			LOG_WRN("msg3 s decrypt failed: %d", ret);
			goto fail;
		}
	}

	if (expected_client_pub &&
	    memcmp(s->remote_s_pub, expected_client_pub, 32) != 0) {
		LOG_WRN("client static key mismatch — rejecting");
		ret = -EACCES;
		goto fail;
	}

	/* se token: DH(eR_priv, sI_pub), MixKey(se). */
	{
		uint8_t se[32];

		ret = noise_crypto_dh(se, e_priv, s->remote_s_pub);
		if (ret) {
			goto fail;
		}
		ret = sym_mix_key(&sym, se, 32);
		memset(se, 0, 32);
		if (ret) {
			goto fail;
		}
	}

	/* Client payload: decrypt + authenticate the trailing CBOR (msg3_len -
	 * 48 ciphertext bytes, >= 16). Parse as client identity chain (T-19). */
	{
		size_t client_pt_len;

		ret = sym_decrypt_and_hash(&sym, msg3 + 48, msg3_len - 48,
					   chain_pt, sizeof(chain_pt), &client_pt_len);
		if (ret) {
			LOG_WRN("msg3 payload auth failed: %d", ret);
			goto fail;
		}
		parse_client_chain(s, chain_pt, client_pt_len);
	}

	/* ── Handshake complete: Split() ── */

	{
		uint8_t k1[32], k2[32];  /* k1: initiator→responder, k2: responder→initiator */

		ret = sym_split(&sym, k1, k2);
		if (ret) {
			memset(k1, 0, 32);
			memset(k2, 0, 32);
			goto fail;
		}
		memcpy(s->rx_key, k1, 32);
		memcpy(s->tx_key, k2, 32);
		memset(k1, 0, 32);
		memset(k2, 0, 32);
	}

	s->rx_nonce = 0;
	s->tx_nonce = 0;
	s->established = true;

	memset(s_priv, 0, 32);
	memset(e_priv, 0, 32);
	memset(&sym, 0, sizeof(sym));

	LOG_INF("Noise_XX handshake complete");
	*session_out = s;
	return 0;

fail:
	memset(s_priv, 0, 32);
	memset(e_priv, 0, 32);
	memset(&sym, 0, sizeof(sym));
	memset(s, 0, sizeof(*s));
	session_free(s);
	return ret;
}

void session_close(cantil_session_t *session)
{
	if (session) {
		memset(session, 0, sizeof(*session));
		session_free(session);
	}
}

int session_send(cantil_session_t *session, const uint8_t *buf, size_t len)
{
	if (!session || !session->established) {
		return -EINVAL;
	}

	/* Static buffer — single-session firmware is single-threaded here. */
	static uint8_t ct_buf[MAX_FRAME_PAYLOAD + NOISE_TAG_LEN];
	size_t ct_len;

	int ret = noise_crypto_encrypt(ct_buf, sizeof(ct_buf), &ct_len,
				       session->tx_key, session->tx_nonce,
				       (const uint8_t *)"", 0,  /* AD = empty */
				       buf, len);
	if (ret) {
		return ret;
	}
	session->tx_nonce++;
	return send_frame(session->transport, ct_buf, ct_len);
}

int session_recv(cantil_session_t *session, uint8_t *buf,
		 size_t max_len, size_t *received)
{
	if (!session || !session->established) {
		return -EINVAL;
	}

	static uint8_t ct_buf[MAX_FRAME_PAYLOAD + NOISE_TAG_LEN];
	size_t ct_len;

	int ret = recv_frame(session->transport, ct_buf, sizeof(ct_buf), &ct_len);

	if (ret) {
		return ret;
	}
	if (ct_len < NOISE_TAG_LEN) {
		return -EPROTO;
	}

	ret = noise_crypto_decrypt(buf, max_len, received,
				   session->rx_key, session->rx_nonce,
				   (const uint8_t *)"", 0,  /* AD = empty */
				   ct_buf, ct_len);
	if (ret) {
		return ret;
	}
	session->rx_nonce++;
	return 0;
}

int session_get_remote_pubkey(cantil_session_t *session, uint8_t pubkey[32])
{
	if (!session || !session->established) {
		return -EINVAL;
	}
	memcpy(pubkey, session->remote_s_pub, 32);
	return 0;
}

int session_get_local_pubkey(cantil_session_t *session, uint8_t pubkey[32])
{
	if (!session || !session->established) {
		return -EINVAL;
	}
	memcpy(pubkey, session->local_s_pub, 32);
	return 0;
}

int session_get_client_cert(const cantil_session_t *session, size_t idx,
			    const uint8_t **der, size_t *len)
{
	if (!session || !der || !len) {
		return -EINVAL;
	}
	if (idx >= session->client_cert_count) {
		return -ENOENT;
	}
	*der = session->client_chain + session->client_cert_off[idx];
	*len = session->client_cert_len[idx];
	return 0;
}

size_t session_get_client_cert_count(const cantil_session_t *session)
{
	return session ? session->client_cert_count : 0;
}
