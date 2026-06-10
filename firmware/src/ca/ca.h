#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

int ca_init(void);

/* Called on first boot when no CA key exists yet. */
int ca_provision(void);

/* True once slot 0 has a key, x509 data, and a self-signed cert. */
bool ca_ready(void);

/*
 * Install x509 subject data into a key slot and (re)generate the slot's
 * self-signed certificate.
 *
 * `data` layout (flat, big-endian, owned by ca.c):
 *   [0]   validity_days  (2 bytes)
 *   [2]   is_ca          (1 byte: 0 or 1)
 *   [3]   path_len       (1 byte: 0..127, 0xFF = unconstrained)
 *   [4]   key_usage_bits (2 bytes; bitfield, see KU_* in ca.c)
 *   [6]   cn_len (1) + cn bytes
 *   ...   o_len  (1) + o bytes
 *   ...   ou_len (1) + ou bytes
 *   ...   c_len  (1) + c bytes (must be 0 or 2)
 *   ...   st_len (1) + st bytes
 *   ...   l_len  (1) + l bytes
 *
 * Honors the bootstrap exemption: if the slot is protected but has no cert
 * yet, the call is allowed; otherwise protected slots reject the push.
 */
int ca_push_key_x509(uint32_t slot_id, const uint8_t *data, size_t len);

/* CA management */
int ca_sign_csr(const uint8_t *csr_der, size_t csr_len,
		uint8_t *cert_der, size_t *cert_len);

/* Generic per-slot CSR signing — issuer_slot may be any populated slot with
 * stored x509 params (so the issuer DN can be reconstructed). Same on-wire
 * semantics as ca_sign_csr but for arbitrary sub-CAs. */
int ca_sign_csr_slot(uint32_t issuer_slot,
		     const uint8_t *csr_der, size_t csr_len,
		     uint8_t *cert_der, size_t *cert_len);
int ca_get_cert(uint8_t *cert_der, size_t *cert_len);
int ca_get_chain(uint8_t *chain_der, size_t *chain_len);

/*
 * Recursive chain walker for any key slot. Emits the slot's own cert.der
 * followed by either:
 *   - the pushed chain.der if it exists (externally-signed sub-CA), or
 *   - the issuer slot's full chain (on-device signed), recursing up.
 *
 * Returns -ENOENT if `slot` has no cert; -ELOOP if recursion exceeds the
 * configured slot count; -ENOMEM via the read helpers if the chain doesn't
 * fit in *chain_len.
 */
int ca_get_chain_slot(uint32_t slot, uint8_t *chain_der, size_t *chain_len);
int ca_get_serial(uint8_t *serial, size_t *serial_len);
int ca_get_csr(uint8_t *csr_der, size_t *csr_len);
int ca_push_cert(const uint8_t *cert_der, size_t cert_len,
		 const uint8_t *chain_der, size_t chain_len);

/* Issued certificate store */
int ca_list_certs(uint8_t *cbor_out, size_t *len);
int ca_get_issued_cert(const uint8_t *serial, size_t serial_len,
		       uint8_t *cert_der, size_t *cert_len);
int ca_get_cert_count(uint32_t *count);
/*
 * Mark `serial` revoked under its issuing slot's CRL. `now_unix` is recorded
 * on the cert's meta as the revocation date; pass 0 if no wall clock is
 * available (the DER encoder will substitute thisUpdate at fetch time).
 */
int ca_revoke_cert(const uint8_t *serial, size_t serial_len,
		   uint64_t now_unix);
int ca_auto_expire(uint64_t now_unix, uint32_t *expired_count);

/*
 * Build and return an RFC 5280 v2 CertificateList (DER) signed by the
 * issuer slot's private key. `now_unix` populates thisUpdate; nextUpdate
 * is thisUpdate + CONFIG_CANTIL_CRL_VALIDITY_SEC. Each revoked entry's
 * revocationDate comes from the cert's stored revoked_at_unix; if that
 * value is 0 (caller never supplied one), thisUpdate is used instead.
 *
 * Returns -EINVAL for bad args (out-of-range slot, now_unix==0, buffer
 * too small to even attempt encoding), -ENOENT if the slot has no key
 * or no self-signed cert (the cert provides the issuer Name), -ENOMEM
 * if the encoded CRL exceeds the supplied buffer, -EIO on mbedtls error.
 *
 * Slots with no revocations return a well-formed empty CRL.
 */
int ca_get_crl(uint32_t issuer_slot, uint64_t now_unix,
	       uint8_t *crl_out, size_t *crl_len);

/* General-purpose key slots */
int ca_list_keys(uint8_t *cbor_out, size_t *len);
int ca_gen_key(uint8_t key_type, uint32_t *slot_id_out);
/*
 * Delete an entire key slot (key blob, meta, x509 data, cert, CSR, CRL).
 * Refuses slot 0 (-EPERM) and protected slots (-EACCES).
 */
int ca_delete_key(uint32_t slot_id);

/*
 * Set the protection flag on a slot. If `protect_issued` is true, also walk
 * the issued-cert store and mark every cert with issuer_slot == slot_id as
 * protected (so REVOKE_CERT will refuse them). Caller is responsible for
 * obtaining the tap-confirm gesture before invoking this.
 */
int ca_protect_slot(uint32_t slot_id, bool protect_issued);

/* Clear the protection flag on a slot. Does NOT touch protected-cert flags
 * already set on issued certs — the spec treats those as permanent. */
int ca_unprotect_slot(uint32_t slot_id);
int ca_gen_key_csr(uint32_t slot_id, const char *subject_dn);
int ca_get_key_csr(uint32_t slot_id, uint8_t *csr_der, size_t *csr_len);
int ca_push_key_cert(uint32_t slot_id,
		     const uint8_t *cert_der, size_t cert_len,
		     const uint8_t *chain_der, size_t chain_len);
int ca_sign_key_slot(uint32_t issuer_slot, uint32_t subject_slot);

/*
 * Build an ECDSA self-signed transport-identity certificate for the session
 * slot (transport + pairing T-02). Unlike the /keys/<n>/ self-signed builder,
 * this is not slot-bound: the P-256 identity privkey and the packed x509_data_t
 * params blob (typically cantil_session_x509_constant[]) are supplied directly,
 * and the DER is returned in the caller's buffer.
 *
 *   x509_blob/blob_len : packed x509_data_t (same wire format x509_parse reads).
 *                        is_ca MUST be 0 — a session identity is never a CA.
 *   cn_override        : NUL-terminated CN to substitute (FICR-derived device
 *                        serial); NULL or "" keeps the blob's CN.
 *   id_priv[32]        : P-256 scalar; becomes the cert's SubjectPublicKeyInfo
 *                        and signs it.
 *   x25519_pub[32]     : raw Noise static pubkey, bound into the
 *                        1.3.6.1.4.1.58270.1.1 extension.
 *   out/out_len        : in = buffer capacity, out = DER length on success.
 *
 * Returns -EINVAL on bad params (is_ca set, CN too long, malformed blob),
 * -ENOMEM if the DER exceeds *out_len, -EIO on an mbedtls/crypto failure.
 */
int ca_build_session_cert(const uint8_t *x509_blob, size_t blob_len,
			  const char *cn_override,
			  const uint8_t id_priv[32],
			  const uint8_t x25519_pub[32],
			  uint8_t *out, size_t *out_len);

/*
 * Build a PKCS#10 CSR for the session transport identity (transport + pairing
 * T-05). Same inputs as ca_build_session_cert(): the CSR's SubjectPublicKeyInfo
 * is the P-256 identity key, the subject DN is rebuilt from the packed x509
 * params + cn_override (byte-identical to the self-signed cert's subject), and
 * the Noise X25519 static key rides in a non-critical extensionRequest so an
 * upstream CA can copy it into the issued cert. is_ca MUST be 0.
 *
 * Returns -EINVAL on bad params, -ENOMEM if the DER exceeds *out_len, -EIO on
 * an mbedtls/crypto failure.
 */
int ca_build_session_csr(const uint8_t *x509_blob, size_t blob_len,
			 const char *cn_override,
			 const uint8_t id_priv[32],
			 const uint8_t x25519_pub[32],
			 uint8_t *out, size_t *out_len);

/*
 * Build a CA-signed session transport-identity cert (transport + pairing T-06).
 *
 * The subject side is identical to ca_build_session_cert() — subject DN rebuilt
 * from the packed x509 params + cn_override, SubjectPublicKeyInfo is the P-256
 * identity key (id_priv), KU from the constant, is_ca rejected, and the Noise
 * X25519 static key bound into the 1.3.6.1.4.1.58270.1.1 extension. The
 * difference is the issuer: instead of self-signing, the cert's issuer DN and
 * signature come from CA slot `issuer_slot` (its stored x509 params + privkey).
 *
 * The session slot may never be an issuer; callers pass a numbered /keys/<n>/
 * CA slot. Slot 0 must be provisioned (ca_ready()).
 *
 * Returns -EINVAL on bad params (is_ca set, bad slot, malformed blob), -ENOENT
 * if the issuer slot has no key (or slot 0 isn't ready), -ENOMEM if the DER
 * exceeds *out_len, -EIO on an mbedtls/crypto failure.
 */
int ca_sign_session_cert(uint32_t issuer_slot,
			 const uint8_t *x509_blob, size_t blob_len,
			 const char *cn_override,
			 const uint8_t id_priv[32],
			 const uint8_t x25519_pub[32],
			 uint8_t *out, size_t *out_len);

/*
 * Strict boot-time identity check (transport + pairing T-03).
 *
 * Compares the subject-side identity fields of a stored session cert (`cert_der`)
 * against the build-time x509 constant (`x509_blob`, typically
 * cantil_session_x509_constant[]). The compared fields are O, OU, C, ST, L,
 * key_usage, and — for self-signed certs — the validity window. Deliberately
 * IGNORED: CN (FICR-derived per device), and issuer DN / signature / serial
 * (which legitimately change when the cert is CA-signed).
 *
 * Validity relaxation (T-08): if the cert is CA-signed (issuer != subject) the
 * not_after comparison is skipped, because an external CA sets its own validity
 * window and cannot be required to reproduce the device's synthetic constant.
 * The chain-signature gate in ca_validate_pushed_session_cert() already
 * verified trust for such certs.
 *
 * Returns 1 if the identity fields match, 0 on a field mismatch, and a negative
 * errno if either input fails to parse.
 */
int ca_session_cert_matches_constant(const uint8_t *cert_der, size_t cert_len,
				     const uint8_t *x509_blob, size_t blob_len);

/*
 * Validate an externally-signed session cert before it is installed
 * (transport + pairing T-07, PUSH_SESSION_CERT). Checks, in order:
 *   1. SPKI gate     — the cert's subject pubkey equals `id_pub` (the device's
 *                      P-256 session identity key, SEC1 0x04||X||Y).
 *   2. X25519 gate    — the cert's binding extension equals `x25519_pub`.
 *   3. Constant gate  — subject-side identity fields match the build constant
 *                      (`x509_blob`) per ca_session_cert_matches_constant().
 *   4. Chain gate     — if the leaf is CA-signed (issuer != subject) it MUST
 *                      arrive with `chain_der` (concatenated DER), and every
 *                      signature link from leaf up to the topmost supplied cert
 *                      (the trust anchor) is verified. Validity windows are
 *                      ignored — the device has no RTC. A self-signed leaf needs
 *                      no chain.
 *
 * `*out_ca_signed` (optional) reports whether the leaf is CA-signed, so the
 * caller can latch the SESSION_META_FLAG_CA_SIGNED marker. Returns 0 if the
 * cert is acceptable, -EINVAL on any gate failure, negative errno otherwise.
 */
int ca_validate_pushed_session_cert(const uint8_t *cert_der, size_t cert_len,
				    const uint8_t *chain_der, size_t chain_len,
				    const uint8_t id_pub[65],
				    const uint8_t x25519_pub[32],
				    const uint8_t *x509_blob, size_t blob_len,
				    bool *out_ca_signed);

/*
 * Validate a client certificate chain against the cert stored in an on-device
 * CA slot (transport + pairing T-19, Method 4). cert_ders[]/cert_lens[] are
 * leaf-first with cert_count entries. The anchor CA cert is loaded from
 * anchor_slot's /keys/<slot>/cert.der. Returns 0 on success, -ENOENT if the
 * anchor slot has no cert, -EINVAL on chain validation failure.
 */
int ca_validate_client_cert_chain(const uint8_t *const cert_ders[],
				   const size_t cert_lens[], size_t cert_count,
				   uint32_t anchor_slot);
