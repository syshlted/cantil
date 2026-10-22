/* SPDX-License-Identifier: GPL-3.0-or-later */
/* See LICENSE at the repo root. */

#ifndef CANTIL_HOST_X509_H
#define CANTIL_HOST_X509_H

/*
 * x509 — the host's backend-independent X.509 *reader* seam.
 *
 * Step 5 of docs/roadmap/wolfssl-migration.md, then the mbedTLS drop of
 * 2026-07-24. trust.c evaluates the four trust tiers (see
 * docs/transport-security.md); everything it needs from a certificate library
 * is the three functions below. Implementations:
 *
 *   x509_openssl.c  — the default. libcrypto is the library a Linux host is
 *                     most likely to already have, and it is the third
 *                     implementation the test fixtures are generated from.
 *   x509_wolfssl.c  — matches the firmware's library. Needs a host wolfSSL;
 *                     scripts/setup_wolfssl_host.sh builds one.
 *
 * Selected at configure time by -DCANTIL_HOST_CRYPTO=openssl|wolfssl. Exactly
 * one is compiled, so they never collide. (The mbedTLS backend was removed when
 * the firmware went wolfCrypt-only; it lives in git history if wanted back.)
 *
 * The seam is deliberately *bytes in, bytes out* — no library type appears in
 * this header, and nothing returns a pointer into a parsed structure whose
 * lifetime the caller would have to reason about. Every output is copied into
 * a caller-supplied buffer. That costs a memcpy of at most a few hundred bytes
 * per check and removes the whole class of use-after-free the three libraries
 * would otherwise each express differently.
 *
 * Note this is the *host* seam. It has no relation to the firmware's
 * ca/certgen.h beyond the shape of the idea: that one writes certificates,
 * this one reads them, and the two never share a build.
 */

#include <stdint.h>
#include <stddef.h>

/* Longest subject DN TLV a Cantil certificate can carry. The six RDNs are
 * capped at 64 chars each by the firmware's x509_params_t, so a real DN is
 * ~200 B; 512 is slack, not a measured bound. */
#define CANTIL_X509_SUBJECT_MAX 512

/* Errors. Negative so they never collide with a length. trust.c maps these
 * onto cantil_err_t; they are intentionally coarse, because a caller cannot
 * act differently on "malformed" vs "unsupported curve". */
#define CANTIL_X509_OK          0
#define CANTIL_X509_ERR_PARSE  (-1)   /* not a certificate we can read */
#define CANTIL_X509_ERR_ABSENT (-2)   /* parsed, but the field is not present */
#define CANTIL_X509_ERR_SPACE  (-3)   /* caller's buffer is too small */
#define CANTIL_X509_ERR_CHAIN  (-4)   /* chain does not verify */
#define CANTIL_X509_ERR_INTERNAL (-5) /* allocation or library failure */

/*
 * Copy the certificate's subject DN as a complete DER element — the SEQUENCE
 * tag and length included, not just its contents.
 *
 * That boundary is load-bearing and is *not* what every library hands you.
 * mbedTLS's `subject_raw` spans the full TLV; wolfSSL's `subjectRaw` points at
 * the contents only, after the tag and length are consumed. The two differ by
 * the 2-4 byte header. Since Tier 2 compares this against a value a user
 * pinned earlier — possibly with a client built against the other library —
 * every backend must normalise to the same definition or pins silently stop
 * matching. The full TLV is the definition, chosen because it is what the
 * existing mbedTLS-built clients already stored.
 *
 * Returns CANTIL_X509_OK, or ERR_PARSE / ERR_SPACE.
 */
int cantil_x509_subject_der(const uint8_t *cert_der, size_t cert_len,
                            uint8_t *out, size_t out_cap, size_t *out_len);

/*
 * Copy the subject's commonName as a NUL-terminated string.
 *
 * Returns CANTIL_X509_OK, ERR_PARSE, ERR_ABSENT (no CN in the subject) or
 * ERR_SPACE.
 */
int cantil_x509_subject_cn(const uint8_t *cert_der, size_t cert_len,
                           char *out, size_t out_cap);

/*
 * Verify that `leaf` chains to `ca`, optionally through `inter_count`
 * intermediates supplied in any order.
 *
 * Two policy decisions are baked in, because they are properties of Cantil's
 * certificates rather than of any caller:
 *
 *   - Validity dates are NOT checked. The device has no RTC, so it issues
 *     certificates with a synthetic validity window; every one of them would
 *     otherwise fail. The firmware's own chain_vrfy_cb in ca.c clears the same
 *     two flags, and this mirrors it.
 *   - The profile is P-256 / SHA-256 / ECDSA only, matching what the device
 *     can produce. Anything else is a certificate Cantil did not issue.
 *
 * Returns CANTIL_X509_OK, ERR_PARSE (any input unreadable), ERR_CHAIN (parsed
 * fine, does not verify) or ERR_INTERNAL.
 *
 * Callers must treat "not CANTIL_X509_OK" as the refusal, never a particular
 * error code. A certificate outside the profile may surface as ERR_CHAIN or as
 * ERR_PARSE depending on how the backend was built — a wolfSSL compiled
 * without RSA cannot even decode an RSA key, where mbedTLS parses it and then
 * rejects it on policy. Both refuse; only the reason differs.
 */
int cantil_x509_verify_chain(const uint8_t *leaf_der, size_t leaf_len,
                             const uint8_t *const inter_ders[],
                             const size_t inter_lens[],
                             size_t inter_count,
                             const uint8_t *ca_der, size_t ca_len);

/*
 * Human-readable name of the compiled-in backend ("openssl" or "wolfssl").
 * Reported by `cantil version` so a bug report says which X.509 stack produced
 * it.
 */
const char *cantil_x509_backend_name(void);

#endif /* CANTIL_HOST_X509_H */
