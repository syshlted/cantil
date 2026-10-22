# Phase 2 — wolfSSL migration

> **Complete 2026-07-24.** All six steps landed; mbedTLS is gone from the
> firmware (wolfCrypt only). The step-6 retrospective is
> [below](#step-6--mbedtls-removed-landed-2026-07-24). A follow-on "Step 7"
> (same day) removed mbedTLS from `libcantil` too — OpenSSL is now the client's
> default X.509 backend — so mbedTLS is gone from the whole repo.
>
> **Reordered 2026-07-22.** This was Phase 3; it ran before Bazel — doing it
> first removed the Mbed TLS 4.x blocker that makes the Bazel migration
> expensive, and avoided writing a large `modules/mbedtls.BUILD` this phase
> would immediately make disposable. Reasoning:
> [bazel-migration.md](bazel-migration.md).
>
> Order: 1 upstream Zephyr ✓ → **2 wolfSSL ✓** → 3 Bazel → 4 multi-platform.

Replace mbedTLS with wolfCrypt/wolfSSL across firmware and `libcantil`.

## Decision (2026-07-22): relicense to GPLv3, drop FIPS certification

Project scale is an open-source project deployed to **at most two devices**,
not a commercial product. That settles most of the analysis below:

- **FIPS certification is out of scope.** It exists to satisfy procurement
  auditors. With no commercial deployment there is nobody to present a
  certificate to, and the commercial module (~$7,500/product) is not a
  rational spend. FIPS *alignment* remains optional design hygiene, not a
  driver — see the caveat in the FIPS section below.
- **Post-quantum is the real motivation**, and it is in the open-source
  distribution.
- **GPLv3 is the target license.** It is compatible with wolfSSL 5.8.2+,
  absorbs Apache-2.0 Zephyr and mbedTLS one-way, keeps AGPLv3 downstreams
  able to consume, and retains a patent grant (§11) equivalent to
  Apache §3. There is a single copyright holder, so the relicense is
  unilateral — no CLA or contributor permission needed.

### Prerequisite: relicense to GPLv3 — **done 2026-07-22**

`9e84dba` had changed `LICENSE`, `CONTRIBUTING.md` and three docs while
touching **zero source files**, leaving the tree inconsistent. The audit
found it was worse than recorded here: not 16 stale headers but **71**, plus
**46** source files carrying no SPDX header at all, all against a `LICENSE`
that said Apache 2.0.

Resolved:

1. ✅ `LICENSE` replaced with the GPL-3.0 text.
2. ✅ `cantil-additional-permissions` **retired**, not restored. The `WITH`
   clause was stripped from all 71 headers and the dangling
   `LICENSE-EXCEPTIONS.md` pointers removed. Consequence, stated plainly:
   there is no linking exception, so proprietary applications cannot link
   `libcantil` — the client library is copyleft along with the firmware.
3. ✅ Every tracked source file now carries
   <!-- REUSE-IgnoreStart -->
   `SPDX-License-Identifier: GPL-3.0-or-later` (117 files).
   <!-- REUSE-IgnoreEnd -->
4. ✅ `CONTRIBUTING.md` updated, including a note that the retired exception
   identifier must not reappear.
5. ✅ `docs/competitor-comparison.md` and `docs/reference/architecture.md`
   updated.
6. ✅ `docs/crypto-blobs.md` rewritten — its conclusion **inverted**. Under
   Apache 2.0 the Nordic 5-Clause blob created no upstream conflict and the
   restrictions merely flowed to recipients. Under GPLv3 clauses 4 and 5 are
   further restrictions barred by §7, so a combined binary cannot lawfully be
   distributed at all. Local use is unaffected.

The rest of this document records the analysis that led here and the
constraints that still apply.

## Why it looked easy

The crypto abstraction is unusually narrow. `firmware/src/crypto/crypto.h`
is 8 functions and `firmware/src/session/noise_crypto.h` is 6. Both were
designed for backend substitution, and `noise_crypto.h` says so explicitly.

wolfSSL is an [optional Zephyr
module](https://docs.zephyrproject.org/latest/develop/manifest/external/wolfssl.html),
so Phase 1 does not complicate it.

> **Corrected 2026-07-23.** This paragraph used to say the module was
> "present in the upstream west manifest at `modules/crypto/wolfssl/zephyr/`".
> It is not, and that page is why: it lists *external* modules, which in
> Zephyr's terminology means "known to work with Zephyr and maintained
> elsewhere", not "fetched by `west update`". Checked against the v4.3.1
> manifest — no `wolfssl` project, and `modules/crypto/` contains only
> `mbedtls`. It is now a project entry in `firmware/west.yml`, pinned to
> `v5.9.2-stable`, which costs nothing beyond writing the four lines.

Certificate work — `WOLFSSL_CERT_GEN`, `WOLFSSL_CERT_REQ` for CSRs,
`WOLFSSL_CERT_EXT` for extensions, plus CRL support — lives inside wolfCrypt
rather than a separate library.

## Why it is not that easy — measured 2026-07-22

The 14-function abstraction is real, but **X.509 bypasses it completely**.
Counting direct `mbedtls_` references outside the two backend
implementations:

| File | Refs | Dominated by |
| --- | --- | --- |
| `firmware/src/ca/ca.c` | **230** | `x509write_crt` 67, `x509_crt` 55, `asn1_write` 32, `x509write_csr` 16 |
| `libcantil/src/trust.c` | **34** | `x509_crt` chain validation, host side |
| `firmware/src/session/session_slot.c` | 13 | all `mbedtls_platform_zeroize` |
| `firmware/src/crypto/crypto_psa.c` | 3 | ACCELERATED backend, already gated off |
| `session.c`, `pairing.c` | 2 | incidental |

So roughly **280 call sites**, of which ~180 are X.509 and ASN.1 in `ca.c`
alone. Swapping `crypto.c` and `noise_crypto_mbedtls.c` — the part the
abstraction was designed for — is perhaps a tenth of the phase.

The X.509 port is not mechanical either. mbedTLS builds certificates
incrementally through `mbedtls_x509write_crt_set_*` mutators on an opaque
context; wolfSSL fills in a `Cert` struct and calls `wc_MakeCert` /
`wc_SignCert`. The shapes do not correspond one-to-one, so this is a
rewrite of the cert and CSR construction paths, not a symbol substitution.

The 32 `mbedtls_asn1_write_*` calls are the hand-rolled RFC 5280 CRL writer
(mbedTLS has no CRL writer, which is why it exists). Those depend only on
thin ASN.1 primitives and are the most portable part — budget them as the
easy end.

Suggested order, each independently verifiable against the existing ztest
suites:

1. ✅ **Done 2026-07-23.** `crypto.c` → `crypto_wolfssl.c` (8 functions) and
   `noise_crypto_mbedtls.c` → `noise_crypto_wolfssl.c` (6 functions), behind
   a new `CANTIL_CRYPTO_BACKEND_WOLFSSL` Kconfig choice. Both backends
   coexist during the port. See "Step 1" below.
2. ✅ **Done 2026-07-23.** `mbedtls_platform_zeroize` → a Cantil-local
   `cantil_zeroize` helper — 43 call sites (not 37), removes an mbedTLS
   dependency from files that otherwise have none. See "Step 2" below.
3. ✅ **Done 2026-07-23.** The ASN.1/CRL writer — to a Cantil-local
   backwards-DER writer, not to wolfCrypt. See "Step 3" below.
4. ✅ **Done 2026-07-23.** `ca.c` cert + CSR construction — behind a new
   `ca/certgen.h` writer seam with mbedTLS and wolfCrypt implementations. The
   CRL signer moved off `slot_pk`/`mbedtls_pk_sign` too. See "Step 4" below.
5. ✅ **Done 2026-07-23.** `libcantil/src/trust.c` — host-side chain
   validation. Became a *swappable* `libcantil/src/x509.h` seam (mbedTLS,
   wolfSSL, OpenSSL) rather than a port to wolfSSL, because the client may want
   OpenSSL. Found two real bugs, one of them shipped. See "Step 5" below.
6. Delete the mbedTLS backend and drop the module from `west.yml`.

## Step 1 — the two backend files, landed 2026-07-23

Files added:

| File | What |
| --- | --- |
| `firmware/west.yml` | wolfSSL `v5.9.2-stable` as a project entry (it is not in Zephyr's manifest — see the correction above) |
| `firmware/include/cantil_wolfssl_user_settings.h` | the whole wolfCrypt configuration; the module reads nothing else |
| `firmware/src/crypto/crypto_wolfssl.c` | `crypto.h`, 8 functions |
| `firmware/src/session/noise_crypto_wolfssl.c` | `noise_crypto.h`, 6 functions |
| `firmware/src/crypto/wc_rand.{c,h}` | the one entropy seam between Zephyr and wolfCrypt |
| `firmware/prj_wolfssl.conf`, `scripts/build.sh --wolfssl` | how to select it |
| `firmware/tests/crypto_kat/`, `firmware/tests/crypto_kat_wolfssl/` | new; see below |
| `firmware/tests/noise_crypto_wolfssl/` | the existing Noise vectors, re-pointed |

### The gate: neither backend is the oracle

`firmware/tests/noise_crypto/` was the stated acceptance criterion and it
passes unmodified — 15/15 — against wolfCrypt, from a sibling directory that
references the same `src/main.c` and `vectors.h` rather than copying them.

That left `crypto.h` with no gate at all. The doc's plan was "then
`ca_bootstrap`, `sign_csr` and `session_*`", but those suites build `ca.c`,
which is still mbedTLS-bound until step 4 — so they cannot run against this
backend yet, and the eight functions with the highest blast radius in the
whole phase would have shipped untested. Hence a new `crypto_kat` suite, run
from two directories, 12 tests each:

- **`crypto_storage_key_derive()` against a fixed answer.** This is not an
  interoperability test but a data-availability one. The CA private key is
  AES-256-GCM encrypted under that derived key, cannot be exported, and has no
  backup. A backend that derived it differently would turn a firmware update
  into unrecoverable key loss: the device boots, mounts its volume, finds its
  key blob intact, and cannot authenticate it. The same reasoning covers
  `decrypt_blob`, which pins the on-disk `[nonce][ct][tag]` layout.
- **ECDSA against RFC 6979 §A.2.5 verbatim.** Deterministic signing makes
  P-256 a true known-answer test. `gen_vectors.py` recomputes `k`, `r`, `s`
  and the public key itself and asserts they equal the transcribed RFC
  literals, so a transcription slip fails the generator rather than producing
  a vector only one implementation agrees with.

The vectors come from RFC 6979 and from Python's HKDF/AES-GCM, so passing in
both directories means both libraries agree with a third implementation —
which is the only form of agreement worth having here.

Suites: 18 dirs / 19 suites / 235 tests (was 16 / 16 / 196).

### Two things wolfCrypt does differently

**Empty AEAD plaintexts are rejected.**
`wc_ChaCha20Poly1305_Encrypt()` validates its arguments as though a NULL
plaintext of length 0 were legal, then passes that NULL to
`wc_ChaCha20Poly1305_UpdateData()`, which rejects a NULL data pointer
regardless of length. The result is `BAD_FUNC_ARG` (-173) where mbedTLS
returns a bare tag. Noise_XX AEAD-encrypts an empty payload during the
handshake, so every session would have failed on its first message; this was
caught by `aead_empty_plaintext`, the one test that failed on the first run.
`noise_crypto_wolfssl.c` substitutes a pointer to a static one-byte array.

**All-zero X25519 shared secrets are refused.** wolfCrypt returns an error
where mbedTLS returns the zero secret — the outcome of a peer sending a
small-order point. That is stricter than Noise requires and is the safer
behaviour, but it is a real difference: a handshake mbedTLS would have
continued fails here. It surfaces as a failed handshake, not a silently weak
session.

`SINGLE_THREADED` is a third difference, though one of ours rather than
wolfCrypt's. Its Zephyr port offers only that or pthreads via
`CONFIG_POSIX_THREADS` — there is no `k_mutex` option — and pulling the POSIX
subsystem into a security device for one mutex is the worse trade. The claim
it rests on is written out in the settings header, along with what would
invalidate it.

### What step 1 cost

| Build | FLASH | RAM |
| --- | --- | --- |
| FREE (mbedTLS), unchanged | 203,720 B | 74,912 B |
| WOLFSSL, uf2_only tier | 252,896 B | 66,208 B |
| WOLFSSL, mcuboot tier | 256,848 B / 489,322 B | 66,208 B |

Attributing allocated sections from the linker map:

| | FREE | WOLFSSL step 1 |
| --- | --- | --- |
| Cantil + Zephyr | 217,754 B | 217,596 B |
| mbedTLS | 55,827 B | 38,915 B |
| wolfCrypt | — | 57,498 B |

So mbedTLS splits roughly 38.9 KB of X.509 (still needed by `ca.c`) and
16.9 KB of primitives (now displaced). **wolfCrypt costs ~57.5 KB for the
same fourteen functions mbedTLS provided in ~16.9 KB** — a 3.4× premium, and
the reason the "smaller footprint" line above is now struck through. It is
not obviously bad: 22.9 KB of that is `sp_cortexm.c`, which buys assembly
P-256 where mbedTLS is pure C. But the footprint argument for this phase does
not survive measurement, and step 6's net saving is now an open question
rather than an assumption.

Two settings were worth 15,560 B between them, found by breaking the map file
down per object rather than guessing:

- `NO_SHA` — SHA-1 was being compiled in at 4,146 B. Nothing in Cantil uses
  it; wolfCrypt just enables it by default.
- `WOLFSSL_AES_SMALL_TABLES` — the default AES tables were 14,816 B, more
  than every other primitive here combined, to speed up a cipher this device
  runs over 60 bytes at a time. 3,636 B with small tables.

`WOLFSSL_SP_ARM_CORTEX_M_ASM` was measured too, and is free: turning it off
*grew* the image by 2,096 B, because the generic C paths in `sp_int.c` it
displaces are larger than the 22,930 B of assembly. Faster and smaller, not a
trade.

### What step 1 did not do

Selecting this backend **adds** a library rather than replacing one.
`firmware/src/ca/ca.c` still builds every certificate, CSR and CRL through
mbedTLS's `x509write` and `asn1_write` APIs — ~180 call sites that bypass both
abstractions — so `prj_wolfssl.conf` has to keep `CONFIG_MBEDTLS=y` and the
image links both. That is the shape of steps 2 through 6, and it is why the
flash figures above are not the ones to judge the phase by.

Cert and CSR generation (`WOLFSSL_CERT_GEN` / `WOLFSSL_CERT_REQ`) is
deliberately absent from the settings header for the same reason: enabling it
now would ship a second, unreachable X.509 writer. `NO_ASN_TIME` is set for
now and will need revisiting at step 4, when writing a certificate has to emit
`notBefore` / `notAfter` again.

## Step 2 — cantil_zeroize, landed 2026-07-23

`mbedtls_platform_zeroize` had **43** call sites, not the 37 the plan
estimated: 24 in `ca.c`, 16 in `session_slot.c`, 2 in `noise_crypto_mbedtls.c`,
1 in `crypto.c`. All now call `cantil_zeroize`
([firmware/src/crypto/zeroize.c](../../firmware/src/crypto/zeroize.c)), a
14-line volatile-pointer scrub — the same dead-store-defeating technique
`mbedtls_platform_zeroize` and OpenSSL's `OPENSSL_cleanse` use, with no library
behind it. It is an always-on source, since `ca.c` and `session_slot.c` need it
regardless of crypto backend.

The concrete win is `session_slot.c`: its **only** mbedTLS reference was that
one symbol, so it now links no crypto library at all — which is exactly the
outcome this step exists for. `ca.c` still pulls in mbedTLS for X.509 (step 4),
and the two backend files keep their respective libraries, so for them the
change is consistency rather than decoupling.

It also fixed a real defect in the step-1 wolfSSL files. `crypto_wolfssl.c` and
`noise_crypto_wolfssl.c` had scrubbed secrets — the FICR UID, the clamped
X25519 scalar, and the 64-byte HKDF output — with plain `memset()`, which is a
dead store on a buffer about to leave scope and which the compiler is free to
delete. Those three sites now use `cantil_zeroize`. (The `memset` in
`nonce_encode` stays: it is formatting a nonce, not scrubbing a secret.)

No dedicated ztest. A test that `cantil_zeroize` writes zeros is trivial and
proves nothing about the property that matters — that the write is *not
elided* — which is by construction unobservable from within the program. The
helper is exercised transitively by every crypto suite. FREE cost: +16 B
(203,720 → 203,736). 17 test suites gained the source file; all 19 suites stay
green.

## Step 3 — the CRL/ASN.1 writer, landed 2026-07-23

**Ported to a Cantil-local DER writer, not to wolfCrypt** — and that is the
right call, not a shortcut. The CRL encoder in `ca.c` (~`build_crl_der` and its
helpers) is hand-rolled precisely because *no* crypto library ships a CRL
writer: mbedTLS has none, and neither does wolfCrypt. So it never depended on a
library for the CRL *structure* — only on mbedTLS's generic DER byte primitives
(`mbedtls_asn1_write_len/tag/raw_buffer/int/oid` and the `MBEDTLS_ASN1_CHK_ADD`
macro). Those are the whole of what step 3 replaces.

[firmware/src/ca/der_write.c](../../firmware/src/ca/der_write.c) is Cantil's own
copy of those five, ~130 lines, no library behind them. The API deliberately
mirrors the mbedtls one — same backwards-writing convention (`*p` moves left,
returns bytes-written or a negative error), same `CHK_ADD`-with-an-in-scope-`ret`
shape — so the encoder changed by a near-mechanical rename plus two OID-argument
edits and two local OID byte arrays. The `MBEDTLS_OID_*` string macros became
`static const uint8_t OID_*[]`.

Why not wolfCrypt's ASN.1 writers: they encode **forwards** (`SetSequence`,
`SetLength`, …), with a different calling convention, and many are internal
(`WOLFSSL_LOCAL`). The CRL encoder is built to write right-to-left — content,
then length, then tag — so adopting them would rewrite its control flow, not
swap a primitive. The Cantil writer is also **disposable-free**: it survives
step 6 (dropping mbedTLS) untouched, where a wolfCrypt port would not have
removed the dependency, only moved it.

Scope held tight. Only the ASN.1 *write* path moved. `ca.c` still uses
`mbedtls_asn1_get_tag` to split the session-cert chain, and still parses the
issuer cert and signs the TBS through mbedTLS — those are reads and signing,
i.e. step 4. `#include <mbedtls/asn1write.h>` is gone; `asn1.h` and `oid.h`
stay for the reader and the `MBEDTLS_OID_AT_*` name comparisons.

Verification is unusually strong here. The `crl_der` suite (13 tests) parses
every generated CRL with `mbedtls_x509_crl_parse_der` — an independent DER
*parser*, which rejects malformed lengths or tags — and tests 04/05 verify the
CRL **signature** under the issuer key. A single wrong byte in the encoded
TBSCertList would change the hash and fail that verification. 13/13 green means
the writer is byte-exact on the signed structure, not merely self-consistent.

FREE cost: +472 B (203,736 → 204,208), the writer's code with no offset yet —
mbedTLS's `asn1write.c` is still linked by the cert-construction path and only
gets garbage-collected at step 6. All 19 suites green; 7 `ca.c`-building suites
gained the source file.

## Step 4 — the cert + CSR writer seam, landed 2026-07-23

The bulk. `ca.c` built every certificate, CSR and CRL through mbedTLS's
`x509write` and `asn1_write` APIs — ~180 call sites across seven builders. These
now go through **`ca/certgen.h`**, a backend-independent *writer* seam with two
implementations selected by the same `CANTIL_CRYPTO_BACKEND` choice:

| File | Backend | What |
| --- | --- | --- |
| `firmware/src/ca/certgen.h` | — | seam: raw bytes in, DER out |
| `firmware/src/ca/certgen_mbedtls.c` | FREE, ACCELERATED | the existing `mbedtls_x509write_*` path, moved verbatim; `slot_pk` (incl. the PSA-opaque signing key) came with it |
| `firmware/src/ca/certgen_wolfssl.c` | WOLFSSL | `wc_MakeCert` / `wc_SignCert` / `wc_MakeCertReq` |

The seam speaks only bytes — P-256 keys as the raw 32-byte scalar or 65-byte
SEC1 point, a structured DN, serial, pre-formatted validity strings, and an
optional custom extension. It carries no mbedTLS or wolfSSL type, which is what
lets `ca.c` compile against either backend unchanged and lets step 6 delete the
mbedTLS writer by removing one file. `ca.c` keeps everything else: slot loading,
storage, serial/date policy, and all X.509 **reads** (CSR/cert parsing, pubkey
extraction) — still mbedTLS until steps 5–6.

Chosen over inline `#ifdef` in the 3,200-line `ca.c` deliberately (mirrors the
existing `crypto.h` / `crypto_wolfssl.c` backend split).

### The CRL signer moved too

Step 3 left the CRL *signature* on `slot_pk` + `mbedtls_pk_sign`, which was the
last `slot_pk` user in `ca.c`. It now signs through the backend-agnostic
`crypto_sign` (raw P1363 `r||s`) and DER-encodes the `Ecdsa-Sig-Value` SEQUENCE
with a new `cantil_der_mpint` primitive in `der_write.c` (a big-endian INTEGER
with the leading-zero/sign handling `cantil_der_int`'s `uint32_t` form can't do).
`slot_pk`, `rng_cb` and every `x509write`/`mbedtls_pk_sign` reference are gone
from `ca.c`; it holds only mbedTLS *readers* now. `crl_der`'s tests 04/05 verify
the CRL signature under the issuer key, so a wrong byte fails them — 13/13 green
across both backends.

### DN: structured, six RDNs

The seam DN is the six RDNs Cantil issues (CN/O/OU/C/ST/L), filled from three
sources: the parsed `x509_params` blob, a parsed CSR's subject (by OID), and —
for `GEN_KEY_CSR` — a host RFC 4514 string. That last path now **rejects
attribute types outside the six** (`-EINVAL`), a deliberate narrowing: Cantil
only ever issues those, and wolfCrypt's `CertName` cannot encode arbitrary RDNs.
Escaped separators are not supported.

### Five things wolfCrypt needed that mbedTLS did not

Found by running the wolfSSL writer against the existing suites' mbedTLS-parse
assertions (below); each surfaced as a concrete failure, not a guess.

1. **The subject key needs its public point computed.**
   `wc_ecc_import_private_key_ex(priv, …, NULL, 0, …)` imports only the scalar;
   `wc_MakeCert`/`wc_MakeCertReq` write the subjectPublicKeyInfo from the public
   point, so `certgen_wolfssl.c` calls `wc_ecc_make_pub()` after importing a
   private subject key. (An `-EIO` from every cert build until fixed.)
2. **A CSR's version is 0.** `wc_InitCert` defaults `cert.version = 2` (v3, right
   for a certificate); a PKCS#10 CertificationRequestInfo is v1 (`0`). Left
   unset, mbedTLS rejected the CSR as `version = 2`.
3. **The custom X25519 extension is byte-compatible for free.**
   `wc_SetCustomExtension` wraps the raw 32-byte value in the OCTET STRING
   `extnValue`, exactly as `mbedtls_x509write_crt_set_extension` did — so a
   client parses either backend's session cert identically. It needs
   `WOLFSSL_ASN_TEMPLATE` + `WOLFSSL_CUSTOM_OID` + `HAVE_OID_ENCODING`, and takes
   the OID as a dotted-decimal string (certgen converts the DER OID bytes).
4. **`NO_ASN_TIME` stays.** The device has no RTC. certgen hands `wc_MakeCert`
   pre-encoded `Cert.beforeDate`/`afterDate` (UTCTime < 2050, else
   GeneralizedTime), which takes wolfCrypt's manual-date path and never calls
   `SetValidity` — so cert generation needs no `time()` backend after all. The
   step-1 note predicting this would need revisiting is resolved: it did not.
5. **KeyUsage passes straight through.** wolfCrypt's `KEYUSE_*` bit values equal
   the RFC 5280 / mbedTLS `MBEDTLS_X509_KU_*` encoding, so `params.key_usage`
   goes into `cert.keyUsage` unmodified. Signing is deterministic (RFC 6979) via
   `wc_ecc_set_deterministic_ex`, matching `crypto_sign` and the mbedTLS backend.

Config added to `cantil_wolfssl_user_settings.h`: `WOLFSSL_CERT_GEN`,
`WOLFSSL_CERT_REQ`, `WOLFSSL_CERT_EXT`, `WOLFSSL_ASN_TEMPLATE`,
`WOLFSSL_CUSTOM_OID`, `HAVE_OID_ENCODING`.

### The gate: the wolfSSL writer cross-checked by the mbedTLS parser

The existing `ca.c` suites parse and verify every generated cert/CSR/CRL with
**mbedTLS** as an independent checker. Three new sibling suites re-point those
same suites' `src/main.c` at the wolfCrypt writer (`crypto_wolfssl.c` +
`certgen_wolfssl.c`) while keeping mbedTLS linked as the parser — so the
existing assertions now cross-check the wolfSSL output, and neither library is
its own oracle:

- `sign_csr_wolfssl` — 52 tests: CA-signed leaves from CSRs, sub-CA chains,
  chain verification, CSR round-trip.
- `ca_bootstrap_wolfssl` — 9 tests: self-signed root, basicConstraints CA:TRUE,
  provisioning.
- `session_slot_wolfssl` — 27 tests: the session cert's X25519 binding
  extension (the highest-risk wolfCrypt-specific path).

Suites: 22 dirs / 22 suites / 323 tests. The FREE `ca.c` suites (sign_csr 52,
session_slot 27, ca_bootstrap 9, crl_der 13, …) stay green unchanged.

### What step 4 cost

| Build | FLASH | vs prior |
| --- | --- | --- |
| FREE (mbedTLS) | 203,644 B | −564 B from step 3 — the CRL's move to `crypto_sign` shed the `mbedtls_pk_sign` path |
| WOLFSSL, uf2_only | 259,680 B | +6,784 B over step 1 — `WOLFSSL_CERT_GEN`/`_REQ`/`_EXT` + `ASN_TEMPLATE` + custom-OID + `certgen_wolfssl.c` |

The WOLFSSL image still links both libraries (`ca.c` reads are mbedTLS), so this
figure is not the one to judge the phase by — step 6 is.

## Step 5 — the host X.509 seam, landed 2026-07-23

The plan said "port `trust.c` to wolfSSL". It became something better on
request: **the host X.509 library is now swappable**, because the client may
want OpenSSL rather than either of the two the firmware cares about.

So `libcantil/src/x509.h` is a seam in the same spirit as the firmware's
`ca/certgen.h` — bytes in, bytes out, no library type in the header — and
`trust.c` names no certificate library at all:

> **Superseded 2026-07-24** by "Step 7" below: the mbedTLS backend was dropped
> and OpenSSL became the default. This table records the step-5 state.

| File | Backend | Status |
| --- | --- | --- |
| `libcantil/src/x509_mbedtls.c` | **default** | Fedora packages `mbedtls-devel`, so the CLI builds with no setup |
| `libcantil/src/x509_wolfssl.c` | matches the firmware | needs `scripts/setup_wolfssl_host.sh` |
| `libcantil/src/x509_openssl.c` | reserved | **not written** — see below |

Selected with `-DCANTIL_HOST_CRYPTO=mbedtls|wolfssl|openssl`. The whole surface
is three functions: `subject_der`, `subject_cn`, `verify_chain`. Every output is
copied into a caller buffer rather than returned as a pointer into a parsed
structure, which removes the lifetime question three libraries would each answer
differently. `cantil version` reports the compiled-in backend.

### Two bugs the tests found, one of them shipped

`libcantil/tests/test_x509.c` runs 20 checks per backend against golden values
generated by the **openssl CLI** — a third implementation neither backend can
bias. Cross-comparing the two backends would not have caught either of these,
because in both cases the code looked entirely reasonable in isolation.

**1. Tier 3 and Tier 4 never worked.** The certificate profile in `trust.c` set
`allowed_pks = MBEDTLS_X509_ID_FLAG(MBEDTLS_PK_ECDSA)`. mbedTLS uses that one
field for two different questions: at `x509_crt.c:2586` it checks the
*signature* algorithm (`PK_ECDSA`, 4), and at `x509_crt.c:3094` it checks the
end-entity's *public key* type — which for any EC key is `PK_ECKEY` (2), never
`PK_ECDSA`. So every intermediate passed and every leaf failed with
`BADCERT_BAD_PK`. **CA-allowlist trust could not succeed for any certificate,
ever**, from the day `trust.c` was written until 2026-07-23. It went unnoticed
because Tier 2 (fingerprint pinning) does not touch the profile, and Tier 2 is
what both dev units actually use. Fixed by listing `ECKEY` alongside `ECDSA`;
this weakens nothing, since `allowed_curves` still pins P-256 and `allowed_mds`
still pins SHA-256.

**2. The wolfSSL backend trusted attacker-supplied intermediates.** Caught
before it ever ran outside a test, but worth recording because the API invites
it. wolfSSL has no notion of untrusted chain material: mbedTLS takes
intermediates as a separate argument and verifies them, whereas wolfSSL's only
way to make a certificate available to the walker is
`wolfSSL_CertManagerLoadCABuffer`, **which makes it a trust anchor**. The
obvious translation — load the anchor, load the intermediates, verify the leaf —
means a peer can send a self-signed certificate as its "intermediate" and have
its leaf accepted against *any* anchor. `test_chain_wrong_anchor` returned OK
against an unrelated root. Replaced with incremental path building: an
intermediate is promoted to anchor only after it verifies against what is
already trusted, which reproduces mbedTLS's semantics.

### The subject-DN trap

`cantil_x509_subject_der` returns the full DER **TLV**, tag and length included.
This is specified rather than incidental: mbedTLS's `subject_raw` spans the
whole TLV, while wolfSSL's `subjectRaw` points at the SEQUENCE *contents*, after
`GetASN_Sequence` consumed the header. A backend returning the contents alone
would be self-consistent and would silently break every Tier 2 subject-DN pin
made by a client built the other way. The wolfSSL backend reconstructs the
header and asserts it lands on a SEQUENCE tag, so a future wolfSSL change fails
loudly instead of pinning the wrong bytes.

### What "refused" guarantees

Callers must treat *anything other than* `CANTIL_X509_OK` as the refusal, never
a specific code. An out-of-profile certificate surfaces as `ERR_CHAIN` under
mbedTLS (parsed, then rejected on policy) but as `ERR_PARSE` under a wolfSSL
built without RSA — which `setup_wolfssl_host.sh` does, since Cantil has no use
for RSA. Pinning one code would assert a property of the build configuration
rather than of the seam.

### Host wolfSSL

Fedora does not package wolfSSL (`rpm-ostree search wolfssl` finds nothing), so
`scripts/setup_wolfssl_host.sh` builds one, defaulting to the copy `west` already
fetched — same revision as the firmware, which is the point — and warning if the
installed version does not match the `west.yml` pin. Two things it must do that
are not obvious: build with CMake (the checkout has no `./configure`, and
regenerating one needs `libtool`, which this host lacks), and pass
`-DCMAKE_INSTALL_LIBDIR=lib`, because wolfSSL installs the archive to `lib64` on
a 64-bit host while the `wolfssl.pc` it generates hardcodes `libdir=.../lib` —
pkg-config then reports a `-L` containing no library and the link dies.

### OpenSSL is deliberately not written

> **Done 2026-07-24 — see "Step 7" below.** `openssl-devel` was installed, the
> backend was written and passes all 20 conformance checks, and it is now the
> *default*. The paragraph below records why it was held back at step 5.

The slot is reserved and the CMake branch fails with instructions rather than a
missing-file error. This host has no `openssl-devel`, so the backend could not be
compiled, let alone run against the tests — and the two bugs above are exactly
what shipping unverified chain-verification code produces. `rpm-ostree install
openssl-devel` is the prerequisite; the backend is then one file and one CMake
branch.

### Cost

Nothing in the firmware changed, so no image moved. The client gained one
compiled file and 20 tests per backend, both green.

## Step 6 — mbedTLS removed, landed 2026-07-24

The phase is complete: **mbedTLS no longer exists in the firmware.** wolfCrypt
backs all four crypto seams (`crypto.h`, `noise_crypto.h`, `ca/certgen.h`,
`ca/certparse.h`), the default build links only wolfSSL, and `nm` on the ELF
finds zero `mbedtls_*` symbols. FREE was 203,752 B; the wolfCrypt-only image is
246,084 B (uf2) / 250,032 B (mcuboot). The footprint went *up*, as step 1
predicted — the "smaller" premise never survived measurement — but the reason
the phase exists (ML-KEM / ML-DSA in the same library, plus a single GPLv3
crypto stack) is now in place.

It ran in two parts.

### Step 6a — `ca.c` off the mbedTLS *readers* (the `certparse.h` seam)

`ca.c` still held ~71 mbedTLS reader references after step 5 — chain
verification, `pk_write_pubkey`, cert/CSR parsing, `asn1_get_tag` chain
splitting. These moved behind `ca/certparse.h`, the reader mirror of
`certgen.h`: bytes in, typed struct out, no library type in the header.
`certparse_wolfssl.c` is the one implementation. Its chain walker is
hand-written on `wc_CheckCertSigPubKey`, because a WOLFCRYPT_ONLY build has no
library chain verifier — wolfSSL's lives in the TLS layer the flag excludes.
That is the same trap the host seam fell into (a self-signed "intermediate"
accepted against any anchor); the firmware walker promotes an intermediate to
anchor only after it verifies against something already trusted, and the new
`certparse` ztest suite's negative cases pin that.

### Step 6b — the independent oracle, then the deletion

Dropping mbedTLS removes the thing that had been keeping wolfCrypt honest: the
`*_wolfssl` suites parsed wolfCrypt's output with mbedTLS, so a shared
misunderstanding of DER between wolfCrypt's writer and reader would have gone
unseen. Two step-4 bugs (a version-2 CSR, an empty SPKI) were caught *only*
because mbedTLS was the parser.

That oracle moved to **OpenSSL** before mbedTLS left. `scripts/openssl_gate.sh`
runs the `openssl` CLI over every DER artifact a generation suite dumps
(`test_artifacts.h`), dispatched by filename suffix: certificates and CSRs must
parse and self-verify, CRLs must parse and — when their issuer is supplied —
verify, and leaf/anchor pairs must chain. `scripts/test.sh` runs it after each
suite. It needs only the binary, no `-devel` headers. Three refinements were
load-bearing:

- **`-check_ss_sig` is mandatory.** OpenSSL matches a trusted cert by identity
  and takes its signature on faith, so a suite supplying one self-signed cert
  as both leaf and anchor (the session slot, the CA root) got an OK back
  without a signature ever being verified — the exact hole the gate exists to
  close. Confirmed by mutation: a corrupted-signature cert passed the gate as
  first committed, and `-check_ss_sig` turns it into "error 7".
- The CRL is the encoder with the least library cover in the tree
  (`der_write.c` writes it backwards by hand; the signature is assembled from
  `crypto_sign` + `cantil_der_mpint`), so its `.crl.der` is paired with its
  issuer's `.ca.der` and the gate runs `openssl crl -verify`.
- Validity dates are **not** checked (`-no_check_time`): the device has no RTC
  and issues synthetic windows on purpose.

With the oracle in place, the six `*_wolfssl` sibling suites collapsed onto
their originals (now wolfCrypt-backed), and the seven backend-agnostic suites
switched their linked sources. Test-side certificate/CSR generation, which had
used mbedTLS's `x509write` API, moved to `firmware/tests/common/test_pki.h` —
thin wrappers over the firmware's own `certgen` + `crypto_keygen`, so a suite
links no library the firmware does not. CRL *content* checks (serials, dates,
`crlNumber`, the validity window) are read by a small self-contained forward-DER
walker in the `crl_der` suite, since `certparse` reads certs and CSRs but not
CRLs and there is no WOLFCRYPT_ONLY CRL enumerator to call.

One firmware call site outside the CA also had to move: `clients/pairing.c`
derived the passkey PSK with `mbedtls_hkdf` directly. It now uses a new
`crypto_hkdf_sha256()` on the `crypto.h` seam (both the storage-key derivation
and the PSK sit on it), pinned by `crypto_kat` against RFC 5869 TC1 and a fixed
pairing-PSK vector — a silent divergence there would not error, it would just
fail every cross-backend handshake.

The **ACCELERATED** backend was deleted in the same phase (2026-07-23): it had
been unselectable since the upstream-Zephyr move, never paired on real
hardware, its Nordic blobs are un-distributable under GPLv3 §7, and its cert
writing went through `certgen_mbedtls.c` — so it was a dependency on the very
library being removed, not the route back to acceleration. That route is
wolfCrypt driving the CC310 directly.

### The open question, settled

Step 5 left open whether `mbedtls` should stay in `west.yml` as a **test-only**
parser. Decided: **no.** OpenSSL is the independent oracle now, so keeping
mbedTLS would buy a second parser at the cost of a second crypto library in the
manifest — exactly what the phase set out to remove. `mbedtls` is gone from the
allowlist; `west update` no longer fetches it.

## Step 7 — mbedTLS removed from libcantil, OpenSSL is the client default (2026-07-24)

Step 6 ended with the *firmware* wolfCrypt-only but the *client* still defaulting
to `x509_mbedtls.c` — mbedTLS survived in exactly one place. This step retires it
there too, so mbedTLS is gone from the whole repo.

The seam did its job: mbedTLS in the client was confined to `x509_mbedtls.c` plus
its CMake wiring — every other file names no certificate library — so this was a
delete, a default change, and one new backend, not a hunt.

**OpenSSL over wolfSSL-for-the-client.** The client and the device never share a
build and the wire is backend-independent DER, so the client is free to differ
from the firmware. OpenSSL wins the default on two grounds: `libcrypto` is the
certificate library a Linux host is most likely to already have (so it keeps the
"builds with no extra setup" property mbedTLS had, on more hosts), and it is the
*same third implementation* the test fixtures (`tests/gen_fixtures.sh`) and the
firmware's OpenSSL gate are already generated from — so the backend matching the
golden values is very nearly by construction. `x509_wolfssl.c` stays as the
`-DCANTIL_HOST_CRYPTO=wolfssl` alternate: it matches the firmware's library and
is already tested, so it is cheap insurance and the fallback for a host that
cannot get `openssl-devel`.

**The trust model is mbedTLS's, for free.** Unlike wolfSSL, OpenSSL *has* an
untrusted-chain-material concept: intermediates go into a `STACK_OF(X509)` passed
to `X509_STORE_CTX_init()`, and only the caller's anchor is added to the store
via `X509_STORE_add_cert()`. Nothing in the untrusted stack can become a trust
anchor, so the self-signed-"intermediate" attack the wolfSSL backend had to
defend against with hand-built incremental path building simply does not arise
here — `test_chain_wrong_anchor` passes because OpenSSL's model is the same as
mbedTLS's separate-argument one.

Three things `x509_openssl.c` has to do that are worth recording:

1. **Subject DN is the full TLV via `i2d_X509_NAME()`.** It re-encodes the
   subject Name tag-and-length included, which is exactly the seam's definition —
   no header reconstruction (contrast the wolfSSL backend's `subjectRaw - hdr`
   arithmetic). Because the fixtures were produced by OpenSSL, the re-encoding
   reproduces the original bytes and matches `golden_subject` exactly.
2. **The profile is enforced by hand.** OpenSSL has no `mbedtls_x509_crt_profile`
   equivalent in its verify API, so `leaf_profile_ok()` checks
   `X509_get_signature_nid() == NID_ecdsa_with_SHA256` and that the leaf key is
   EC on `prime256v1`, refusing anything else as `ERR_CHAIN` before verifying —
   the OpenSSL analogue of wolfSSL's OID check. This is what makes
   `test_chain_rejects_non_p256` (an RSA chain) refuse.
3. **Dates are skipped with `X509_V_FLAG_NO_CHECK_TIME`.** The device has no RTC
   and issues a synthetic window; this mirrors the mbedTLS `chain_vrfy_cb` and the
   wolfSSL date-tolerant callback, and makes `test_chain_ignores_expiry` pass.

**Gate.** `tests/test_x509.c` is unchanged — the same 20 golden checks now run
against `test_x509_openssl` and `test_x509_wolfssl`, both green (20/20). One
honesty note went into the test header: the OpenSSL backend now shares a library
*family* with the fixture oracle (the `openssl` CLI), so wolfSSL is what keeps the
golden values honest across independent implementations. The `openssl` CLI
(`asn1parse`) and `libcrypto` (`i2d_X509_NAME`) are still distinct code paths, but
the strong cross-check is the wolfSSL run.

**Prerequisite:** just `openssl-devel` (headers + `libcrypto.so`) — one
`rpm-ostree install` + reboot on an ostree host. There is **no** static-OpenSSL
requirement: Fedora ships no `libcrypto.a`, `openssl-static` is not a package,
and upstream discourages fully-static OpenSSL, so `CANTIL_CLI_STATIC` links
libcrypto *dynamically*. That is correct rather than a compromise —
`libcrypto.so` is a base-system library present on effectively every Linux
target, whereas libsodium (which the static option *does* bundle) is not. The
CMake static branch links the backend statically only when it lists a `.a`
(wolfSSL does; openssl lists none).

**Cost:** nothing in the firmware changed, so no image moved. The client dropped
one backend file and its `pkg_check_modules(mbedtls …)`; the CMake choice is now
`openssl|wolfssl`.

## The licensing problem — resolve before starting

**(Historical — Cantil was Apache 2.0 when this section was written; it is
now GPL-3.0-or-later. Kept because the compatibility reasoning is what led to
the relicense.)**

**Cantil is Apache 2.0.** It was GPLv3 with §7 exceptions briefly and was
deliberately relicensed:

```text
9e84dba chore: relicense to Apache 2.0, move secure_pairing.md to docs/
e46e7ac license: adopt GPLv3 with client-interface and proprietary-crypto exceptions
```

wolfSSL's open-source license is **GPLv3 as of version 5.8.2** (changed from
GPLv2 — see [wolfssl.com/license](https://www.wolfssl.com/license/) and
[issue #9177](https://github.com/wolfssl/wolfssl/issues/9177)); the
alternative is a paid commercial license at roughly **$7,500 per end
product**. That creates a conflict the current mbedTLS setup does not have:

- **mbedTLS is Apache 2.0** — an exact match for Cantil's license. The
  status quo costs nothing.
- **Incorporating GPL code into an Apache 2.0 project means the distributed
  combined work must be licensed under GPL terms.** Shipping wolfSSL-based
  firmware would effectively re-impose copyleft on the binary, undoing the
  relicense in `9e84dba`.
- Apache 2.0 is one-way compatible with **GPLv3** (Apache code may be
  incorporated into a GPLv3 work), but is **incompatible with GPLv2-only**
  because of the patent and indemnity terms. Which of those applies depends
  on whether wolfSSL is "v2 only" or "v2 or later".

### It also conflicts with the standing dependency policy

The Apache 2.0 relicense was driven by a specific goal: keeping Cantil
consumable by **AGPLv3** downstream projects. Apache 2.0 is one-way
compatible with AGPLv3, which achieves that without §7-exception complexity.

The policy that follows from it is that default-build-path dependencies must
be **both Apache 2.0-compatible and AGPLv3-compatible**, and that pure-GPL
dependencies should be avoided unless gated behind an optional Kconfig,
precisely because they block AGPLv3 downstreams from combining cleanly.

A GPLv2 wolfSSL as the **default** crypto backend fails that policy directly
— it would reimpose the consumability problem the relicense was performed to
solve. Under existing policy wolfSSL could only be a Kconfig-gated
alternative backend, not the default, unless the commercial license is
purchased or the policy is deliberately revised.

That reframes the phase: not "replace mbedTLS with wolfSSL" but "add wolfSSL
as an option alongside mbedTLS" — which is a materially smaller and less
valuable change, and worth confirming is still wanted.

### Must verify before committing to this phase

1. Confirm the license of the specific wolfSSL version to be used. 5.8.2 and
   later are GPLv3; earlier releases were GPLv2-or-later. Pinning an old
   GPLv2 release to dodge this is a dead end — it forgoes exactly the
   post-quantum work that motivates the migration.
2. Decide the outcome deliberately, because all options have a cost:
   - **Relicense the firmware to GPLv3** — the only copyleft version that
     works. GPLv2 does **not**: it cannot consume wolfSSL 5.8.2+, and it
     cannot absorb Apache-2.0 Zephyr. Reverses `9e84dba`, and ends
     permissive downstream use.
   - **Buy wolfSSL's commercial license** — keeps Apache 2.0 *and* is the
     only route to a FIPS certificate. If FIPS is a real requirement this
     strictly dominates relicensing, which yields neither Apache 2.0 nor a
     certificate.
   - **Stay on mbedTLS** — zero licensing cost, already integrated.

This is not legal advice. The point is that licensing is now the *deciding*
factor in this phase rather than a footnote.

## FIPS is not a reason to switch libraries

> **Superseded by the 2026-07-22 decision above** — certification is out of
> scope at this project's scale. Retained because the cipher-suite analysis
> still stands on its own, and because the alignment work remains available
> if wanted.
>
> Caveat worth weighing before doing it: X25519 and ChaCha20-Poly1305 are
> the better primitives on technical merit. Swapping to P-256/AES-GCM to
> satisfy a standard nobody is auditing against is a downgrade for its own
> sake. Do it only if FIPS alignment is wanted as an exercise.

Per [fips_discussion_2026-05-18.md](../fips_discussion_2026-05-18.md), the
blocker for FIPS alignment is the **cipher suite, not the library**: X25519
is not on the NIST SP 800-56A approved KAS list and ChaCha20-Poly1305 is not
an approved AEAD. mbedTLS already "provides every FIPS-approved primitive
needed"; the identified fix is moving to `Noise_XX_P256_AESGCM_SHA256`.

A FIPS-validated library still running X25519 and ChaCha20-Poly1305 produces
a non-compliant device. Do the cipher-suite work first — it is free, needs
no relicense, and is a prerequisite either way.

Note also that **wolfCrypt FIPS Ready** (free, GPL) is *not* validated. Only
the commercial wolfCrypt FIPS 140-3 module carries certificates
`#4718` / `#5041`, and validation is bound to a tested operational
environment, so an nRF52840 under a custom Zephyr build likely needs vendor
affirmation or re-validation regardless.

## Why abstraction serves the FIPS goal (2026-07-22)

The goal is not for Cantil to claim compliance. It is that **a downstream
party pursuing compliance finds the crypto boundary already in the right
place.** That is a legitimate architectural aim and it changes what "good"
looks like here.

Two things to be precise about:

- A FIPS certificate attaches to a **specific validated module build**, not
  to the wolfCrypt API. Open-source wolfCrypt is *not* the validated module,
  so shipping it confers nothing by itself.
- But open-source wolfCrypt and the commercial wolfCrypt FIPS module
  **share the same API**. Code written against `wc_*` swaps from one to the
  other by changing the library, not the application. That is the real
  benefit, and it is exactly what a clean backend boundary buys.

**Design guideline that follows:** keep cryptographic operations *inside*
`wc_*` calls rather than composing primitives in Cantil's own code. Anything
Cantil computes itself sits outside the module boundary and would have to be
re-argued during a validation effort. Concretely, implement
`noise_crypto_hkdf2()` via `wc_HKDF_Extract`/`wc_HKDF_Expand` rather than
hand-rolled HMAC chaining, even though both produce identical output.

## Plan: wolfSSL as a third backend

Not a replacement. `choice CANTIL_CRYPTO_BACKEND` already has `FREE`
(mbedTLS) and `ACCELERATED` (Oberon/CC3XX); wolfSSL becomes a third arm.
This keeps mbedTLS as the Apache-2.0 path and makes wolfSSL non-load-bearing,
which is what preserves dual-licensing optionality.

**This work depends on no other phase.** It does not need the upstream
Zephyr migration, Bazel, or hardware — the conformance suite runs on
`native_sim`.

Files, mirroring the existing backend pattern:

- `firmware/src/crypto/crypto_wolfssl.c` — implements `crypto.h` (8 functions)
- `firmware/src/session/noise_crypto_wolfssl.c` — implements
  `noise_crypto.h` (6 functions)
- `firmware/Kconfig` — `CANTIL_CRYPTO_BACKEND_WOLFSSL`
- `firmware/CMakeLists.txt` — `target_sources_ifdef` arm
- `firmware/west.yml` — add the wolfSSL module

Primitive mapping (all present in open-source wolfCrypt):

| Need | wolfCrypt | Build flag |
| --- | --- | --- |
| X25519 | `wc_curve25519_*` | `HAVE_CURVE25519` |
| SHA-256 | `wc_Sha256*` | — |
| ChaCha20-Poly1305 | `wc_ChaCha20Poly1305_*` | `HAVE_CHACHA`, `HAVE_POLY1305` |
| HKDF | `wc_HKDF_Extract` / `_Expand` | `HAVE_HKDF` |
| P-256 ECDSA | `wc_ecc_*` | `HAVE_ECC` |
| AES-256-GCM | `wc_AesGcm*` | `HAVE_AESGCM` |
| Cert / CSR generation | `wc_MakeCert`, `wc_SignCert` | `WOLFSSL_CERT_GEN`, `WOLFSSL_CERT_REQ` |

TRNG needs no backend work — per the `CANTIL_CRYPTO_BACKEND` help text it is
sourced from the Zephyr entropy device regardless of the choice.

**Acceptance criterion:** the existing `firmware/tests/noise_crypto/` suite
passes unmodified against the wolfSSL backend. Its 16 ZTESTs run against
fixed vectors from `gen_vectors.py`, so passing them proves the backend is
bit-for-bit interchangeable with mbedTLS rather than merely self-consistent.
Then `ca_bootstrap`, `sign_csr`, and `session_*` for the `crypto.h` side.

## Post-quantum — the one genuine argument

ML-KEM and ML-DSA are in the open-source distribution, and this is a real
capability mbedTLS currently lacks. Weigh it against:

- It requires GPLv3, not GPLv2.
- Sizes are awkward here: ML-DSA-65 signatures are ~3.3 KB and public keys
  ~2 KB, against a transport that chunks at 3968 bytes. A single PQ
  certificate may not fit one frame — the wire format and `x509_data_t`
  would need rework.
- PQ X.509 standardization is still in flux; a CA issuing PQ certificates
  today issues against moving specs.
- `pqm4` offers Cortex-M4-optimised PQ implementations without a library
  swap, and mbedTLS/PSA is adding PQC.

Recommendation: revisit when PQ X.509 stabilises rather than relicensing for
it now.

## What still argues for wolfSSL

The original motivations survive the licensing problem and should be weighed
against it:

- ~~Smaller footprint~~ and finer-grained feature gating than mbedTLS.
  **Measured 2026-07-23 and it is not smaller** — see "What step 1 cost"
  below. The gating is real and very fine-grained; the footprint is not the
  argument it was assumed to be.
- `wc_scrypt` — a memory-hard KDF for
  [storage-key-derivation.md](storage-key-derivation.md). mbedTLS has only
  PBKDF2 (`mbedtls_pkcs5_pbkdf2_hmac`), which is weaker for low-entropy
  inputs. This is a real technical gain, though PBKDF2 with a high iteration
  count is an acceptable interim.
- `wolfBoot` as an MCUboot alternative, relevant to the existing
  firmware-signing work.
- The CC310 spike path — see [crypto-blobs.md](../crypto-blobs.md).

## Sequencing note

The storage-key fix does **not** depend on this phase. mbedTLS has PBKDF2
today, and that weakness should not wait behind a licensing decision plus
two build-system migrations. See
[storage-key-derivation.md](storage-key-derivation.md).
