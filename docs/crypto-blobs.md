# Optional hardware crypto blobs (CC310)

> **Cantil ships no binary blobs.** Nothing in this repository requires one.
> The default build is fully open source and software-only.
>
> CC310 hardware acceleration is **opt-in**, off by default, and currently a
> **spike** — not a supported configuration. See
> [storage-key-derivation.md](roadmap/storage-key-derivation.md) for why it
> is not on the critical path.

## What the blob is and why it cannot be avoided

The nRF52840 embeds an Arm TrustZone CryptoCell 310. Enabling it requires
Nordic's prebuilt `libnrf_cc310_platform_*.a` / `libnrf_cc310_mbedcrypto_*.a`.

There is no open-source alternative and there cannot be one: Nordic does not
publish the CC310 register interface. The nRF52840 Product Specification
documents only the `CRYPTOCELL.ENABLE` power gate; the core itself is
undocumented. Every consumer — mbedTLS via nrf_security, wolfSSL via its
`WOLFSSL_CRYPTOCELL` port — is a wrapper calling into the same binary.

wolfSSL supplies glue, not a driver. Its port calls `CRYS_*` functions
implemented inside Nordic's library.

## Licensing — read before enabling

The blobs are `LicenseRef-Nordic-5-Clause`. **This is not a free software
license.** Two clauses matter:

> **Clause 4.** This software, with or without modification, must only be
> used with a Nordic Semiconductor ASA integrated circuit.
>
> **Clause 5.** Any software provided in binary form under this license must
> not be reverse engineered, decompiled, modified and/or disassembled.

Cantil itself is [GPL-3.0-or-later](../LICENSE). Clauses 4 and 5 are
further restrictions of exactly the kind GPLv3 §7 forbids adding to a
covered work, so a binary linking both the blob and Cantil **cannot be
distributed** — the GPL terms and the Nordic terms cannot both be satisfied.

This is a stronger conclusion than the one that applied while Cantil was
Apache 2.0, where linking created no conflict upstream and the restrictions
merely flowed downstream to recipients. Under GPLv3 there is no lawful
combined distribution at all.

Building a CC310 image for **your own use** remains fine — the GPL is
triggered by distribution, not by use. Distributing one is not, and neither
is offering it as a release artifact.

This is one of the reasons the CC310 path stays an opt-in spike rather than
a shipped configuration, and why Phase 2 targets wolfCrypt — it drives the
CC310 directly, under a license compatible with Cantil's, with no Nordic
blob involved. See [roadmap/wolfssl-migration.md](roadmap/wolfssl-migration.md).

Practical consequences of enabling CC310:

| | Default build | CC310 build |
| --- | --- | --- |
| Fully open source | yes | **no** |
| Runs on non-Nordic silicon | yes | **no** (clause 4) |
| Redistributable without added terms | yes | **no** |
| Recipients may reverse engineer | yes | **no** (clause 5) |
| Portable to Phase 4 targets | yes | **no** |

If you redistribute firmware built with CC310, clause 2 requires reproducing
Nordic's copyright notice and the license text in your documentation.

**If any of this is a problem for your deployment, use the default build.**
The software path is correct, portable, and fast enough — see below.

## Is it worth it?

For Cantil's workload, almost certainly not. The device performs a handful
of operations per human gesture, not bulk throughput. On a 64 MHz Cortex-M4F
the software path costs single-digit milliseconds for X25519 and tens of
milliseconds for a P-256 signature — imperceptible next to the seconds a
user spends tapping.

CC310 is offered because the hardware exists and some deployments have
policy requirements that name hardware crypto. It is not a performance fix
for a problem Cantil has.

## Getting the blob

Use `scripts/fetch_cc310_blob.sh`. It clones Nordic's standalone
[sdk-nrfxlib](https://github.com/nrfconnect/sdk-nrfxlib) into a gitignored
directory, prints the license, and requires explicit acknowledgement.

```sh
scripts/fetch_cc310_blob.sh              # show license, prompt, fetch
scripts/fetch_cc310_blob.sh --print-license   # inspect terms, fetch nothing
```

The fetched tree lands in `third_party/nrfxlib/` and is **gitignored** — it
is never committed. `sdk-nrfxlib` is a standalone repository: fetching it
does **not** require NCS, west, or a Zephyr workspace.

To do it by hand instead:

```sh
git clone --depth 1 https://github.com/nrfconnect/sdk-nrfxlib \
    third_party/nrfxlib
```

The archives are at `third_party/nrfxlib/crypto/nrf_cc310_platform/lib/cortex-m4/`
(`hard-float/` for the nRF52840) and the license at `crypto/nrf_cc310_platform/license.txt`.

## Building with it

Off by default. Enabling it is a deliberate two-step act — the blob must be
present *and* the Kconfig acknowledgement set, mirroring how
`CANTIL_ALPHABET_STDT_PLAIN` guards its own footgun:

```kconfig
CONFIG_CANTIL_CRYPTO_HW_CC310=y
CONFIG_CANTIL_CRYPTO_HW_CC310_I_ACCEPT_NORDIC_LICENSE=y
```

The build fails with a pointer to this document if the second symbol is
missing. It is not a formality — it records that someone read clause 4
before shipping a binary that may not run on non-Nordic hardware.

## Spike status and open questions

This is exploratory. Known unknowns:

- wolfSSL's CryptoCell port was developed against **nRF5 SDK 15.2**, the
  archived pre-Zephyr SDK — not nrfxlib. The `CRYS_*` surface is the same
  family, but version and ABI alignment against nrfxlib's build is
  unverified. This is the single largest risk in the spike.
- Coverage is unconfirmed for the primitives Cantil actually uses: X25519,
  P-256 ECDSA, SHA-256, and the Noise AEAD.
- CC310 has documented errata around concurrent and repeated operations.
  Cantil's prior accelerated-backend attempt failed on stacked bugs in the
  PSA X25519 path; assume nothing until it is measured on hardware.
- Blob revisions are pinned by whatever `sdk-nrfxlib` HEAD provides. If the
  spike proceeds, pin a tag rather than tracking `main`.
