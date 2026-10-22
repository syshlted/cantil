# Task 15 — GET_CA_CHAIN (chain walker)

**Status:** Landed 2026-05-30 (session 047)
**Opcode:** `CMD_GET_CA_CHAIN` (0x03) — repurposed with optional slot arg
**Touches:** [firmware/src/ca/ca.c](../../firmware/src/ca/ca.c), [firmware/src/protocol/protocol.c](../../firmware/src/protocol/protocol.c), [firmware/src/storage/storage.c](../../firmware/src/storage/storage.c), [libcantil/src/ca.c](../../libcantil/src/ca.c)

---

## What this task adds

Real on-device chain assembly. Before this, `ca_get_chain` was a
one-line alias for `ca_get_cert` — fine for a self-signed master CA,
broken for everything else. `PUSH_CA_CERT` and `PUSH_KEY_CERT`
accepted a `chain` payload on the wire and silently dropped it
(`ARG_UNUSED`).

Now:

- A `chain.der` file is persisted per slot at `/keys/<slot>/chain.der`
  whenever the host pushes a non-empty chain.
- `ca_get_chain_slot(slot, …)` walks recursively:
  1. Read `/keys/<slot>/cert.der` and append it to the output.
  2. If `/keys/<slot>/chain.der` exists, append it and stop
     (externally-enrolled path).
  3. Otherwise look up the cert's serial in the issued-cert store
     (`/certs/<hex>/meta.bin`) to find `issuer_slot`. A miss means the
     cert is a self-signed slot cert (those don't get written to
     `/certs/`) — stop.
  4. If `issuer_slot == slot`, treat as self-signed — stop.
  5. Otherwise recurse on `issuer_slot`.
- Recursion is bounded by `CONFIG_CANTIL_MAX_KEY_SLOTS`; cycles return
  `-ELOOP`.

`ca_get_chain` is now a thin wrapper around `ca_get_chain_slot(0, …)`.

---

## Wire

`GET_CA_CHAIN` (0x03) now takes an **optional** 4-byte BE u32 slot
argument. An empty body keeps the slot-0 default (backwards-compatible
with the previous protocol); any non-zero, non-4 body returns
`ERR_INVALID_ARGS`.

Response: concatenated DER certs, leaf first.

---

## Chain freshness invariants

`chain.der` must never outlive the leaf it was uploaded for. Three call
sites clear it:

| Trigger | Why |
| --- | --- |
| `ca_push_key_x509` self-signed regen | replaces cert.der; any pushed chain is now for a stale leaf |
| `ca_sign_key_slot` (subject side) | new cert was signed by another on-device slot; the walker will recurse instead |
| `ca_push_cert` / `ca_push_key_cert` with `chain_len == 0` | host explicitly pushed a cert with no chain |

`storage_slot_delete` already wipes the whole slot dir via `rm_rf`, so
deleting a slot also drops chain.der.

---

## libcantil

```c
cantil_err_t cantil_get_ca_chain(cantil_session_t *s,
                                 uint8_t **out, size_t *out_len);

cantil_err_t cantil_get_key_chain(cantil_session_t *s, uint32_t slot,
                                  uint8_t **out, size_t *out_len);
```

Both return a malloc'd buffer containing the concatenated DER chain;
caller frees with `free()`. `cantil_get_ca_chain` sends an empty body
(slot 0); `cantil_get_key_chain` sends a 4-byte slot id.

---

## Tests

`firmware/tests/sign_csr/` adds four cases:

| # | Case |
| --- | --- |
| 50 | Self-signed root → chain = single cert, byte-equal to `ca_get_cert(0)` |
| 51 | On-device sub-CA (`SIGN_KEY_SLOT(0, 1)`) → chain = 2 certs, leaf parses + verifies under root via `mbedtls_x509_crt_verify` |
| 52 | External chain push (`PUSH_CA_CERT(cert, chain)`) → chain bytes round-trip verbatim |
| 53 | After installing a chain via `PUSH_KEY_CERT`, re-pushing x509 (self-signed regen) collapses the chain back to a single cert |

Test 51 splits the DER stream by walking the outer `SEQUENCE` length
(mbedtls' `_parse` doesn't iterate concatenated DER) and parses each
cert separately with `mbedtls_x509_crt_parse_der`.

---

## Footprint

Production `xiao_ble/nrf52840/sense` build: **286,156 B FLASH /
64,224 B RAM** (~1 KB FLASH growth over the prior baseline).
