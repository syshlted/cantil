# Task T-15 — Client Bond Management

**Status:** Landed 2026-06-04, 9/9 ztests on native_sim (session 063)
**Opcodes:** `CMD_LIST_CLIENTS` (0x70), `CMD_UNPAIR_CLIENT` (0x71), `CMD_SET_CLIENT_NAME` (0x72)
**Touches:** [firmware/src/clients/client_bond.c](../../firmware/src/clients/client_bond.c), [firmware/src/clients/client_bond.h](../../firmware/src/clients/client_bond.h), [firmware/src/protocol/protocol.c](../../firmware/src/protocol/protocol.c), [firmware/src/storage/storage.c](../../firmware/src/storage/storage.c), [libcantil/src/clients.c](../../libcantil/src/clients.c), [libcantil/include/cantil.h](../../libcantil/include/cantil.h), [libcantil/cli/main.c](../../libcantil/cli/main.c)

The first task of **Phase D** ([docs/transport-and-pairing.md](../transport-and-pairing.md)).
Establishes the `/clients/` LittleFS layout, the `client_bond_*` module that all pairing methods
(T-16 through T-20) build on, and three management opcodes so operators can inspect and manage
bonded clients.

---

## What this task adds

Three opcodes reserved in the `0x70–0x7F` range:

- **`LIST_CLIENTS` (0x70)** — returns a CBOR array of bond metadata; one entry per `/clients/<id>/`.
- **`UNPAIR_CLIENT` (0x71)** — removes a named bond (identified by its 32-byte Curve25519 static
  pubkey). Tap-confirmed.
- **`SET_CLIENT_NAME` (0x72)** — sets a UTF-8 friendly name on a bond (for `LIST_CLIENTS` display).

All three require `UNLOCKED` state and flow through the normal recovery-mode gate.

---

## Storage layout

```text
/clients/
    <hex-pubkey-prefix-8>/      (4-byte = 8 hex chars; the first 4 bytes of SHA-256(pubkey))
        pubkey.bin              ; 32 B raw Curve25519 static pubkey
        meta.bin                ; client_meta_t: kind, created_at, last_seen, friendly_name
        psk.bin                 ; optional — Methods 3/5 only: 32 B PSK encrypted under FICR key
        cert.der                ; optional — Method 4/5 only: cached client leaf cert
```

The directory name is the **4-byte ID**, stored as 8 lowercase hex characters, derived as the
first 4 bytes of SHA-256(pubkey). This is a short prefix, not a cryptographic identity — `client_bond_exists` re-reads and verifies `pubkey.bin` on every lookup to handle the (highly unlikely) 4-byte collision between two distinct 32-byte pubkeys.

`client_meta_t` is a packed struct:

```c
typedef struct {
    client_kind_t kind;            /* CLIENT_KIND_HOST or CLIENT_KIND_PEER_DEVICE */
    uint32_t      created_at;      /* Unix timestamp, 0 if no RTC */
    uint32_t      last_seen;       /* Unix timestamp, 0 if no RTC */
    char          name[CLIENT_META_NAME_MAX]; /* null-terminated UTF-8, default = hex-prefix-8 */
} client_meta_t;
```

Bond caps are enforced at pairing time (not at `LIST_CLIENTS` / management time):
- `CONFIG_CANTIL_MAX_CLIENT_BONDS` (kind=HOST, default 4)
- `CONFIG_CANTIL_MAX_PEER_BONDS` (kind=PEER_DEVICE, default 4)
- Budgets are independent — peer bonds do not consume host-client allowance.

---

## Implementation

### `client_bond_*` module ([client_bond.c](../../firmware/src/clients/client_bond.c))

The module wraps LittleFS storage helpers (in [storage.c](../../firmware/src/storage/storage.c)) and exposes a clean API
independent of CBOR or sessions. All callers (pairing methods, management opcodes) go through this module.

Key functions:

| Function | Behaviour |
|---|---|
| `client_bond_id(pub, id)` | Derive the 4-byte ID from `SHA-256(pub)[0..3]` |
| `client_bond_exists(pub)` | Probe dir + verify `pubkey.bin`; returns 1/0/-errno |
| `client_bond_add(pub, kind, now)` | Create dir + write `pubkey.bin` + default `meta.bin`; `-EEXIST` if already bonded, `-ENOSPC` at cap |
| `client_bond_remove(pub)` | Recursively delete `/clients/<id>/`; `-ENOENT` if not found |
| `client_bond_set_name(pub, name)` | Update `meta.bin` `name` field (max `CLIENT_META_NAME_MAX - 1` bytes, UTF-8, must resolve to existing bond) |
| `client_bond_count(hosts, peers)` | Count all bonds by `kind` field in `meta.bin` |
| `client_bond_list_cbor(out, len)` | Encode all bonds as CBOR array |

`client_bond_list_cbor` iterates `storage_client_bond_foreach`, reads `meta.bin` for each ID,
and builds a CBOR array of maps:

```cbor
[
  {
    1: h'<32B pubkey>',          ; key (bstr)
    2: <uint kind>,              ; 1=HOST, 2=PEER_DEVICE
    3: <uint created_at>,        ; Unix seconds, 0 if no RTC
    4: <uint last_seen>,         ; Unix seconds, 0 if no RTC
    5: "<utf-8 name>",           ; tstr
  },
  ...
]
```

### Dispatcher cases ([protocol.c](../../firmware/src/protocol/protocol.c))

- **`CMD_LIST_CLIENTS`** — no request body; response is the CBOR array from `client_bond_list_cbor`.
- **`CMD_UNPAIR_CLIENT`** — request body must be exactly 32 bytes (the pubkey). Gated by
  `await_protect_confirm()` (tap-confirm), then calls `client_bond_remove`. `-ENOENT` → `ERR_NOT_FOUND`.
- **`CMD_SET_CLIENT_NAME`** — request body: 32 B pubkey || 1–`(CLIENT_META_NAME_MAX-1)` B name.
  No confirm required (naming is non-destructive). Calls `client_bond_set_name`. `-ENOENT` →
  `ERR_NOT_FOUND`; `-EINVAL` → `ERR_INVALID_ARGS` (name too long or bond not found).

---

## libcantil API ([libcantil/include/cantil.h](../../libcantil/include/cantil.h))

```c
typedef struct {
    uint8_t  pubkey[32];
    uint32_t kind;          /* 1=host, 2=peer-device */
    uint32_t created_at;
    uint32_t last_seen;
    char     name[64];
} cantil_client_info_t;

cantil_err_t cantil_list_clients(cantil_session_t *s,
                                 int (*cb)(const cantil_client_info_t *, void *user),
                                 void *user);

cantil_err_t cantil_unpair_client(cantil_session_t *s, const uint8_t pubkey[32]);

cantil_err_t cantil_set_client_name(cantil_session_t *s,
                                    const uint8_t pubkey[32], const char *name);
```

`cantil_list_clients` decodes the CBOR array from the device and invokes `cb` once per entry; the
callback may return non-zero to stop early (that value propagates as the return from
`cantil_list_clients`).

CLI subcommands: `cantil clients <port>`, `cantil unpair <hex-pubkey> <port>`,
`cantil name <hex-pubkey> <name> <port>`.

---

## Failure modes & wire mapping

| Condition | `client_bond_*` | Wire err |
| --- | --- | --- |
| `LIST_CLIENTS` storage error | any non-zero rc | `ERR_STORAGE` |
| `UNPAIR_CLIENT` tap denied / timeout | (not called) | `ERR_BUSY` |
| `UNPAIR_CLIENT` pubkey not found | `-ENOENT` | `ERR_NOT_FOUND` |
| `SET_CLIENT_NAME` pubkey not found | `-ENOENT` | `ERR_NOT_FOUND` |
| `SET_CLIENT_NAME` name out of range | `-EINVAL` | `ERR_INVALID_ARGS` |

---

## Code map

| File | Role |
| --- | --- |
| [firmware/src/clients/client_bond.c](../../firmware/src/clients/client_bond.c) | Core bond module (exists/add/remove/name/count/list) |
| [firmware/src/clients/client_bond.h](../../firmware/src/clients/client_bond.h) | Public API + `client_meta_t` / `client_kind_t` types |
| [firmware/src/protocol/protocol.c](../../firmware/src/protocol/protocol.c) | `CMD_LIST_CLIENTS` / `CMD_UNPAIR_CLIENT` / `CMD_SET_CLIENT_NAME` cases |
| [firmware/src/storage/storage.c](../../firmware/src/storage/storage.c) | `storage_client_bond_*` primitives (dir/file CRUD, foreach) |
| [libcantil/src/clients.c](../../libcantil/src/clients.c) | `cantil_list_clients`, `cantil_unpair_client`, `cantil_set_client_name` |
| [libcantil/include/cantil.h](../../libcantil/include/cantil.h) | `cantil_client_info_t` + client management API declarations |
| [libcantil/cli/main.c](../../libcantil/cli/main.c) | `clients` / `unpair` / `name` CLI subcommands |

---

## Tests (firmware/tests/pairing — 9/9 PASS on native_sim)

Tests 1–9 (consolidated across the pairing test suite):

- `test_01_list_empty` — `LIST_CLIENTS` on a fresh store returns an empty CBOR array.
- `test_02_bond_and_list` — add a bond via `client_bond_add`, then `LIST_CLIENTS`; entry present with
  correct pubkey + default name.
- `test_03_set_name_and_list` — `SET_CLIENT_NAME`, then `LIST_CLIENTS`; updated name reflected.
- `test_04_set_name_not_found` — name an unbonded pubkey → `ERR_NOT_FOUND`.
- `test_05_unpair_removes_bond` — bond + `UNPAIR_CLIENT` + `LIST_CLIENTS`; entry gone.
- `test_06_unpair_not_found` — unpair unknown pubkey → `ERR_NOT_FOUND`.
- `test_07_cap_enforced` — fill to `CONFIG_CANTIL_MAX_CLIENT_BONDS` hosts; next add → `-ENOSPC` /
  `ERR_INVALID_ARGS` from the pairing gate.
- `test_08_peer_budget_independent` — fill host cap; add a PEER_DEVICE bond → succeeds (different
  budget).
- `test_09_id_collision_resolved` — two pubkeys that share the same 4-byte prefix are both stored
  correctly (the second write goes to the same dir slot only after the collision resolver confirms
  the stored pubkey does not match).

Note: the collision test (09) exercises the `id_matches_pub` verifier inside `client_bond_exists`.
A genuine 4-byte SHA-256 prefix collision is astronomically unlikely in practice, but the code path
must be exercised in tests since a silently-broken resolver would allow one client to impersonate
another.
