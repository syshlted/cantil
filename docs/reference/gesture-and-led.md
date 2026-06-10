# Reference: Gesture State Machine & LED Patterns

> Relocated verbatim from CLAUDE.md (token-cost trim). Authoritative gesture/LED reference.

## Tap Gesture Input

Tap detection is impulse-based (transient onset), driven by either the PDM microphone or a GPIO button:

- **PDM mic (XIAO BLE Sense):** envelope follower + onset detector on the audio stream. The LSM6DS3TR-C IMU is dead on every tested unit and has been abandoned (see [[project-tap-imu-debug]]).
- **GPIO button (any board):** debounce on a rising edge.

Both sources emit a single "tap" event; the input layer does not distinguish single-tap vs double-tap at the hardware level. Higher-level structure comes from counting taps and timing the silence between them.

**Input alphabet: count-then-pause = color.** Each "digit" of a sequence is N taps in quick succession (N = 1..palette_size). A **1.5 s silence** after the last tap closes the digit. A further **1.5 s silence** (3 s total since last tap) closes the entire sequence and triggers evaluation. Build-time palette (default 6 colors):

| Tap count | Color |
| --- | --- |
| 1 | Red |
| 2 | Orange |
| 3 | Yellow |
| 4 | Blue |
| 5 | Cyan |
| 6 | Purple |

`CONFIG_CANTIL_UNLOCK_PALETTE_SIZE` defaults to 6, max 9. Smaller palette → less entropy but easier to enter. With 6 colors and a 4-digit sequence: 6⁴ = 1296 combos; 6 digits: 6⁶ ≈ 46.6k.

Mono LED boards use the same alphabet — the user memorizes counts instead of colors. Same security, less mnemonic aid.

**Per-tap feedback (mandatory):**

- Each individual tap → `TAP_ACK` (dim white flicker, ~30 ms, 10% brightness) confirms the tap registered. The active idle loop is cleared immediately so the LED stays dark between taps; the state's idle pattern is restored when the sequence closes (success → new state's idle; failure → `FAIL`/`SEQ_ERROR` one-shot, then the prior idle resumes).
- 1.5 s silence after last tap → `DIGIT_ACK` (bright white, ~80 ms) confirms one digit captured.
- **Never echo the digit's color back to the user** — would leak the secret to anyone watching the LED.

> Build-time alphabet variants (COUNT_COLOR default, STDT_BINARY, STDT_PLAIN) — see [[project-alphabet-decision]].

## Gesture State Machine

### States

- `BOOT` — POST blip, then immediately `LOCKED`.
- `LOCKED` — BLE advertising active for bonded devices; CA operations blocked.
- `UNLOCKED` — CA operations available; auto-locks after inactivity timeout (default 5 min).
- `PAIRING` — BLE passkey entry in progress; returns to `UNLOCKED` on completion or timeout.
- `CHANGE_SEQ_CONFIRM` — waiting for new unlock sequence entry.
- `CHANGE_SEQ_VERIFY` — waiting for re-entry of new sequence to confirm.
- `AWAITING_CONFIRM` — host issued `PROTECT_SLOT` / `UNPROTECT_SLOT`; waiting for confirm gesture (default 10 s).
- `AWAITING_RESET` — host issued `RESET_DEVICE`; waiting for confirm gesture (default 30 s).
- `AWAITING_PAIR` — an unknown Noise client just completed the handshake; waiting for the user to tap the pairing trigger (Orange Orange) to approve bonding (default 30 s timeout).

### Default Gesture Sequences

All gestures share the count-then-pause color alphabet. State context disambiguates intent: in `LOCKED` the parser is matching against the unlock sequence; in `UNLOCKED` it's matching against triggers; in `AWAITING_*` it's matching against the confirm pattern for that state.

| Gesture | Sequence | Tap count | Valid in |
| --- | --- | --- | --- |
| Factory default unlock | `Red Red Red Red` (1 1 1 1) | 4 | `LOCKED`, first boot only — must rotate after first use |
| User unlock (after rotation) | user-defined, stored in LittleFS | varies | `LOCKED` |
| Explicit lock | `Red` (1) | 1 | `UNLOCKED` |
| BLE pairing trigger | `Orange Orange` (2 2) | 4 | `UNLOCKED` |
| Change-sequence trigger | `Yellow Yellow Yellow` (3 3 3) | 9 | `UNLOCKED` |
| Protect / unprotect confirm | `Purple Purple Purple` (6 6 6) | 18 | `AWAITING_CONFIRM` |
| Reset confirm (default build) | `Red Purple Red Purple Red` (1 6 1 6 1) | 15 | `AWAITING_RESET` |
| Pairing trigger / pair confirm | `Orange Orange` (2 2) | 4 | `UNLOCKED` (trigger BLE pairing) or `AWAITING_PAIR` (confirm new client bond) |
| Reset confirm (`CANTIL_RESET_REQUIRES_UNLOCK=y` build) | user's current unlock sequence | varies | `AWAITING_RESET` |

The confirm and reset-confirm gestures are fixed at compile time (no secrecy value, only deliberate-action value).

**Mid-sequence mistake handling:** lazy / on-close. The parser waits for the 3 s sequence-close timeout, then evaluates. If the closed sequence matches nothing valid for the current state, fire `SEQ_ERROR` (red ↔ yellow alternation over 1.5 s). Eager prefix-fail is deliberately rejected — it would leak which digit was wrong to an attacker observing the LED.

**Reset gating (Kconfig):**

- `CONFIG_CANTIL_RESET_REQUIRES_UNLOCK` defaults to **n**. Forgotten passphrase must not brick the device by default. `RESET_DEVICE` is accepted from `LOCKED`; only gate is the 15-tap awkward confirm pattern.
- `=y` restores the strict spec — `RESET_DEVICE` only from `UNLOCKED`, confirm gesture is the unlock sequence itself; device is intentionally brickable.
- Secure wipe = erase `/keys/`, `/certs/`, `/config*` *and* explicitly overwrite the slot 0 encrypted key blob. FICR-derived storage key is intrinsic, so erasing ciphertext is unrecoverable. Reboot afterward.

**Default-unlock-code flow:** If the unlock attempt matches the factory default `Red Red Red Red`, play `MUST_CHANGE_SEQ` then auto-transition into `CHANGE_SEQ_CONFIRM` (not `UNLOCKED`). User must set a custom sequence before any CA ops are accepted. On mismatch in VERIFY, return to `LOCKED` and re-arm the must-change flow on next unlock.

**Host command serialization:** single-command-in-flight. Client awaits each response before sending the next. Commands arriving during transient states (`PAIRING`, `CHANGE_SEQ_*`, `AWAITING_*`) return `ERR_BUSY` and play `BUSY_REJECT`.

**Distinction between lock/unlock, protect/unprotect, and reset:**

| Term | Scope | Trigger | Purpose |
| --- | --- | --- | --- |
| Lock / Unlock | Whole device | User taps unlock sequence (or explicit lock gesture) | Day-to-day access gate |
| Protect / Unprotect | Single key slot | Host command + confirm tap | Tamper-resistance flag on a slot |
| Reset | Whole device | Host command + reset-confirm tap (per build option) | Factory wipe (irreversible) |

## LED Blink Patterns

All patterns take a semantic colour plus a timing schedule. PWM-driven on RGB boards (XIAO BLE Sense uses 3 GPIOs via `pwm-leds` devicetree binding; ~2–3 KB flash). Mono boards (`cantil-led` only) drop color and rely on timing alone.

**One-shot patterns preempt active loops.** The active loop pauses, the one-shot plays to completion, then the loop resumes at the start of its next period.

**Boot:**

| Pattern | Colour | Timing |
| --- | --- | --- |
| `POST` | blue → green (hard switch) | 250 ms blue, 250 ms green, off; then `LOCKED` |

**Idle states (loops):**

| Pattern | Colour | Timing | Use |
| --- | --- | --- | --- |
| `LOCKED` | red → orange → yellow → orange → red crossfade | 4 s full cycle | `LOCKED` with custom unlock sequence |
| `LOCKED_DEFAULT_SEQ` | same cycle, 2× speed | 2 s full cycle | `LOCKED` with factory default still active |
| `LOCKED_CONNECTED` | `LOCKED` + cyan blip | underlying `LOCKED` loop with one ~80 ms cyan blip every 3 s | Bonded BLE central is connected while `LOCKED` |
| `UNLOCKED` | rainbow HSV sweep | 10 s full hue cycle, smooth PWM, 25% brightness | Idle while `UNLOCKED` |
| `PAIRING` | magenta | 100/100 — loop | Awaiting BLE passkey entry |
| `PAIRING_PROMPT` | cyan | 200/200 — loop | `AWAITING_PAIR` — waiting for user to tap-confirm a new Noise client bond |
| `CONFIRM_PROMPT` | yellow | 400 on / 600 off — loop | `AWAITING_CONFIRM` |
| `RESET_PROMPT` | red | 100 on / 300 off — loop | `AWAITING_RESET` |
| `RESET_WIPING` | red | solid on | Secure wipe in progress |
| `THINKING` | red → green → blue cycle | 100 ms per color — loop | Crypto op in progress >150 ms |
| `IDENTITY_MISMATCH` | red ↔ yellow | 500/500 — loop | Session-identity recovery mode (transport T-03): stored session cert no longer matches the build constant under `CANTIL_SESSION_X509_STRICT`. Sharp hard-switch alternation, distinct from the `SEQ_ERROR` one-shot and the warm `LOCKED` crossfade. |

**One-shots:**

| Pattern | Colour | Timing | Use |
| --- | --- | --- | --- |
| `TAP_ACK` | dim white (10%) | 30 ms | Per detected tap |
| `DIGIT_ACK` | white | 80 ms | Per closed digit (after 1.5 s silence) |
| `LOCKING` | white | 1 × 150 ms | Explicit lock gesture accepted, before `LOCKED` |
| `READY` | yellow | 500 ms | Prompt: start entering next sequence |
| `VERIFY` | yellow | 250/250/250 | Prompt: re-enter to confirm |
| `MUST_CHANGE_SEQ` | yellow | 3 × (100/100) | Default unlock accepted; chaining into `CHANGE_SEQ_CONFIRM` |
| `UNLOCKED_BLINK` | green | 100/100/100/100 | Unlock succeeded, entering `UNLOCKED` |
| `PASSKEY_DIGIT` | white | N × (100/100), 500 ms trailing pause | One per passkey digit |
| `PAIRING_SUCCESS` | green | 3 × (300/150) | Pairing complete |
| `CONFIRMED` | green | 800 ms | Confirm gesture accepted |
| `RESET_COMPLETE` | white | 3 × (500/500) | Wipe finished, about to reboot |
| `FAIL` | red | 6 × 80 ms toggle | Sequence mismatch, AWAITING timeout expired, generic failure |
| `SEQ_ERROR` | red ↔ yellow | 4 transitions over 1.5 s (375 ms each) | Mid-sequence mistake — entered sequence matched nothing valid |
| `BUSY_REJECT` | red | 2 × 80 ms | Host command rejected due to transient state |

**Kconfig overrides:**

- `CONFIG_CANTIL_LOCKED_LED_STATIC_COLOR=0xRRGGBB` — replace the warm-cycle crossfade with single-color slow blink (4 s period).
- Mono boards: all colors collapse to timing-only blink.

Caller is responsible for the 1000 ms pause between passkey digit groups; the per-digit pattern only includes the within-digit pulses and a 500 ms trailing pause.

## Gesture Timeouts

| Kconfig | Default | Purpose |
| --- | --- | --- |
| `CONFIG_CANTIL_DIGIT_TIMEOUT_MS` | 1500 ms | Silence window that closes the current digit (count of taps → color) |
| `CONFIG_CANTIL_SEQ_TIMEOUT_MS` | 3000 ms | Total silence (since last tap) that closes a whole sequence and triggers evaluation |
| `CONFIG_CANTIL_INACTIVITY_TIMEOUT_SEC` | 300 s | Auto-lock from `UNLOCKED` |
| `CONFIG_CANTIL_CONFIRM_TIMEOUT_SEC` | 10 s | `AWAITING_CONFIRM` → `UNLOCKED` (plays `FAIL`) |
| `CONFIG_CANTIL_RESET_TIMEOUT_SEC` | 30 s | `AWAITING_RESET` → origin state (plays `FAIL`) |
| `CONFIG_CANTIL_PAIR_TIMEOUT_SEC` | 30 s | `AWAITING_PAIR` → origin state (plays `FAIL`); connection rejected |

## BLE Passkey Encoding via LED

BLE Passkey Entry requires exactly 6 decimal digits (BLE Core Spec requirement; phone UI hardcodes 6-digit input). To avoid the ambiguity of encoding zero with blinks, passkeys are generated using only digits 1–9, giving 9⁶ = 531,441 possible values.

Display format: two groups of three digits, 1s pause between groups.

```text
Passkey "3 5 2 | 7 1 4":

  blink×3  blink×5  blink×2   [1s pause]   blink×7  blink×1  blink×4
  ───────  ───────  ───────                 ───────  ───────  ───────
  digit 1  digit 2  digit 3                 digit 4  digit 5  digit 6
```

Blink timing: 100ms on / 100ms off per flash; 500ms pause between digits within a group.

## BLE Pairing Workflow

1. Device boots into `LOCKED`. BLE advertises with RPA; only bonded centrals can resolve and connect.
2. User taps unlock sequence. Device transitions to `UNLOCKED`.
3. User taps pairing trigger `Orange Orange` (2 2). Device transitions to `PAIRING`.
4. Device generates a 6-digit passkey (digits 1–9 only) and begins blinking it.
5. User reads blinks and enters passkey on their device.
6. On completion or timeout (default 60s): device returns to `UNLOCKED`.
7. Bonded central is now in whitelist; future connections allowed while `LOCKED`.

Note: while `LOCKED`, a bonded central can connect at BLE layer and receive `DEVICE_STATUS` responses, but all CA operation commands return `ERR_DEVICE_LOCKED`.

## Change-Sequence Flow

1. While `UNLOCKED`: tap change-sequence trigger `Yellow Yellow Yellow` (3 3 3)
2. Device emits `READY` blink → enters `CHANGE_SEQ_CONFIRM`
3. User taps new sequence (count-then-pause colors; sequence closes after 3 s silence)
4. Device emits `VERIFY` blink → enters `CHANGE_SEQ_VERIFY`
5. User re-taps new sequence:
   - Match → save to LittleFS → emit `UNLOCKED_BLINK` → return to `UNLOCKED`
   - Mismatch → emit `FAIL` → return to `UNLOCKED` (do not save)

Note: when this flow is entered automatically because the user just unlocked with the factory default sequence (`Red Red Red Red`), step 5 mismatch returns to `LOCKED` (not `UNLOCKED`) and re-arms the must-change flow on next unlock — the user must successfully change the sequence before gaining access.
