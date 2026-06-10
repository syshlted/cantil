# Button UI — State Machine

Sequence names use the COUNT_COLOR alphabet (default). STDT_BINARY uses the same colour mapping; STDT_PLAIN substitutes ST/DT patterns.

```mermaid
stateDiagram-v2
    [*] --> LOCKED : power-on / reset

    LOCKED --> LOCKED : wrong sequence → FAIL + rate-limit
    LOCKED --> UNLOCKED : correct unlock sequence
    LOCKED --> CHANGE_SEQ_CONFIRM : factory-default unlock (forced change)

    UNLOCKED --> LOCKED : Red — lock
    UNLOCKED --> PAIRING : Orange-Orange — pairing trigger
    UNLOCKED --> CHANGE_SEQ_CONFIRM : Yellow x3 — change sequence
    UNLOCKED --> AWAITING_CONFIRM : host PROTECT_SLOT / UNPROTECT_SLOT
    UNLOCKED --> AWAITING_RESET : host RESET_DEVICE

    PAIRING --> AWAITING_PAIR : unknown client handshake

    AWAITING_PAIR --> UNLOCKED : Orange-Orange → bond accepted
    AWAITING_PAIR --> UNLOCKED : wrong sequence → FAIL
    AWAITING_PAIR --> UNLOCKED : timeout → FAIL

    AWAITING_CONFIRM --> UNLOCKED : Purple x3 → confirmed
    AWAITING_CONFIRM --> UNLOCKED : wrong sequence → FAIL
    AWAITING_CONFIRM --> UNLOCKED : timeout → FAIL

    AWAITING_RESET --> UNLOCKED : re-enter unlock seq (was UNLOCKED)
    AWAITING_RESET --> LOCKED : re-enter unlock seq (was LOCKED)
    AWAITING_RESET --> AWAITING_RESET : wrong sequence → FAIL
    AWAITING_RESET --> AWAITING_RESET : timeout → FAIL

    CHANGE_SEQ_CONFIRM --> CHANGE_SEQ_VERIFY : enter new sequence
    CHANGE_SEQ_VERIFY --> UNLOCKED : confirmed → saved
    CHANGE_SEQ_VERIFY --> LOCKED : forced-change mismatch → FAIL
    CHANGE_SEQ_VERIFY --> UNLOCKED : voluntary mismatch → FAIL (no change)
```

## Interaction flows (sequence view)

```mermaid
sequenceDiagram
    participant U as User (Gestures)
    participant D as Device
    participant H as Host

    Note over D: LOCKED (power-on / reset)

    rect rgb(255,240,240)
        Note over U,D: Unlock
        U->>D: correct unlock sequence
        D-->>U: UNLOCKED
    end

    rect rgb(240,255,240)
        Note over U,H: Pairing
        U->>D: Orange-Orange (from UNLOCKED)
        D-->>U: PAIRING (advertising)
        H->>D: unknown client handshake
        D-->>U: AWAITING_PAIR
        alt Orange-Orange
            U->>D: Orange-Orange
            D-->>U: UNLOCKED (bonded)
        else wrong / timeout
            D-->>U: UNLOCKED (FAIL)
        end
    end

    rect rgb(240,240,255)
        Note over U,D: Change Sequence
        U->>D: Yellow×3 (from UNLOCKED)
        D-->>U: CHANGE_SEQ_CONFIRM
        U->>D: enter new sequence
        D-->>U: CHANGE_SEQ_VERIFY
        alt confirmed (re-enter matches)
            D-->>U: UNLOCKED (saved)
        else mismatch
            D-->>U: LOCKED / UNLOCKED (FAIL)
        end
    end

    rect rgb(255,255,220)
        Note over U,H: Protect / Unprotect Slot
        H->>D: PROTECT_SLOT or UNPROTECT_SLOT
        D-->>U: AWAITING_CONFIRM
        alt Purple×3
            U->>D: Purple×3
            D-->>H: confirmed
            D-->>U: UNLOCKED
        else wrong / timeout
            D-->>U: UNLOCKED (FAIL)
        end
    end

    rect rgb(220,255,255)
        Note over U,H: Reset Device
        H->>D: RESET_DEVICE
        D-->>U: AWAITING_RESET
        alt re-enter unlock sequence
            U->>D: unlock sequence
            D-->>H: confirmed
            D-->>U: prior state (LOCKED or UNLOCKED)
        else wrong / timeout
            D-->>U: AWAITING_RESET (FAIL)
        end
    end
```

## Sequence reference (COUNT_COLOR)

| Sequence | Gesture | Triggers |
| -------- | ------- | -------- |
| Red (×1) | 1 tap | Lock |
| Red×4 | 4 taps | Factory-default unlock |
| Orange-Orange | 2 taps, 2 taps | Pairing trigger (from UNLOCKED); pair-confirm (from AWAITING_PAIR) |
| Yellow×3 | 3 taps, 3 taps, 3 taps | Change-sequence trigger |
| Purple×3 | 6 taps, 6 taps, 6 taps → now **3 taps, 3 taps, 3 taps** | Confirm (PROTECT/UNPROTECT) |
| *(unlock seq)* | user-defined | RESET_DEVICE confirmation |

## Notes

- **PAIRING** is an idle advertising state entered via the pairing trigger; it advances to AWAITING_PAIR only when the session layer receives a handshake from an unknown client.
- **pre_state** in AWAITING_RESET means the device returns to whichever state (LOCKED or UNLOCKED) it was in before the reset prompt.
- The optional `GESTURE_REHEARSAL` build flag adds two extra sequences from UNLOCKED: Blue-Blue (simulates PROTECT_SLOT) and Cyan-Cyan (simulates RESET_DEVICE), bypassing the host command requirement.
- `SEQ_CONFIRM` (Purple×3) was reduced from `{6,6,6}` to `{3,3,3}` to ease the protect/unprotect UX.
