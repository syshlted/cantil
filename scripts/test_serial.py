#!/usr/bin/env python3
"""
Smoke test for the cantil USB CDC/ACM serial transport.

Wire format (stub, pre-Noise):
  Frame = 2-byte big-endian length + payload
  Request payload  = [cmd_byte, seq_byte, ...data]
  Response payload = [seq_byte, err_byte, ...data]

Usage:
  python3 scripts/test_serial.py [/dev/ttyACM0]
"""

import sys
import struct
import time
import serial

CMD_DEVICE_STATUS = 0x30
CMD_GET_RANDOM    = 0x40

ERR_OK            = 0
ERR_DEVICE_LOCKED = 1
ERR_INVALID_CMD   = 2
ERR_INVALID_ARGS  = 3
ERR_STORAGE       = 4
ERR_CRYPTO        = 5
ERR_NOT_FOUND     = 6
ERR_NO_SLOTS      = 7

STATE_NAMES = {0: "LOCKED", 1: "UNLOCKED", 2: "PAIRING",
               3: "CHANGE_SEQ_CONFIRM", 4: "CHANGE_SEQ_VERIFY"}

ERR_NAMES = {0: "OK", 1: "DEVICE_LOCKED", 2: "INVALID_CMD", 3: "INVALID_ARGS",
             4: "STORAGE", 5: "CRYPTO", 6: "NOT_FOUND", 7: "NO_SLOTS"}

def send_frame(port: serial.Serial, payload: bytes) -> None:
    hdr = struct.pack(">H", len(payload))
    port.write(hdr + payload)
    port.flush()

def recv_frame(port: serial.Serial, timeout_s: float = 12.0) -> bytes:
    port.timeout = timeout_s
    hdr = port.read(2)
    if len(hdr) < 2:
        raise TimeoutError("timed out waiting for length header")
    length = struct.unpack(">H", hdr)[0]
    payload = port.read(length)
    if len(payload) < length:
        raise TimeoutError(f"timed out reading payload ({len(payload)}/{length} bytes)")
    return payload

def send_cmd(port: serial.Serial, cmd: int, seq: int, data: bytes = b"") -> tuple[int, int, bytes]:
    payload = bytes([cmd, seq]) + data
    send_frame(port, payload)
    resp = recv_frame(port)
    if len(resp) < 2:
        raise ValueError(f"response too short: {resp.hex()}")
    resp_seq, err = resp[0], resp[1]
    resp_data = resp[2:]
    return resp_seq, err, resp_data

def check(label: str, cond: bool, detail: str = "") -> bool:
    status = "PASS" if cond else "FAIL"
    print(f"  [{status}] {label}" + (f": {detail}" if detail else ""))
    return cond

def main() -> int:
    dev = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyACM0"
    print(f"Opening {dev} ...")

    try:
        port = serial.Serial(dev, baudrate=115200, timeout=2)
    except serial.SerialException as e:
        print(f"ERROR: {e}")
        return 1

    # Wait for DTR to be acknowledged (device polls every 500ms)
    port.dtr = True
    time.sleep(1.2)

    passed = 0
    failed = 0

    def run(label: str, cond: bool, detail: str = "") -> None:
        nonlocal passed, failed
        if check(label, cond, detail):
            passed += 1
        else:
            failed += 1

    print("\n--- DEVICE_STATUS ---")
    try:
        seq, err, data = send_cmd(port, CMD_DEVICE_STATUS, seq=1)
        run("seq echoed", seq == 1, f"got {seq}")
        run("err == OK", err == ERR_OK, ERR_NAMES.get(err, hex(err)))
        run("response has state byte", len(data) >= 1, f"{len(data)} bytes")
        if len(data) >= 1:
            state = data[0]
            run("state is valid", state in STATE_NAMES,
                STATE_NAMES.get(state, f"unknown({state})"))
    except (TimeoutError, ValueError) as e:
        print(f"  [FAIL] exception: {e}")
        failed += 1

    print("\n--- GET_RANDOM (8 bytes) ---")
    try:
        req_data = struct.pack(">H", 8)
        seq, err, data = send_cmd(port, CMD_GET_RANDOM, seq=2, data=req_data)
        run("seq echoed", seq == 2, f"got {seq}")
        # Device is LOCKED at boot — GET_RANDOM requires unlock, so either OK or LOCKED is valid
        run("err is OK or LOCKED",
            err in (ERR_OK, ERR_DEVICE_LOCKED),
            ERR_NAMES.get(err, hex(err)))
        if err == ERR_OK:
            run("got 8 random bytes", len(data) == 8, f"got {len(data)}: {data.hex()}")
    except (TimeoutError, ValueError) as e:
        print(f"  [FAIL] exception: {e}")
        failed += 1

    print("\n--- INVALID CMD (0xFF) ---")
    try:
        seq, err, data = send_cmd(port, 0xFF, seq=3)
        run("seq echoed", seq == 3, f"got {seq}")
        # Lock check fires before cmd dispatch, so locked device returns DEVICE_LOCKED
        run("err == INVALID_CMD or LOCKED",
            err in (ERR_INVALID_CMD, ERR_DEVICE_LOCKED),
            ERR_NAMES.get(err, hex(err)))
    except (TimeoutError, ValueError) as e:
        print(f"  [FAIL] exception: {e}")
        failed += 1

    port.close()

    total = passed + failed
    print(f"\nResult: {passed}/{total} passed", "✓" if failed == 0 else "✗")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
