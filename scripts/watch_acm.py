#!/usr/bin/env python3
"""
Watch one or more /dev/ttyACM* devices and print every line with a colored
[device] prefix. Useful for tailing the log/console ACM of one or both XIAOs
in parallel.

Usage:
  scripts/watch_acm.py                       # auto-detect /dev/ttyACM*
  scripts/watch_acm.py /dev/ttyACM1          # one specific device
  scripts/watch_acm.py /dev/ttyACM1 /dev/ttyACM3
  scripts/watch_acm.py -b 115200 /dev/ttyACM1

Ctrl-C to quit.
"""
import argparse
import glob
import os
import sys
import threading
import time

try:
    import serial
except ImportError:
    sys.exit("pyserial not installed — run: pip install pyserial")

COLORS = ["\033[36m", "\033[33m", "\033[35m", "\033[32m",
          "\033[34m", "\033[31m", "\033[96m", "\033[93m"]
RESET = "\033[0m"


def reader(path: str, baud: int, label: str, color: str, stop: threading.Event):
    backoff = 0.5
    while not stop.is_set():
        try:
            with serial.Serial(path, baud, timeout=0.2) as ser:
                print(f"{color}[{label}]{RESET} opened {path} @ {baud}",
                      flush=True)
                backoff = 0.5
                buf = b""
                while not stop.is_set():
                    chunk = ser.read(256)
                    if not chunk:
                        continue
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        text = line.rstrip(b"\r").decode("utf-8", "replace")
                        print(f"{color}[{label}]{RESET} {text}", flush=True)
        except serial.SerialException as e:
            print(f"{color}[{label}]{RESET} {e} — retry in {backoff:.1f}s",
                  flush=True)
            stop.wait(backoff)
            backoff = min(backoff * 2, 5.0)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("devices", nargs="*",
                   help="paths like /dev/ttyACM1 (default: all /dev/ttyACM*)")
    p.add_argument("-b", "--baud", type=int, default=115200)
    args = p.parse_args()

    devices = args.devices or sorted(glob.glob("/dev/ttyACM*"))
    if not devices:
        sys.exit("no devices specified and no /dev/ttyACM* found")

    stop = threading.Event()
    threads = []
    for i, dev in enumerate(devices):
        label = os.path.basename(dev)
        color = COLORS[i % len(COLORS)]
        t = threading.Thread(target=reader,
                             args=(dev, args.baud, label, color, stop),
                             daemon=True)
        t.start()
        threads.append(t)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nstopping...", flush=True)
        stop.set()
        for t in threads:
            t.join(timeout=1.0)


if __name__ == "__main__":
    main()
