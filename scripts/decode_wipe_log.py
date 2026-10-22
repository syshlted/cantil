#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Extract the sparse-wipe diagnostic log from a CURRENT.UF2 dumped by the XIAO
# UF2 bootloader. The wipe_diag firmware (firmware/wipe_diag) writes its log to
# internal flash at 0xE6000; the bootloader's CURRENT.UF2 dumps internal flash
# 0x1000..0xEA000, so the log region is inside it.
#
# Usage:
#   scripts/decode_wipe_log.py /run/media/$USER/XIAO-SENSE/CURRENT.UF2

import struct
import sys

LOG_OFF = 0xE6000
LOG_SIZE = 0x4000
UF2_MAGIC0 = 0x0A324655
UF2_MAGIC1 = 0x9E5D5157
MAGIC = b"==CANTIL-WIPE-DIAG=="


def main():
    if len(sys.argv) < 2:
        print("usage: decode_wipe_log.py CURRENT.UF2", file=sys.stderr)
        sys.exit(2)

    data = open(sys.argv[1], "rb").read()
    if len(data) % 512 != 0:
        print("warning: file size is not a multiple of 512", file=sys.stderr)

    region = bytearray(b"\xff" * LOG_SIZE)
    covered = False
    for i in range(len(data) // 512):
        blk = data[i * 512:(i + 1) * 512]
        m0, m1, flags, addr, size, bno, nb, fam = struct.unpack("<IIIIIIII", blk[:32])
        if m0 != UF2_MAGIC0 or m1 != UF2_MAGIC1:
            continue
        if size > 476:
            size = 476
        payload = blk[32:32 + size]
        for j in range(size):
            a = addr + j
            if LOG_OFF <= a < LOG_OFF + LOG_SIZE:
                region[a - LOG_OFF] = payload[j]
                covered = True

    if not covered:
        print("error: CURRENT.UF2 did not cover the log region 0x%06x..0x%06x"
              % (LOG_OFF, LOG_OFF + LOG_SIZE), file=sys.stderr)
        sys.exit(1)

    # Trim trailing erased (0xFF) bytes, then any 4-byte write padding (0x00).
    end = len(region)
    while end > 0 and region[end - 1] == 0xFF:
        end -= 1
    text = bytes(region[:end]).rstrip(b"\x00")

    if not text.startswith(MAGIC):
        print("warning: log magic not found — firmware may not have run, "
              "or the region was never written", file=sys.stderr)

    sys.stdout.buffer.write(text)
    if not text.endswith(b"\n"):
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
