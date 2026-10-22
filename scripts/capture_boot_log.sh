#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Capture a unit's boot log over its second CDC ACM interface.
#
# The firmware exposes two CDC interfaces: #00 is the protocol transport and
# #02 is the log console. The console port only exists while the application is
# running, and it disappears on every reboot, so this polls for the port
# belonging to a given FICR serial and reopens it as soon as it reappears.
#
# Boot logs are the only way to inspect a device that is not paired: the
# protocol needs an authenticated Noise session, and pairing needs a physical
# tap-confirm. Logs need neither.
#
# Usage: capture_boot_log.sh <ficr-serial> <seconds> [outfile]

set -u

SERIAL="${1:?usage: capture_boot_log.sh <ficr-serial> <seconds> [outfile]}"
SECS="${2:-30}"
OUT="${3:-/dev/stdout}"

find_console_port() {
    for p in /dev/ttyACM*; do
        [ -e "$p" ] || continue
        eval "$(udevadm info -q property -n "$p" 2>/dev/null |
                grep -E '^(ID_SERIAL_SHORT|ID_USB_INTERFACE_NUM)=' |
                sed 's/^/local_/')" 2>/dev/null || true
        s=$(udevadm info -q property -n "$p" 2>/dev/null |
            sed -n 's/^ID_SERIAL_SHORT=//p')
        i=$(udevadm info -q property -n "$p" 2>/dev/null |
            sed -n 's/^ID_USB_INTERFACE_NUM=//p')
        if [ "$s" = "$SERIAL" ] && [ "$i" = "02" ]; then
            echo "$p"
            return 0
        fi
    done
    return 1
}

end=$(( $(date +%s) + SECS ))

echo "--- watching for console port of $SERIAL (${SECS}s)" >&2

while [ "$(date +%s)" -lt "$end" ]; do
    if port=$(find_console_port); then
        # Raw mode, no hangup on close, so reopening does not reset the board.
        stty -F "$port" 115200 raw -echo -hupcl 2>/dev/null || true
        timeout 5 cat "$port" >>"$OUT" 2>/dev/null
    else
        sleep 0.2
    fi
done

echo "--- capture window closed" >&2
