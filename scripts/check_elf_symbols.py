#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Assert symbol-level security invariants on a linked ELF.

Cantil's most important build-time guarantees are not expressible in C: they
are statements about what the *linker* did or did not leave in the image.

  * Production firmware must contain no filesystem formatter. The app is built
    with CONFIG_FILE_SYSTEM_MKFS=n and additionally link-wraps lfs_format to a
    refusing stub, so --gc-sections drops the real one. If either half of that
    regressed, the image would silently regain the ability to erase the key
    store.
  * The factory image, and only the factory image, must contain the formatter —
    that is its entire job (docs/roadmap/two-step-provisioning.md).
  * No mbedTLS code may survive anywhere. The firmware is wolfCrypt-only; a
    stray mbedtls_* symbol means a second crypto implementation was linked in.

Those were verified by hand with `arm-zephyr-eabi-nm` when the Bazel port
landed, and written up in prose. A guarantee that is checked by hand once is a
guarantee that regresses silently, so this makes them build actions: the
firmware does not link unless they hold.

Deliberately parses the ELF symbol table itself rather than shelling out to nm
or objdump. The check must run in the exec configuration while the ELF it reads
is a cross-compiled target artifact, and pulling the target toolchain's binutils
into that configuration is far more machinery than reading a symtab needs. It
also keeps the check identical for the arm and native_sim images.

Usage:
    check_elf_symbols.py IMAGE.elf [--require SYM]... [--forbid SYM]...
                         [--forbid-pattern REGEX]... --out REPORT

Exits non-zero, with the offending symbols named, if any assertion fails.
"""

import argparse
import re
import struct
import sys

SHT_SYMTAB = 2
SHN_UNDEF = 0
STT_NOTYPE = 0


def _read_defined_symbols(path):
    """Return the set of symbol names *defined* by this ELF.

    Undefined (imported) symbols are excluded: a relocatable reference to a
    name is not the same as carrying its code, and only the latter is what
    these invariants are about.
    """
    with open(path, "rb") as fh:
        data = fh.read()

    if data[:4] != b"\x7fELF":
        raise SystemExit("error: %s is not an ELF file" % path)

    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"

    if is64:
        e_shoff, = struct.unpack_from(endian + "Q", data, 0x28)
        e_shentsize, e_shnum = struct.unpack_from(endian + "HH", data, 0x3A)
    else:
        e_shoff, = struct.unpack_from(endian + "I", data, 0x20)
        e_shentsize, e_shnum = struct.unpack_from(endian + "HH", data, 0x2E)

    names = set()
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_type, = struct.unpack_from(endian + "I", data, off + 4)
        if sh_type != SHT_SYMTAB:
            continue

        if is64:
            sh_offset, sh_size = struct.unpack_from(endian + "QQ", data, off + 0x18)
            sh_link, = struct.unpack_from(endian + "I", data, off + 0x28)
            sh_entsize, = struct.unpack_from(endian + "Q", data, off + 0x38)
        else:
            sh_offset, sh_size = struct.unpack_from(endian + "II", data, off + 0x10)
            sh_link, = struct.unpack_from(endian + "I", data, off + 0x18)
            sh_entsize, = struct.unpack_from(endian + "I", data, off + 0x24)

        # sh_link names the associated string table section.
        str_off = e_shoff + sh_link * e_shentsize
        if is64:
            strtab_offset, = struct.unpack_from(endian + "Q", data, str_off + 0x18)
        else:
            strtab_offset, = struct.unpack_from(endian + "I", data, str_off + 0x10)

        for j in range(sh_size // sh_entsize):
            sym = sh_offset + j * sh_entsize
            st_name, = struct.unpack_from(endian + "I", data, sym)
            if is64:
                st_info = data[sym + 4]
                st_shndx, = struct.unpack_from(endian + "H", data, sym + 6)
            else:
                st_info = data[sym + 12]
                st_shndx, = struct.unpack_from(endian + "H", data, sym + 14)

            if st_shndx == SHN_UNDEF or st_name == 0:
                continue
            # Section and file symbols carry no code; STT_NOTYPE entries are
            # mostly assembler labels. Keep NOTYPE (linker-script symbols such
            # as __wrap_* aliases can land there) but drop the rest.
            st_type = st_info & 0xF
            if st_type not in (STT_NOTYPE, 1, 2):  # NOTYPE, OBJECT, FUNC
                continue

            end = data.index(b"\x00", strtab_offset + st_name)
            names.add(data[strtab_offset + st_name:end].decode("utf-8", "replace"))

    return names


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("elf")
    ap.add_argument("--require", action="append", default=[], metavar="SYM",
                    help="symbol that must be defined in the image")
    ap.add_argument("--forbid", action="append", default=[], metavar="SYM",
                    help="symbol that must not be defined in the image")
    ap.add_argument("--forbid-pattern", action="append", default=[], metavar="RE",
                    help="regex no defined symbol may match")
    ap.add_argument("--out", required=True, help="report file to write")
    args = ap.parse_args()

    defined = _read_defined_symbols(args.elf)
    failures = []
    report = ["symbol invariants for %s" % args.elf,
              "  %d defined symbols" % len(defined), ""]

    for sym in args.require:
        ok = sym in defined
        report.append("  %-8s require  %s" % ("ok" if ok else "FAIL", sym))
        if not ok:
            failures.append("required symbol %r is not defined in the image" % sym)

    for sym in args.forbid:
        ok = sym not in defined
        report.append("  %-8s forbid   %s" % ("ok" if ok else "FAIL", sym))
        if not ok:
            failures.append("forbidden symbol %r is defined in the image" % sym)

    for pattern in args.forbid_pattern:
        hits = sorted(s for s in defined if re.search(pattern, s))
        ok = not hits
        report.append("  %-8s forbid   /%s/%s" %
                      ("ok" if ok else "FAIL", pattern,
                       "" if ok else "  -> " + ", ".join(hits[:8])))
        if hits:
            failures.append("%d symbol(s) match forbidden pattern /%s/: %s" %
                            (len(hits), pattern, ", ".join(hits[:8])))

    report.append("")
    report.append("RESULT: %s" % ("PASS" if not failures else "FAIL"))

    with open(args.out, "w") as fh:
        fh.write("\n".join(report) + "\n")

    if failures:
        sys.stderr.write("\n".join(report) + "\n\n")
        for f in failures:
            sys.stderr.write("error: %s\n" % f)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
