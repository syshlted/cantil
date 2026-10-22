#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Assert that firmware/west.yml and MODULE.bazel pin the same tree.

While both build systems exist, every dependency Cantil pins is stated twice —
as a manifest revision in firmware/west.yml and as an explicit commit in
MODULE.bazel — and nothing makes the two agree. That matters more than ordinary
duplication, because the CMake/west build's only remaining job is to be the
*reference* the Bazel output is checked against. A reference that builds a
different tree proves nothing, and it would fail silently: both builds would be
green, and the A/B comparison between them would quietly become meaningless.

The obstacle is that the two files speak different languages. west names a tag
(`revision: v4.4.0`); Bazel names the commit that tag peels to
(`684c9e8f...`). Resolving one to the other needs the network and a clone of
the upstream repo, which a build-time check cannot have.

So each file carries a `PIN:` marker line naming *both* halves:

    # PIN: zephyr v4.4.0 684c9e8f32e4373a21098559f748f06915f950c9

and this checks the loop those markers close:

  1. the two files' markers agree with each other;
  2. each marker's commit is the commit MODULE.bazel actually pins;
  3. each marker's version is the revision west.yml actually names.

Any single-sided edit therefore fails: bump west's `revision:` and (3) breaks,
bump MODULE.bazel's `commit =` and (2) breaks, update one file's marker and (1)
breaks. What remains a human's job is asserting the tag really does peel to that
commit — done once, with a network, when the pin moves. The recipe is in the
MODULE.bazel comment above the pin.

Usage:
    check_pin_agreement.py MODULE.bazel firmware/west.yml [--out REPORT]
"""

import argparse
import re
import sys

# "# PIN: <project> <version> <40-hex-sha>", in either file.
MARKER_RE = re.compile(
    r"^\s*#\s*PIN:\s*(\S+)\s+(\S+)\s+([0-9a-fA-F]{40})\s*$", re.MULTILINE)


def parse_markers(text, path):
    markers = {}
    for name, version, sha in MARKER_RE.findall(text):
        if name in markers:
            raise SystemExit("error: %s declares PIN: %s twice" % (path, name))
        markers[name] = (version, sha.lower())
    return markers


def parse_module_commits(text):
    """Every commit MODULE.bazel actually pins, keyed by project name.

    Covers both idioms in the file: the zephyr_patch.checkout() call (which has
    no name attribute — the project is 'zephyr' by construction) and the
    new_git_repository / git_override blocks.
    """
    commits = {}

    # Bounded by a close paren in column 0, not the first ")" — the call bodies
    # here are mostly prose, and prose has parentheses in it.
    m = re.search(r"zephyr_patch\.checkout\((.*?)\n\)", text, re.DOTALL)
    if m:
        c = re.search(r'commit\s*=\s*"([0-9a-fA-F]{40})"', m.group(1))
        if c:
            commits["zephyr"] = c.group(1).lower()

    for block in re.finditer(
            r"(?:new_git_repository|git_override)\(\s*(.*?)\n\)", text, re.DOTALL):
        body = block.group(1)
        n = re.search(r'(?:name|module_name)\s*=\s*"([^"]+)"', body)
        c = re.search(r'commit\s*=\s*"([0-9a-fA-F]{40})"', body)
        if n and c:
            commits[n.group(1)] = c.group(1).lower()

    return commits


def parse_west_revisions(text):
    """Every `revision:` in west.yml, keyed by the project name above it.

    Hand-rolled rather than via PyYAML: the check has to run inside the build
    graph, where a third-party parser would be one more dependency to pin, and
    the manifest's shape here is two keys deep.
    """
    revisions = {}
    name = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if stripped.startswith("- name:"):
            name = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("revision:") and name:
            revisions[name] = stripped.split(":", 1)[1].strip()
            name = None
    return revisions


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("module_bazel")
    ap.add_argument("west_yml")
    ap.add_argument("--out", help="report file to write")
    args = ap.parse_args()

    module_text = open(args.module_bazel).read()
    west_text = open(args.west_yml).read()

    module_markers = parse_markers(module_text, args.module_bazel)
    west_markers = parse_markers(west_text, args.west_yml)
    module_commits = parse_module_commits(module_text)
    west_revisions = parse_west_revisions(west_text)

    failures = []
    report = ["pin agreement: MODULE.bazel <-> firmware/west.yml", ""]

    if not module_markers:
        failures.append("MODULE.bazel declares no PIN: markers at all")
    if not west_markers:
        failures.append("firmware/west.yml declares no PIN: markers at all")

    # 1. The two files' markers agree.
    for name in sorted(set(module_markers) | set(west_markers)):
        m = module_markers.get(name)
        w = west_markers.get(name)
        if m is None:
            failures.append("west.yml pins %r but MODULE.bazel has no PIN: marker "
                            "for it" % name)
            continue
        if w is None:
            failures.append("MODULE.bazel pins %r but west.yml has no PIN: marker "
                            "for it" % name)
            continue
        if m != w:
            failures.append(
                "PIN: markers disagree for %r — MODULE.bazel says %s/%s, "
                "west.yml says %s/%s" % (name, m[0], m[1][:8], w[0], w[1][:8]))
            report.append("  FAIL      %-10s markers disagree" % name)
            continue

        broke = []

        # 2. The marker's commit is what MODULE.bazel really pins.
        actual = module_commits.get(name)
        if actual is None:
            broke.append("MODULE.bazel has a PIN: marker for %r but pins no "
                         "commit for it" % name)
        elif actual != m[1]:
            broke.append(
                "MODULE.bazel pins %r at %s but its PIN: marker says %s — "
                "the pin moved and the marker did not" % (name, actual[:8], m[1][:8]))

        # 3. The marker's version is what west.yml really names.
        rev = west_revisions.get(name)
        if rev is None:
            broke.append("west.yml has a PIN: marker for %r but names no "
                         "revision for it" % name)
        elif rev != m[0]:
            broke.append(
                "west.yml pins %r at revision %s but its PIN: marker says %s — "
                "the pin moved and the marker did not" % (name, rev, m[0]))

        failures.extend(broke)
        report.append("  %-8s  %-10s %s (%s)" %
                      ("ok" if not broke else "FAIL", name, m[0], m[1][:8]))

    report.append("")
    report.append("Note: that each tag really peels to the commit beside it is "
                  "verified by hand when the")
    report.append("pin moves (recipe in MODULE.bazel) — it needs a network and "
                  "cannot be checked here.")
    report.append("")
    report.append("RESULT: %s" % ("PASS" if not failures else "FAIL"))

    text = "\n".join(report) + "\n"
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(text)

    sys.stdout.write(text)
    if failures:
        sys.stderr.write("\n")
        for f in failures:
            sys.stderr.write("error: %s\n" % f)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
