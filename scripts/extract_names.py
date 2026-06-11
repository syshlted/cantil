#!/usr/bin/env python3
"""
Extract top-1000 boy and girl names from the SSA HTML page and write them
to a plain text file, one name per line, lowercased and deduplicated.

This is a maintenance tool — run it when the source HTML is updated.
The output text file is what the build process consumes via gen_names_data.py.

Usage
-----
    python3 scripts/extract_names.py \\
        "contrib/www.ssa.gov - Top Baby Names for 2025.html" \\
        contrib/names.txt
"""

import argparse
import re
import sys
from html.parser import HTMLParser


class NamesParser(HTMLParser):
    """Pull the 2nd and 4th <td> text from each data row of the SSA table."""

    def __init__(self):
        super().__init__()
        self.boy_names = []
        self.girl_names = []
        self._in_tr = False
        self._td_index = 0
        self._capture = False
        self._current = ""

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self._in_tr = True
            self._td_index = 0
        elif tag == "td" and self._in_tr:
            self._td_index += 1
            self._capture = self._td_index in (2, 4)
            self._current = ""

    def handle_endtag(self, tag):
        if tag == "td" and self._capture:
            text = self._current.strip()
            # Accept only plausible name characters: letters, hyphens, apostrophes.
            # This excludes footer nav links that contain spaces, |, &, etc.
            if text and all(c.isalpha() or c in "-'" for c in text):
                if self._td_index == 2:
                    self.boy_names.append(text.lower())
                else:
                    self.girl_names.append(text.lower())
            self._capture = False
        elif tag == "tr":
            self._in_tr = False

    def handle_data(self, data):
        if self._capture:
            self._current += data


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("html_file", help="Path to the SSA HTML file")
    ap.add_argument("out_txt",   help="Output text file path")
    args = ap.parse_args()

    with open(args.html_file, encoding="utf-8") as f:
        html = f.read()

    parser = NamesParser()
    parser.feed(html)

    boy_names  = parser.boy_names
    girl_names = parser.girl_names

    if not boy_names or not girl_names:
        sys.exit("ERROR: No names extracted — check that the HTML file is the "
                 "SSA popular names page.")

    # Deduplicate, preserving order (boy names first, then girl-only names)
    seen: set[str] = set()
    all_names: list[str] = []
    for name in boy_names + girl_names:
        if name not in seen:
            seen.add(name)
            all_names.append(name)

    with open(args.out_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(all_names) + "\n")

    print(f"{len(boy_names)} boy + {len(girl_names)} girl → "
          f"{len(all_names)} unique names written to {args.out_txt}")


if __name__ == "__main__":
    main()
