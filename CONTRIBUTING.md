# Contributing to Cantil

Thanks for your interest. A few notes before opening a pull request.

## License of contributions

This project is licensed under the GNU General Public License, version 3 or
later (see [LICENSE](LICENSE)). Every source file carries
<!-- REUSE-IgnoreStart -->
`SPDX-License-Identifier: GPL-3.0-or-later`.
<!-- REUSE-IgnoreEnd -->
By submitting a contribution, you agree that your contribution is licensed
under the same GPL-3.0-or-later terms.

There is no linking exception. An earlier revision of the tree referenced a
`cantil-additional-permissions` exception that would have let proprietary
applications link `libcantil`; it was retired, and the identifier should not
reappear in new files.

## Developer Certificate of Origin

Sign your commits with `git commit -s` to certify you have the right to
submit the contribution under the above terms. See
<https://developercertificate.org/> for the full DCO text.

## Before opening a PR

- Follow existing patterns in the file you're editing.
<!-- REUSE-IgnoreStart -->
- New files need an SPDX header: `SPDX-License-Identifier: GPL-3.0-or-later`.
<!-- REUSE-IgnoreEnd -->
- One-time setup: `./scripts/setup_zephyr.sh` (installs the Zephyr SDK and
  creates the west workspace from `firmware/west.yml`).
- Run the build and the tests:
  `./scripts/build.sh` and `./scripts/test.sh`
- Conversation transcripts in [docs/conversations/](docs/conversations/)
  are produced by the post-commit automation hook; don't edit them by
  hand.
