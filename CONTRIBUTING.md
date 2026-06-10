# Contributing to Cantil

Thanks for your interest. A few notes before opening a pull request.

## License of contributions

This project is licensed under the Apache License, Version 2.0 (see
[LICENSE](LICENSE)).
By submitting a contribution, you agree that your contribution is licensed
under the same Apache 2.0 terms.

## Developer Certificate of Origin

Sign your commits with `git commit -s` to certify you have the right to
submit the contribution under the above terms. See
<https://developercertificate.org/> for the full DCO text.

## Before opening a PR

- Follow existing patterns in the file you're editing.
- Run the build inside the distrobox:
  `./scripts/dbox.sh bash scripts/build.sh`
- Conversation transcripts in [docs/conversations/](docs/conversations/)
  are produced by the post-commit automation hook; don't edit them by
  hand.
