# Internal Notes

This directory holds documents that are part of the project's working record but are **not intended for external/public release**. Reasoning, positioning analysis, sensitive deployment notes, and similar working material live here.

The whole `internal/` tree is stripped at publish time — see "Publishing to public github mirrors" below.

## Contents

- [hsm_positioning.md](hsm_positioning.md) — why "HSM" was dropped from external copy; what the path would look like if we ever wanted to claim it.

---

## Publishing to public github mirrors

This dev repo holds material that must not appear on public github, in current state or in history:

- `CLAUDE.md` — internal project reference; assistant guidance
- `MEMORY.md` — persisted assistant memory (lives in `~/.claude/projects/.../memory/`, not the repo itself, but listed here for completeness)
- `.claude/` — harness settings + hooks
- `internal/` — this directory
- `docs/conversations/` — full transcripts of dev sessions (verbose, often surface internal reasoning that hasn't been polished)
- build artefacts (`build/`, `build_*/`, `venv/`, `__pycache__/`)

Approach: **snapshot copy + force-push, no history.** History rewrites are fine because we never want any of the above to have existed in the public timeline. The mechanism is `scripts/publish-prep.sh`.

### Workflow

```bash
# 1. Build a clean snapshot in a sibling directory.
scripts/publish-prep.sh                     # default: ../cantil-public
# or
scripts/publish-prep.sh ../some-other-dir

# 2. Point it at the public github repo.
cd ../cantil-public
git remote add origin git@github.com:<owner>/cantil.git
git push -u origin main                     # first push
# or, on subsequent refreshes:
git push -f origin main                     # rewrites public history
```

Each refresh deletes and rebuilds the snapshot directory. The public repo's commit history is intentionally just one commit per refresh — there is no "real" history on the public side, and that's the design.

### Planned repo split

Currently the dev tree is a monorepo. Long-term split (the three public github repos):

| Public repo | Contains | Notes |
| --- | --- | --- |
| `cantil` | `firmware/`, root docs (`README.md`, `docs/roadmap.md`, `LICENSE`, `CHANGELOG.md`), `scripts/`, `Cantil_Logo.txt` | The embedded firmware project. |
| `libcantil` | `libcantil/` core sources + headers + reference transports (POSIX USB, Linux BlueZ BLE) | The client library. |
| `cantil-cli` | `libcantil/cli/` extracted into its own tree, with its own README | The CLI client that uses libcantil. |

`publish-prep.sh` currently snapshots the whole dev tree as a single public repo. When the split happens, the script grows a `--target {cantil,libcantil,cantil-cli}` flag that additionally prunes the irrelevant top-level dirs per target. Until then, the monorepo snapshot is fine.

### Verification

The script sanity-checks the destination after rsync and aborts if anything on the exclude list leaked through. If you add new categories of sensitive paths, update the `EXCLUDES` array in `scripts/publish-prep.sh` *and* this document.
