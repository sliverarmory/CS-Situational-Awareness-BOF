# Synchronizing TrustedSec upstream

This repository is a Sliver Armory fork of
[`trustedsec/CS-Situational-Awareness-BOF`](https://github.com/trustedsec/CS-Situational-Awareness-BOF).
The complete upstream Windows source corpus is retained. Linux and macOS support
is an additive, curated portability layer rather than a replacement for the
upstream implementations.

The initial Reflektor portability work was proven in
[`sliverarmory/Situational-Awareness-BOFs`](https://github.com/sliverarmory/Situational-Awareness-BOFs).
Its `bofs` work started from this fork's commit
`40786cff3c0ac39cb42d64187d3b69efb19acac9` and reached the native Darwin matrix
at `693174ff525595c5ec61b08fdccb5f057ad52c94`. Preserve those source commit IDs
when importing follow-up work, for example with merge ancestry or
`git cherry-pick -x`.

## Ownership boundaries

- Treat Windows C sources and per-command Makefiles below `src/SA/`, shared
  Windows code in `src/common/`, and `src/base_template/` as upstream-facing.
- Treat `src/SA/*/extension.json`, `portable/`, the root matrix/package wrappers,
  the matrix and packaging scripts, `testdata/`, Armory workflows, and
  portability documentation as fork-owned.
- Treat `SA/`, `dist/`, and `packages/` as generated output, not source. Do not
  commit locally generated object files or release archives.

Keeping the Unix implementation below `portable/` avoids spreading platform
conditionals through upstream-owned Windows files. Small corrections to shared
Windows declarations should remain isolated and documented so they are easy to
re-evaluate during a merge.

## Sync procedure

Use a short-lived branch for each sync and preserve the upstream merge parent.
Do not rebase published `master`, squash away the merge, or mix portability and
publishing changes into the upstream merge commit.

```sh
git fetch --prune origin
git fetch --prune upstream
git switch -c feat/upstream-sync-YYYY-MM-DD origin/master
git merge --no-ff --no-commit upstream/master
```

Review every conflict and staged path before committing. Avoid whole-tree
`ours` or `theirs` conflict strategies: they can silently discard either new
upstream BOFs or fork-owned manifests. The first commit should contain only the
upstream merge and the minimum conflict resolutions needed to preserve the
boundaries above.

Use later commits for distinct concerns:

1. Classify new commands and adapt or add portable implementations and runtime
   expectations.
2. Add or update Armory manifests, package assembly, and publishing automation.
3. Update explanatory documentation when it is not already part of the relevant
   focused commit.

This separation makes future syncs, reviews, reverts, and provenance audits
substantially easier. An upstream sync must not create a version tag or release.

## The generated `SA/` conflict boundary

TrustedSec tracks `SA/SA.cna` and compiled objects below `SA/`. This fork keeps
release objects out of Git and retains only its placeholder there, so upstream
updates to those generated files can appear as modify/delete conflicts.

Resolve those conflicts deliberately: accept the corresponding source changes
under `src/`, but keep generated `SA/` artifacts deleted unless the repository's
artifact policy is explicitly changed. Inspect unresolved entries with
`git status` and `git ls-files -u`; never use a broad cleanup command against
`SA/` or `src/` while resolving the merge.

The fork also owns its Armory workflows and `extension.json` files. Review
upstream workflow additions for useful build changes, but do not enable an
upstream auto-release workflow alongside the fork's tag-gated publishing flow.

## Required gates

Every sync must pass these gates before it is merged:

1. **Complete classification:** every directory immediately below `src/SA/`
   appears exactly once in the portability manifest as portable or Windows-only.
   A newly added upstream command must cause verification to fail until that
   choice is explicit.
2. **Full build matrix:** build and verify every declared target with
   `make matrix` and `make verify`. Verification must reject missing or extra
   objects and incorrect COFF, ELF relocatable, or Mach-O object formats and
   machine types.
3. **Fresh runtime contract:** regenerate the E2E manifest when source commands,
   arguments, targets, or expected output change, and require the checked-in
   manifest to match its generator.
4. **Runtime execution:** run the Reflektor BOF corpus for each supported target.
   A valid object header is not proof that the loader can resolve and execute
   that object on the target runtime.
5. **Publishing dry run:** assemble and validate the unsigned Armory packages in
   CI. Signing and GitHub release publication remain exclusive to an explicitly
   approved version tag.

Finish with focused repository checks such as `git diff --check`, manifest JSON
parsing, and a review of the merge commit against both parents. Record the exact
upstream commit in the pull request or handoff.
