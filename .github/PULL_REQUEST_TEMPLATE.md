<!--
Thanks for the PR! A few notes:

- All CI checks must pass before this can merge (yamllint, hadolint,
  shellcheck, pytest, multi-arch build).
- For security-related changes, please coordinate via SECURITY.md
  first — public PRs leak the issue before users can patch.
- See CONTRIBUTING.md for development setup and commit conventions.
-->

## Summary

<!-- One or two sentences on what this PR does. -->

## Motivation

<!-- What problem does this solve? Link an issue if there is one
     (e.g. "Fixes #42"). -->

## Type of change

<!-- Check whichever applies. Multiple are fine. -->

- [ ] `fix` — bug fix
- [ ] `feat` — new feature
- [ ] `docs` — documentation only
- [ ] `refactor` — internal restructuring with no behavior change
- [ ] `perf` — performance improvement
- [ ] `test` — test changes only
- [ ] `chore` — build, CI, dependencies

## Checklist

<!-- Tick what applies. Not all items apply to every PR. -->

- [ ] Tests added or updated for new behavior
- [ ] `access_control/CHANGELOG.md` updated (if user-visible)
- [ ] Documentation updated (README / DOCS) (if user-visible)
- [ ] Manual smoke test against a real HA install completed (if a config /
      ingress / auth path was touched)
- [ ] No secrets, tokens, or homelab-specific references introduced

## Screenshots

<!-- If this PR touches the UI, paste before/after screenshots here. -->
