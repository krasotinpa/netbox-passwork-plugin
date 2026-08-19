# Contributing

This project follows a strict **branch + Pull Request** workflow. It applies to every
contributor, human or AI coding agent.

---

## Core rules

1. **Every new feature or fix is developed on a dedicated branch.**
   - Never commit directly to `main`.
   - One task per branch.

2. **Changes reach `main` only through a Pull Request (PR).**

3. **A PR is merged only after explicit confirmation / approval.**
   - No self-merge without an approving review.
   - AI agents MUST NOT open or merge a PR until a maintainer has confirmed it.

---

## Branch naming

Use a short type prefix and a kebab-case description:

```text
feature/<short-description>    # new functionality
fix/<short-description>        # bug fix
docs/<short-description>       # documentation only
chore/<short-description>      # tooling, deps, housekeeping
```

Examples: `feature/endpoint-group-create`, `fix/vni-uniqueness`, `docs/adr-011`.

---

## Typical flow

```bash
git switch -c feature/my-change      # create a branch off up-to-date main
# ... make changes + tests ...
git commit -m "Concise, imperative summary"
git push -u origin feature/my-change
gh pr create                          # open a PR for review
# ... after explicit approval ...
gh pr merge --squash                  # merge only once confirmed
```

Keep each PR focused on a single task; split large work into smaller PRs.

---

## Before opening a PR

- Behavioural changes are covered by tests.
- Run the checks: `scripts/test.sh all` (lint + Python tests + JS tests). There is no CI, so
  paste its markdown summary into the PR body.
- Docs stay consistent with the change (`docs/`, ADRs).
- User-visible changes get an entry in `CHANGELOG.md` under `[Unreleased]`
  (`Added` / `Changed` / `Fixed` / `Removed`).
- No unrelated refactoring bundled in.

See [docs/index.md](docs/index.md) for the developer documentation and
[docs/development.md](docs/development.md) for the test and release workflow.
