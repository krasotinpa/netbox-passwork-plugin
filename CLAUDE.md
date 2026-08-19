# netbox-passwork — notes for AI coding agents

## Documentation

The developer documentation lives in `docs/` — start with [docs/index.md](docs/index.md)
(table of contents and a "question → where to look" map). Architecture — `docs/architecture.md`,
routes — `docs/api.md`, models — `docs/data-model.md`, Passwork integration —
`docs/passwork-integration.md`, security — `docs/security.md`, development, tests and releases —
`docs/development.md`. Architecture decisions are recorded in `docs/adr/`.

Change process — strictly per [CONTRIBUTING.md](CONTRIBUTING.md): branch + pull request, no direct
commits to `main`; AI agents do not open or merge a pull request without a maintainer's explicit
confirmation.

## Commands

`scripts/test.sh` is the single entry point for all checks (it fills in `PYTHONPATH` and
`NETBOX_CONFIGURATION` from `.env`, see `.env.example`):

```bash
scripts/test.sh netbox_passwork/tests/test_proxy.py -x   # a single module while working
scripts/test.sh lint                                     # ruff check + format --check
scripts/test.sh js                                       # JS tests (node --test + jsdom)
scripts/test.sh all                                      # everything + a markdown summary for the PR body
scripts/release.sh check                                 # release status (see docs/development.md §5)
```

## Working efficiently

- Do not read all of `docs/`: `docs/index.md` → the relevant document → the source file.
- While editing code, run only the affected tests; run the full `scripts/test.sh all` once before
  opening a pull request and paste its summary into the PR body — CI covers lint, the JS tests and
  the package build, but the Python tests need a NetBox installation and run locally only.
