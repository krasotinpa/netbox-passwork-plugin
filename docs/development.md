# Development, tests, releases

This document describes how to set up a development environment for `netbox-passwork`, how to run
the tests (Python and JS), which linting is applied, how versioning and releases work, and how
changes make their way into `main`.

---

## 1. Environment requirements

| Component | Version | Source |
|---|---|---|
| Python | ≥ 3.12 | `requires-python` in [pyproject.toml](../pyproject.toml) |
| NetBox | ≥ 4.5 | `min_version = "4.5"` in [netbox_passwork/config.py](../netbox_passwork/config.py) |
| PostgreSQL | 14+ | [README.md](../README.md) |
| Passwork | 7.6+ (CSE off) | [README.md](../README.md) |

The plugin is a NetBox Django plugin, not a standalone application. `pytest.ini` sets
`DJANGO_SETTINGS_MODULE = netbox.settings`, so the tests cannot run in an empty environment —
they need a NetBox installation with the plugin registered (`netbox_passwork` in `PLUGINS`),
and `pytest` runs from that installation's environment.

The runtime dependencies in [pyproject.toml](../pyproject.toml) are only what the plugin imports
directly (Django, NetBox and their dependencies come with the NetBox installation itself and are
not declared in `dependencies`):

- `requests>=2.31` — HTTP client for the Passwork API (`passwork_client.py`, written in-house, no
  third-party SDK)
- `cryptography>=41.0` — encryption of the Passwork token in the Django session (Fernet)
- `djangorestframework>=3.14` — serializers (`serializers.py`)

The dev extra (`pip install -e ".[dev]"`), section `[project.optional-dependencies].dev`:

- `pytest>=8.0`, `pytest-django>=4.8` — test runner and Django integration
- `responses>=0.25` — mocking HTTP requests to the Passwork API
- `coverage[toml]>=7.4` — code coverage
- `ruff>=0.16` — linter/formatter (same version pinned in `.pre-commit-config.yaml`)
- `pre-commit>=3.7` — pre-commit hooks
- `build>=1.2`, `twine>=5.0` — building and uploading the sdist/wheel during a release
  (`scripts/release.sh`)

Package metadata: the plugin is licensed under Apache-2.0 (see [LICENSE](../LICENSE)). Tests
(`netbox_passwork.tests`) are excluded from the wheel.

Basic environment setup (see [README.md](../README.md#development)):

```bash
pip install -e ".[dev]"
export PW_SESSION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
pytest
```

Dev dependencies live only in `[project.optional-dependencies].dev` in `pyproject.toml`; there is
no separate `requirements.txt`.

### Single entry point: `scripts/test.sh`

[scripts/test.sh](../scripts/test.sh) fills in the NetBox environment (`PYTHONPATH`,
`NETBOX_CONFIGURATION`, the NetBox venv, a Linux `node` binary) and runs the requested check:

```bash
scripts/test.sh                                          # all Python tests
scripts/test.sh netbox_passwork/tests/test_proxy.py -x   # a single module (any pytest arguments)
scripts/test.sh lint                                     # ruff check + ruff format --check
scripts/test.sh js                                       # JS tests (node --test + jsdom)
scripts/test.sh all                                      # lint + Python + JS, with a markdown summary for a PR
```

Paths and the configuration module name come from environment variables; the convenient place for
them is an `.env` file in the repository root (git-ignored), see
[.env.example](../.env.example): `NETBOX_ROOT` (defaults to `/opt/netbox`), `NETBOX_VENV`,
`NETBOX_CONFIGURATION` (the NetBox configuration module where the plugin is registered in
`PLUGINS`) and `NODE_BIN` (a Linux node build — relevant under WSL, where `PATH` may point at a
Windows node).

If you do not have a NetBox configuration with the plugin registered yet, copy the ready-made one:

```bash
cp testing/configuration.py $NETBOX_ROOT/netbox/netbox/configuration.py
```

[testing/configuration.py](../testing/configuration.py) declares everything the suite needs —
database, both Redis sections, a `SECRET_KEY`, `PLUGINS` and the two required plugin settings
(`PASSWORK_URL`, `SESSION_ENCRYPT_KEY`; both are placeholders, since the tests mock every Passwork
call). Each value can be overridden through an environment variable, which is how CI reuses the same
file.

---

## 2. Python tests

Configuration — [pytest.ini](../pytest.ini):

```ini
[pytest]
DJANGO_SETTINGS_MODULE = netbox.settings
django_find_project = false
python_files = tests/test_*.py
python_classes = Test*
python_functions = test_*
addopts = --tb=short -q --reuse-db
```

Key points:

- `DJANGO_SETTINGS_MODULE = netbox.settings` — the tests run against **NetBox's own** Django
  settings, not the plugin's; without an installed and configured NetBox they will not start.
- `--reuse-db` — the test database is not recreated between runs (faster repeat runs); this goes
  together with the `django_db_setup` fixture in `conftest.py`, which does nothing (`pass`) and
  deliberately relies on an already existing test database.
- Test modules live in [netbox_passwork/tests/](../netbox_passwork/tests/); the discovery pattern
  is `tests/test_*.py`.

The test modules and what they cover:

| File | Classes | What it checks |
|---|---|---|
| [test_auth.py](../netbox_passwork/tests/test_auth.py) | `TestLogin`, `TestConfirmTotp`, `TestRefreshIfNeeded`, `TestGetItem`, `TestListVaults`, `TestSearchItems`, `TestClientIsPureHttp`, `TestDecode` | `PassworkAuthClient` on `responses`: login, TOTP (2FA) confirmation, token refresh (including 401/403 from `/sessions/refresh` → session expired), fetching an item, listing vaults, search (including the regression test for URL-encoding the query), absence of Django/local imports and of `disable_warnings()` at import time, `_decode` on a stub response |
| [test_gateway.py](../netbox_passwork/tests/test_gateway.py) | `TestStorageCompatibility`, `TestLogin`, `TestConfirmTotp`, `TestRequireSession`, `TestReadOperations`, `TestListFolderContents`, `TestBuildGateway`, `TestFakeGatewayInterface` | `PassworkGateway` on a dict storage and a client on `responses`: record compatibility with the ≤1.2.x format (a literal Fernet oracle), login/TOTP, refresh and refusals (401/403 from refresh, `InvalidToken`, timeout/non-JSON), reading the record once per gateway, read operations, folder contents (subfolder filtering, search scope, degradation to passwords-only), `build_gateway`, interface parity with `FakeGateway` |
| [test_passwork_view.py](../netbox_passwork/tests/test_passwork_view.py) | `TestDispatchOrder`, `TestPermissionRequiredNone`, `TestRequiresPassworkSessionFalse`, `TestPassworkErrorToJson`, `TestSeam` | The base `PassworkView` ([ADR-0001](adr/0001-passwork-gateway-not-middleware.md)): order of checks (NetBox 401 → 403 → 405 → Passwork 401 → the view method), `OPTIONS` without a Passwork session check, `permission_required = None`, `requires_passwork_session = False`, translation of `PassworkError`/`ApiError` into `{"code","detail"}` |
| [test_proxy.py](../netbox_passwork/tests/test_proxy.py) | `TestSecretsListView`, `TestSecretDetailView`, `TestSecretCopyView`, `TestPassworkLoginView`, `TestPassworkTotpView`, `TestBindingsCreateView`, `TestBindingsDeleteView`, `TestPickerFoldersView`, `TestPickerFolderContentsView`, `TestPickerSearchView` | The largest module — the HTTP views from `views.py`: secret list/detail/copy, login/TOTP, creating and deleting bindings, the picker (search/folders/folder contents). Every gateway-based view (Login/Totp/Detail/Copy/Picker) is tested against `FakeGateway` through the `as_view(gateway_factory=...)` seam: order of checks, gateway calls; the picker returns Passwork 401/403 instead of 200. All errors use the uniform `{"code","detail"}` body |
| [test_binding.py](../netbox_passwork/tests/test_binding.py) | `TestPassworkBindingCreate`, `TestPassworkBindingStr` | The `PassworkBinding` model: creation, hard delete, `__str__` |
| [test_binding_unique.py](../netbox_passwork/tests/test_binding_unique.py) | `TestPassworkBindingUnique` | The binding uniqueness constraint |
| [test_changelog.py](../netbox_passwork/tests/test_changelog.py) | `TestBindingChangelog` | The built-in NetBox changelog: creating/deleting a binding through the full HTTP stack (`django.test.Client`) produces `core.ObjectChange` records; saving outside a request does not |
| [test_audit.py](../netbox_passwork/tests/test_audit.py) | `TestAuditLogView` | `AuditLogView` and the `PassworkAuditLog` model: filters, pagination; `invalid_param` errors use `{"code","detail"}` |
| [test_permissions.py](../netbox_passwork/tests/test_permissions.py) | `TestRequireNetboxPermDecorator`, `TestRequireNetboxPermMixin` | The `require_netbox_perm` decorator and `RequireNetboxPermMixin` (RBAC on top of NetBox `ObjectPermission`); 401/403 refusal bodies use `{"code","detail"}` |
| [test_exceptions.py](../netbox_passwork/tests/test_exceptions.py) | `TestExceptions` | The exception hierarchy: the base `PassworkError` (`code`, `http_status`, `detail`), the defaults of its four subclasses (`PassworkAccessDenied`, `PassworkTimeout`, `PassworkBadResponse`, `PassworkSessionExpired`), contextual `code` override per operation |
| [test_utils.py](../netbox_passwork/tests/test_utils.py) | `TestGetClientIp` | The `get_client_ip()` helper |
| [test_full_flow.py](../netbox_passwork/tests/test_full_flow.py) | `TestFullFlow`, `TestLoginThenSecretsViaGateway`, `TestReleaseScenarioViaGateway` | End-to-end scenarios: tab → lazy load → reveal → `AuditLog` record (Passwork replaced by `FakeGateway`); a full scenario on the real `build_gateway` and `responses`: login (with and without TOTP) → detail/reveal → copy, with both actions audited; `TestReleaseScenarioViaGateway` walks the release scenario on the real `build_gateway`: login → TOTP → list → reveal → copy → picker → binding |
| [test_picker_flow.py](../netbox_passwork/tests/test_picker_flow.py) | `TestPickerFlow`, `TestLoginThenPickerViaGateway` | The picker through the gateway — 401 without a Passwork session or with an expired one, search (`FakeGateway`) → binding creation → database check, duplicate/delete/re-bind; a full scenario on the real `build_gateway` and `responses`: login → vaults/folder contents/search (Bearer/CSRF from the stored session), Passwork 401/403 → 401/403 |
| [test_security.py](../netbox_passwork/tests/test_security.py) | `TestSecurityHardening` | Security-hardening tests |

Fixtures in [conftest.py](../netbox_passwork/tests/conftest.py):

- `grant_netbox_perm(user, action)` — not a pytest fixture but a helper function; grants a user a
  permission through NetBox `ObjectPermission` (the only working way to test the plugin's RBAC
  permissions: `view_secrets`, `reveal_secret`, `add_binding`, `delete_binding`, `view_auditlog`).
- `user`, `other_user` — create Django test users (`User.objects.create_user`).
- `binding` — creates a `PassworkBinding` (`object_type="device"`, `created_by=user`). No
  changelog records appear, because the save happens outside an HTTP request (see
  `test_changelog.py`).
- `django_db_setup` (session scope) — overrides the standard `pytest-django` fixture with a no-op:
  it uses the existing test database instead of recreating it on every run (paired with
  `--reuse-db`).
- `FakeGateway(**outcomes)` — not a pytest fixture but a class; a programmable Passwork gateway for
  view tests with the same eight operations as `PassworkGateway` (interface parity is checked by
  `TestFakeGatewayInterface` in `test_gateway.py`). `outcomes` maps an operation name to its
  result — a value is returned, an exception instance is raised; calls accumulate in `fake.calls`.
- `no_passwork_session()` — a ready-made `PassworkError` ("no record", 401 `pw_not_authenticated`)
  matching what the real gateway raises when there is no Passwork session; convenient as
  `FakeGateway(require_session=no_passwork_session())`.
- `PASSWORK_URL`, `wrap_passwork_response(data)`, `mock_passwork_login(requires_totp=False)` —
  helpers for end-to-end scenarios on the real `build_gateway`: the address of the fake Passwork
  instance, the base64 response wrapper (as Passwork does it) and registration of login responses
  in the active `responses` mock (CSRF → login → users/info; with TOTP, a 401
  `twoFactorAuthRequired` on the probe search). Used by `test_full_flow.py` and
  `test_picker_flow.py`.

### Testing against the gateway

Two seams ([ADR-0001](adr/0001-passwork-gateway-not-middleware.md)), no `unittest.mock`:

- **view ↔ gateway** — `FakeGateway` from `conftest.py`, injected through
  `SomeView.as_view(gateway_factory=lambda request: FakeGateway(...))`; `request.session` can be a
  plain `dict` in these tests; gateway calls are asserted through `fake.calls`; a refusal without a
  Passwork session is `FakeGateway(require_session=no_passwork_session())`.
- **gateway/client ↔ HTTP** — `responses`, with the `PASSWORK_URL`, `wrap_passwork_response()` and
  `mock_passwork_login()` helpers above. The gateway itself (`PassworkGateway`) is built with a
  plain `dict` instead of `request.session` in those tests — the `storage` interface only needs
  `get`/`__setitem__`/`pop`.

Import paths are never monkeypatched in the plugin's tests.

Code coverage — the `[tool.coverage.*]` sections in [pyproject.toml](../pyproject.toml):

```toml
[tool.coverage.run]
source = ["netbox_passwork"]
omit = ["netbox_passwork/tests/*", "netbox_passwork/migrations/*"]

[tool.coverage.report]
fail_under = 85
show_missing = true
```

The minimum coverage threshold is **85%**; tests and migrations are excluded from the count.

---

## 3. JS tests

Frontend tests run through `scripts/test.sh js` (or directly with `npm test`, defined in
[package.json](../package.json)):

```json
"scripts": {
  "test": "node --experimental-vm-modules --test netbox_passwork/tests/js/**/*.test.js"
}
```

The runner is the built-in `node --test`, with no third-party framework. The only dev dependency
is `jsdom` (`^25.0.1`), used to emulate the DOM.

The test files live in [netbox_passwork/tests/js/](../netbox_passwork/tests/js/); each loads
`static/netbox_passwork/passwork.js` into a jsdom environment:

- [xss.test.js](../netbox_passwork/tests/js/xss.test.js) pushes XSS payloads
  (`<img onerror=...>`, `<script>`, attribute injections) through the plugin's rendering
  functions, asserting that values are always treated as text and never as markup.
- [auth_button.test.js](../netbox_passwork/tests/js/auth_button.test.js) checks that the tab
  header switches between the "Bind secret" and "Authenticate" buttons based on the 401 signal
  from the secrets endpoints.
- [picker_explorer.test.js](../netbox_passwork/tests/js/picker_explorer.test.js) checks the
  Explorer-style picker end to end through the fetch seam: vaults render as tree roots, a vault
  click loads its flat folder list and root contents, the chevron expands the tree without
  loading contents, a folder click in the right pane drills down and highlights the folder in
  the tree, breadcrumbs navigate back up, contents are cached for one modal opening, a denied
  vault is marked "no access", a timeout shows a retryable message, and the search block: the
  3-char minimum, flat results with paths, scope via `vault_id`, clearing the box returning to
  the current node, stale responses never rendering, "show in folder", and Bind from results.

---

## 4. Linting

The linter/formatter is `ruff`, configured in [pyproject.toml](../pyproject.toml):

```toml
[tool.ruff]
line-length = 119
target-version = "py311"
exclude = [".venv/", "venv/"]

[tool.ruff.lint]
select = ["E", "F", "W", "I"]
ignore = ["E501"]
```

(`E501` — line too long — is disabled deliberately, while `line-length = 119` is still used by
`ruff format`. `include` is restricted to Python files: otherwise ruff ≥ 0.16 also formats fenced
code blocks in `*.md`.) Run it with `scripts/test.sh lint`.

Pre-commit hooks — [.pre-commit-config.yaml](../.pre-commit-config.yaml):

- `ruff` (`--fix`) and `ruff-format` — from `astral-sh/ruff-pre-commit`
- `trailing-whitespace`, `end-of-file-fixer`, `check-yaml`, `check-merge-conflict`,
  `debug-statements` — from `pre-commit/pre-commit-hooks`

Installation and usage (see [README.md](../README.md)):

```bash
pre-commit install
pre-commit run --all-files
```

### Continuous integration

[.github/workflows/ci.yml](../.github/workflows/ci.yml) runs on every push to `main` and on every
pull request, with four jobs:

| Job | What it runs |
|---|---|
| `ruff` | `scripts/test.sh lint` with `ruff` pinned to the version in `.pre-commit-config.yaml` |
| `JS tests` | `npm install` + `scripts/test.sh js` (node 22, jsdom) |
| `build + twine check` | `python -m build` and `twine check dist/*` — validates the package metadata |
| `pytest` | the full Python suite against a real NetBox, as a matrix of NetBox 4.5/4.6 × Python 3.12/3.14 |

The `pytest` job builds the environment the suite needs: `postgres` and `redis` service containers
(Redis is not optional — `test_changelog.py` goes through the full middleware stack, and NetBox's
`CoreMiddleware` reads its config from the caching Redis), a NetBox checkout at the matrix version
with `testing/configuration.py` in place, and the plugin installed into NetBox's own venv — the
settings module imports every entry of `PLUGINS` before pytest's conftest puts the repository root
on `sys.path`. It then runs `manage.py migrate` explicitly, because `django_db_setup` in
[conftest.py](../netbox_passwork/tests/conftest.py) is a no-op and pytest-django therefore neither
creates nor migrates a database. The job finishes with `makemigrations --check` and `manage.py check`.

Run `scripts/test.sh all` locally before opening a PR anyway and paste its markdown summary into the
PR body, together with `pre-commit` and the release checklist below.

---

## 5. Versioning and releases

The plugin version lives in **exactly one place** — `version = "X.Y.Z"` in
[pyproject.toml](../pyproject.toml). No manual synchronization with other files is needed:

- [netbox_passwork/\_\_init\_\_.py](../netbox_passwork/__init__.py) reads the version at runtime via
  `importlib.metadata.version("netbox-passwork")` (falling back to `"dev"` if the package is not
  installed).
- [netbox_passwork/config.py](../netbox_passwork/config.py) — `PluginConfig` does the same:
  `version = _pkg_version("netbox-passwork")`.

Versioning follows [SemVer](https://semver.org/): **MAJOR** — incompatible changes (configuration,
permissions, migrations that lose data), **MINOR** — new functionality, **PATCH** — fixes. Every
release has a signed `vX.Y.Z` tag and a GitHub Release with notes from `CHANGELOG.md` and the built
sdist/wheel; servers pin a tag (`update.sh vX.Y.Z`).

[CHANGELOG.md](../CHANGELOG.md) follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/):
user-visible changes are recorded under `[Unreleased]` in the same PR that makes them (the rule is
in `CONTRIBUTING.md`); at release time that section becomes `[X.Y.Z] — date`.

### The release process — `scripts/release.sh`

[scripts/release.sh](../scripts/release.sh) splits a release into two steps, compatible with the
"changes reach `main` only through a PR" rule:

1. `scripts/release.sh check` — status: the version in `pyproject.toml`, the latest tag, the top
   CHANGELOG section, the number of entries under `[Unreleased]`, and which step comes next.
2. `scripts/release.sh prepare X.Y.Z` — on a clean, up-to-date `main`: validates SemVer and that
   the version increases, that the tag does not exist and that `[Unreleased]` is not empty; runs
   `scripts/test.sh all` (a failure stops the release); asks for confirmation of the manual
   checklist below; creates the `release/vX.Y.Z` branch, bumps the version in `pyproject.toml`,
   turns `[Unreleased]` into `[X.Y.Z] — date` (leaving an empty `[Unreleased]` on top), commits
   `release: vX.Y.Z`, pushes and opens a PR (the body is the changelog section plus the test
   summary).
3. Review and merge of the release PR — under the normal rules of section 6.
4. `scripts/release.sh publish` — on `main` after the merge: checks that the version in
   `pyproject.toml` matches the top CHANGELOG section and that the tag does not exist yet; builds
   the sdist and wheel (`python -m build`) and validates them (`twine check`); creates a **signed**
   tag `vX.Y.Z` (`git tag -s`, verified with `git tag -v`) and pushes it; creates the GitHub
   Release (`gh release create --verify-tag`) with the notes from the CHANGELOG section and the
   artifacts from `dist/`; uploads the artifacts to PyPI (`twine upload`).
5. Updating servers — `./update.sh vX.Y.Z` (see [README](../README.md#update)).

Flags: `--yes` (skip the checklist prompt), `--no-test` (prepare without running the tests — use
deliberately), `--unsigned` (publish with an annotated instead of a signed tag), `--no-pypi`
(publish without uploading to PyPI). Requirements: a configured `user.signingkey` in git unless
`--unsigned`, an authenticated `gh`, the `build` and `twine` modules from the dev extra
(`PYTHON=...` selects the interpreter explicitly; the default is `venv/bin/python`, otherwise
`python3`), and PyPI credentials in `~/.pypirc` or `TWINE_USERNAME`/`TWINE_PASSWORD` unless
`--no-pypi`.

### Manual checklist before `prepare` (the script does not verify this)

1. All changes for the release are already in `main` through merged PRs.
2. **Live page run (mandatory for any release touching the backend, templates or static files).**
   Install the plugin into a real NetBox and open an object page of every supported type manually —
   **Device**, **Virtual Machine**, **Service** — and confirm that:
   - the page returns `200` and the **Passwork** tab and its badge render without errors (badge and
     `deleted_at` style regressions surface here, not in the API unit tests);
   - if the release contains migrations, `manage.py migrate netbox_passwork` succeeds against a
     database **with realistic data**, not only against an empty one (an empty database skips
     cascade and `RunPython` branches).

   The quick way on a development instance: `manage.py migrate netbox_passwork`, then open
   `/dcim/devices/<id>/`, `/virtualization/virtual-machines/<id>/` and `/ipam/services/<id>/`.
3. After the release PR is merged, refresh `egg-info` on the development machine so that
   `importlib.metadata` reports the new version: `pip install -e . --no-deps --quiet`.

Releases are published locally — the CI workflow deliberately covers checks only. Publishing could
later move into an "on tag push" workflow (with PyPI Trusted Publishing instead of a token) without
changing the rest of the process.

---

## 6. Change process

The rules from [CONTRIBUTING.md](../CONTRIBUTING.md):

- Every feature or fix is developed **in its own branch**; direct commits to `main` are not
  allowed; one task, one branch.
- Branch naming — a short type prefix plus a kebab-case description: `feature/<description>`,
  `fix/<description>`, `docs/<description>`, `chore/<description>` (for example,
  `feature/endpoint-group-create`, `fix/vni-uniqueness`).
- Changes reach `main` only through a pull request.
- **A PR is merged only after an explicit approval.** Merging your own PR without an approving
  review is not allowed. For AI agents this is a hard rule: an agent does not open or merge a PR
  until the maintainer has explicitly confirmed it.
- Before opening a PR: behavioural changes must be covered by tests, the documentation must stay
  consistent with the change, and the PR must not contain unrelated refactoring.

The typical flow:

```bash
git switch -c feature/my-change
# ... changes + tests ...
git commit -m "Concise, imperative summary"
git push -u origin feature/my-change
gh pr create
# ... after an explicit approval ...
gh pr merge --squash
```
