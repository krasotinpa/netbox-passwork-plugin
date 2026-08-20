# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).
User-visible changes are added under `[Unreleased]` in the PR that makes them;
`scripts/release.sh prepare X.Y.Z` turns that section into `[X.Y.Z] — date` (see `docs/development.md` §5).

## [Unreleased]

### Added
- README: a Screenshots section walking through the plugin — the Passwork tab, the secret picker asking for a login, the login and two-factor modals, and the secrets of a bound object

### Added
- CI runs the Python test suite against a real NetBox (PostgreSQL + Redis service containers, matrix of NetBox 4.5/4.6 × Python 3.12/3.14), plus `makemigrations --check` and `manage.py check`
- `testing/configuration.py` — a ready-made NetBox configuration for running the test suite, used by CI and usable locally
- README: a compatibility matrix (plugin ↔ NetBox ↔ Python), the runtime dependency list, a Support section (where to report bugs, how to report a vulnerability privately) and a plugin icon (`docs/img/icon.svg`, CC BY 4.0)

### Changed
- **Breaking:** `requires-python` is now `>=3.12`, matching NetBox 4.5+, which does not run on Python 3.11

### Fixed
- README: the minimum PostgreSQL version is 14, as required by NetBox 4.5 (13 was stated)
- Secrets tab: with no active Passwork session the header button now reads "Authenticate" and opens the login modal directly, instead of "Bind secret" leading into a picker that can only fail with 401; after a successful login (including TOTP) it switches back to "Bind secret"

## [1.3.1] — 2026-08-19

### Fixed
- The wheel no longer ships `netbox_passwork/tests` (it was pulled in as package data despite the `packages.find` exclusion, which also produced a setuptools warning during the build)

## [1.3.0] — 2026-08-19

### Changed
- **All plugin API errors now share one body format `{"code", "detail"}`** — the remaining endpoints (`GET secrets/`, `POST bindings/`, `DELETE bindings/<id>/`, `GET audit/`) and the NetBox permission checks (`not_authenticated` / `netbox_permission_denied`) were aligned with the Passwork-facing ones: `detail` is always present, the extra `param` field of `invalid_param` (audit filters/pagination) is folded into `detail`, `status: "error"` is gone. Values of `code`, routes and successful bodies are unchanged
- Passwork-facing endpoints (login/TOTP/detail/copy/picker) answer `405 Method Not Allowed` for an unsupported HTTP method before touching the Passwork session (previously `401` without a session), and `OPTIONS` no longer requires a Passwork session
- Picker endpoints (`GET picker/folders/`, `GET picker/search/`) now go through the Passwork gateway like the other Passwork-facing views: a Passwork 401 in the picker returns HTTP 401 `pw_session_expired` and a Passwork 403 returns HTTP 403 `pw_access_denied` instead of HTTP 200 with an empty list; error bodies are uniform `{"code", "detail"}` (`missing_query` gained a `detail`), successful bodies (arrays of vaults / items) are unchanged
- Secret detail (`GET secrets/<pw_id>/detail/`) and copy (`POST secrets/<pw_id>/copy/`) endpoints now go through the Passwork gateway (like login/TOTP): the order of checks is unchanged (NetBox permission → `reveal_secret` for `reveal=true` → Passwork session → parameters → binding → Passwork → audit), error bodies are uniform `{"code", "detail"}` (`invalid_object_id` and `binding_not_found` gained a `detail`), successful bodies are unchanged
- Package metadata (`pyproject.toml`): author, PEP 639 license expression, project URLs; tests are no longer shipped in the wheel
- **First public release.** The project is now open source under Apache-2.0; the documentation in `docs/`, the code comments and the helper scripts are in English

### Added
- `LICENSE` (Apache-2.0) and a License section in README
- Published on PyPI: `pip install netbox-passwork`; `update.sh` now upgrades from PyPI by default
- GitHub Actions CI (`.github/workflows/ci.yml`): ruff, the JS tests and a package build/`twine check` on every push to `main` and every pull request (the Python tests still run locally — they need a NetBox installation)
- Issue and pull request templates (`.github/ISSUE_TEMPLATE/`, `.github/PULL_REQUEST_TEMPLATE.md`) and CI/license badges in the README
- `scripts/test.sh` — single entry point for lint / Python tests / JS tests with a markdown summary for PRs; `scripts/release.sh` — release preparation (release PR) and publishing (signed tag, sdist/wheel, GitHub Release)

### Fixed
- Changing `SESSION_ENCRYPT_KEY` no longer leaves users with a permanent `401`: a Passwork session record that cannot be decrypted is dropped (with a warning in the log) and the user is asked to log in to Passwork again (`401 pw_not_authenticated`); unexpected exceptions while reading the Passwork session are no longer masked as `401`
- A `403` from Passwork on token refresh (`/sessions/refresh`) is treated like `401` — the Passwork session is dropped and the client gets `401 pw_session_expired` — instead of being silently accepted as a successful refresh

### Removed
- Unused `passwork-python` dependency (the plugin uses its own `requests`-based client; `requests` is now declared explicitly) and the stale `requirements.txt` — dev dependencies live only in `[project.optional-dependencies].dev`
- Internal modules/helpers superseded by the Passwork gateway: `netbox_passwork/middleware.py` (`PassworkSessionMiddleware` mixin), the Fernet helpers in `utils.py` (`fernet_encrypt`/`fernet_decrypt`), and `PassworkAuthClient.encrypt_session`/`decrypt_session` together with its `session_encrypt_key` constructor argument. No configuration change is required (`MIDDLEWARE` was never touched); existing Passwork sessions stay valid after the upgrade — the session record format is unchanged

### Internal
- **Passwork gateway** (`netbox_passwork/gateway.py`, see [ADR-0001](docs/adr/0001-passwork-gateway-not-middleware.md)): one deep module owns the Passwork session (reading/decrypting/refreshing/encrypting/writing it in the Django session, the only place that reads the plugin config and the only Fernet implementation) and exposes six operations (`login`, `confirm_totp`, `get_item`, `list_vaults`, `search_items`, `require_session`); Passwork refusals are raised as `PassworkError` subclasses carrying `code`/`http_status`/`detail`. All Passwork-facing views inherit one base `PassworkView` (NetBox permission → 405 → gateway → Passwork session → method → `PassworkError`/`ApiError` → JSON error). The HTTP client (`passwork_client.py`) no longer depends on Django (everything via the constructor) and gained public `list_vaults`/`search_items`; `urllib3.disable_warnings()` is called only when SSL verification is off. Within one request the Passwork session record is read and decrypted once. This also removed the duplicated Fernet implementation, the repeated local `import json` calls and the unconditional `urllib3.disable_warnings()` at import time
- Tests: the gateway is swapped in views through one explicit seam (`as_view(gateway_factory=...)`, `FakeGateway` in `conftest.py`); no `unittest.mock` left in the plugin tests (only `responses` for HTTP); new end-to-end release scenario on the real gateway (login → TOTP → list → reveal → copy → picker → binding) and a compatibility test for session records written by ≤ 1.2.x

## [1.2.0] — 2026-07-07

### Changed
- Change Log entries for Passwork bindings are now human-readable. The *Object* column shows the linked Device / VM / Service name (hyperlinked to that object's page) instead of the technical `object_type:object_id`, and `created_by` in the Pre-/Post-Change Data snapshots renders as `<username> (<id>)` instead of a raw user id. Implemented entirely on `PassworkBinding` (`_resolved_object`, `get_absolute_url`, `serialize_object`, `__str__`) — no NetBox core changes and no migration. Applies to new changelog records; existing immutable snapshots are unchanged

### Added
- Tests for the resolved object name, `get_absolute_url`, and the `created_by` snapshot format (`test_binding.py`, `test_changelog.py`)

## [1.1.2] — 2026-07-06

### Fixed
- Opening any Device / VM / Service page crashed with `FieldError: Cannot resolve keyword 'deleted_at' into field` — the Passwork tab badge (`_passwork_badge` in `template_extensions.py`) still filtered on the `deleted_at` field removed in 1.1.0. Removed the stale filter. Added regression tests covering the badge (`test_badge.py`), which is invoked on every object page render but was not previously exercised by the test suite

## [1.1.1] — 2026-07-06

### Fixed
- Migration `0003_changelog` crashed with `UndefinedTable: relation "netbox_passwork_passworkbindinghistory" does not exist` when the database contained soft-deleted bindings. The purge step used the ORM `.delete()`, whose cascade collector queried the `PassworkBindingHistory` PROTECT relation after the table had already been dropped one step earlier. Replaced with a direct SQL `DELETE`, which bypasses the collector. No schema change — the end state is identical; only databases with soft-deleted rows were affected (the failed migration rolled back atomically, so re-running the fixed version applies cleanly)

## [1.1.0] — 2026-07-06

### Changed
- **Breaking:** binding history moved to the standard NetBox changelog (`core.ObjectChange`). `PassworkBinding` now inherits `ChangeLoggedModel`; create/delete events are recorded automatically with user, request ID and pre/post-change snapshots. View them under Operations → Change Log (subject to `CHANGELOG_RETENTION`, 90 days by default; client IP is not recorded)
- **Breaking:** binding deletion is now a hard delete (soft-delete fields `deleted_at`/`deleted_by` removed); the pre-delete snapshot is preserved in the changelog entry
- `PassworkBinding.created_at` renamed to `created` (values preserved); `last_updated` added
- Unique constraint and object index on `PassworkBinding` are now unconditional (`pb_unique_binding`, `pb_object_idx`)

### Removed
- **Breaking:** `PassworkBindingHistory` model and its table (migration `0003` drops the table and purges soft-deleted bindings — irreversible without a DB backup; existing history records are not migrated)
- **Breaking:** `GET /plugins/passwork/bindings/history/` endpoint, `BindingHistoryView`, `BindingHistorySerializer`
- "Binding history" panel on the Passwork tab (use the NetBox changelog instead)
- `signals.py` (`record_binding_history` post_save handler) and the `_current_user`/`_current_ip`/`tracker_*` instance-attribute convention

### Added
- `netbox_passwork.api.serializers` module (re-exports `PassworkBindingSerializer`) — required by the NetBox events pipeline for change-logged models
- Tests for changelog integration (`test_changelog.py`)

## [1.0.14] — 2026-06-24

### Fixed
- Validate `limit`/`offset` query params in AuditLogView and BindingHistoryView; return 400 on non-integer input
- Validate `object_type` against allowed choices in BindingsCreateView; return 400 on unknown type
- Remove Passwork access token prefix from debug log in `get_item`
- Catch `PassworkTimeout` in `PassworkTotpView`; return 504 instead of 500
- Raise `PassworkBadResponse` on non-JSON response from Passwork API instead of unhandled exception

## [1.0.13] — 2026-06-24

### Security
- Fix query parameter injection in PickerSearchView: URL-encode `q` before inserting into Passwork API path
- Fix client IP spoofing via X-Forwarded-For: take rightmost IP set by nginx instead of leftmost

## [1.0.12] — 2026-06-24

### Security
- Fix stored/reflected XSS in `passwork.js`: replace `innerHTML` string
  concatenation with safe DOM API (`createElement` / `textContent`) in
  `pwAddDetailRow`, `pwRevealSecret`, `pwRenderPickerSecrets`, `pwLoadHistory`
- Fix secret value exposure in inline `onclick` attributes: buttons now
  use `addEventListener`; values held in closures, never embedded in markup
- Reject `javascript:` scheme in Passwork URLs via new `safeLink()` helper
- Fix broken `escapedName` no-op escape for custom field names with quotes
- Add JS security test suite: 11 XSS tests with jsdom (`netbox_passwork/tests/js/`)

## [1.0.0] — 2026-06-09

### Added
- Passwork tab on Device, Virtual Machine, and Service pages
- Login modal with TOTP (2FA) support — 6-digit auto-submit input
- Lazy loading of secret metadata
- Reveal / Hide password with configurable auto-hide timer
- Copy to clipboard with HTTP fallback
- Bind secret via folder/search picker
- Unbind with soft-delete (history preserved)
- Binding history panel with pagination
- Audit log for all reveal/copy actions
- NetBox RBAC integration via ObjectPermission
- Fernet encryption of Passwork tokens in Django session
- Proxy endpoint with binding validation (prevents arbitrary secret access)
- Django Admin read-only views for PassworkBinding, BindingHistory, AuditLog
- 97 tests, coverage ≥ 85% on core modules
