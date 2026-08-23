# netbox-passwork plugin API

The plugin registers its views under the `/plugins/passwork/` prefix (the `base_url =
"passwork"` value in [config.py](../netbox_passwork/config.py)). All routes are declared in
[urls.py](../netbox_passwork/urls.py) and implemented in [views.py](../netbox_passwork/views.py).

Every response is `application/json` (`django.http.JsonResponse`).

## 1. Routes

| Method | Path (relative to `/plugins/passwork/`) | View class | Required permission | Purpose |
|---|---|---|---|---|
| POST | `auth/login/` | `PassworkLoginView` | NetBox authentication only (no Passwork permission check) | Log in to Passwork with a username/password, save the encrypted Passwork session into the Django session |
| POST | `auth/totp/` | `PassworkTotpView` | NetBox authentication only | Confirm the TOTP code for the session obtained at the login step |
| GET | `secrets/` | `SecretsListView` | `view_secrets` (`netbox_passwork.view_secrets_passworkbinding`) | List the Passwork secret bindings for a NetBox object (`object_type`/`object_id`) |
| GET | `secrets/<str:pw_id>/detail/` | `SecretDetailView` | `view_secrets`; additionally `reveal_secret` (`netbox_passwork.reveal_secret_passworkbinding`) if `reveal=true` is passed | Proxy a secret's details from Passwork through the gateway (`PassworkGateway.get_item()`); with `reveal=true`, returns the password and any secret custom field values, and writes an audit log entry |
| POST | `secrets/<str:pw_id>/copy/` | `SecretCopyView` | `reveal_secret` | Record a password copy event in the audit log via the gateway (the password itself is not returned in the response) |
| POST | `bindings/` | `BindingsCreateView` | `add_binding` (`netbox_passwork.add_binding_passworkbinding`) | Create a binding between a Passwork item and a NetBox object |
| DELETE | `bindings/<int:binding_id>/` | `BindingsDeleteView` | `delete_binding` (`netbox_passwork.delete_binding_passworkbinding`) | Delete a binding (hard delete; the event is recorded in NetBox's standard changelog) |
| GET | `picker/folders/` | `PickerFoldersView` | `add_binding` | List Passwork vaults — through the gateway (`PassworkGateway.list_vaults()` → `/api/v1/vaults`) |
| GET | `picker/folders/<str:vault_id>/items/` | `PickerFolderContentsView` | `add_binding` | Direct children of a vault node, or of one of its folders with `?folder_id=...`: `{"folders": [direct subfolders], "items": [direct passwords]}` — through the gateway (`PassworkGateway.list_folder_contents()` → `/api/v1/folders?vaultId=...` + `/api/v1/items?vaultId=...[&folderId=...]`; for the vault node the items are filtered to `folderId=null` — Passwork has no "root only" parameter) |
| GET | `picker/folders/<str:vault_id>/folders/` | `PickerVaultFoldersView` | `add_binding` | The vault's flat folder list for the picker tree, `[{"id", "name", "parentFolderId"}, ...]` — through the gateway (`PassworkGateway.list_vault_folders()` → `/api/v1/folders?vaultId=...`) |
| GET | `picker/search/` | `PickerSearchView` | `add_binding` | Search Passwork items by string, optionally scoped to one vault with `?vault_id=...` — through the gateway (`PassworkGateway.search_items()` → `POST /api/v1/items/search` with the query, and the scope as `vaultIds`, in the JSON body) |
| GET | `audit/` | `AuditLogView` | `view_auditlog` | Audit log of `reveal`/`copy` actions performed on secrets |

Every permission is a standard NetBox object permission on the `PassworkBinding` model,
declared in `Meta.permissions` ([models.py](../netbox_passwork/models.py)) and mapped to short
keys in the `PLUGIN_PERMISSIONS` dictionary ([permissions.py](../netbox_passwork/permissions.py)).
The check is performed by `RequireNetboxPermMixin.dispatch()`, which is applied to every view
except `PassworkLoginView` and `PassworkTotpView`.

## 2. Request parameters

### `secrets/`, `secrets/<pw_id>/detail/`, `secrets/<pw_id>/copy/`

- `object_type` (query, string) — the type of NetBox object the secret is bound to. Required for all three views.
  - In `SecretsListView`, `SecretDetailView`, and `SecretCopyView` the value is **not** validated against `PassworkBinding.OBJECT_TYPE_CHOICES` — it's used as-is in the `PassworkBinding.objects.filter(...)` lookup.
- `object_id` (query, integer) — required; a parse failure (`int(...)` raises) returns `400 invalid_object_id`.
- `reveal` (query, `SecretDetailView` only) — `reveal=true` (case-insensitive) turns on revealing the password and secret custom fields, and requires the `reveal_secret` permission; any other value (including the parameter being absent) behaves as if reveal were off.

### `bindings/` (POST)

Request body — JSON:

- `object_type` (string, required) — **is** validated against `PassworkBinding.OBJECT_TYPE_CHOICES` (`device`, `vm`, `service`); a mismatch returns `400 invalid_object_type`.
- `object_id` (required, any non-empty/non-zero value — checked via `all([...])`).
- `passwork_item_id` (string, required).

### `audit/`

- `user` — filters by `netbox_user_id`; parsed via `_parse_int`, a non-numeric value returns `400 invalid_param` (`param: "user"`).
- `action` — filters by a value from `PassworkAuditLog.ACTION_CHOICES` (`reveal`/`copy`).
- `pw_id` — filters by `passwork_item_id`.
- `limit`, `offset` — pagination (see below).

### `picker/search/`

- `q` (query, string, required) — the search string; an empty value returns `400 missing_query`. This
  check happens **after** the Passwork session check: with no session the view responds `401`, not
  `400`. The view passes `q` through as-is (after `strip()`); the client sends it to Passwork in
  the POST body (`PassworkAuthClient.search_items`), so no URL encoding is involved.
- `vault_id` (query, string, optional) — scope the search to one vault; a blank value means a
  global search. Becomes a one-element `vaultIds` list in the Passwork request body.

### Pagination (`limit`/`offset` in `audit/`)

Parsed by `_parse_int(value, default, min_val=0)`:

- A missing parameter falls back to the default (`limit=50`, `offset=0`).
- A non-numeric value makes `_parse_int` return `None`, and the view responds `400 invalid_param` (`param: "limit or offset"`).
- `limit < 1` (including negative values) is checked separately after parsing and responds `400 invalid_param` (`param: "limit"`). This means a negative `limit` is explicitly rejected rather than silently clamped to `0`.
- `limit` is capped from above at `min(limit, 500)`.
- `offset` has no upper bound; `_parse_int` clamps negative values to `min_val=0` (not an error).

## 3. Error format

As of v1.3.0, **every** plugin API error is returned as JSON of the form
`{"code": "...", "detail": "..."}` — the `detail` field is always present (a human-readable
message), and the `status`/`param` fields no longer appear in the error body. Successful
response bodies are unchanged.

| HTTP | code | Returned by | `detail` |
|---|---|---|---|
| 400 | `invalid_json` | `PassworkLoginView`, `PassworkTotpView`, `BindingsCreateView` | `Request body must be a JSON object` |
| 400 | `missing_credentials` | `PassworkLoginView` | `Username and password are required` |
| 400 | `missing_code` | `PassworkTotpView` | `TOTP code is required` |
| 400 | `missing_params` | `SecretsListView` | `object_type and object_id are required` |
| 400 | `missing_params` | `BindingsCreateView` | `object_type, object_id and passwork_item_id are required` |
| 400 | `invalid_object_id` | `SecretsListView`, `SecretDetailView`, `SecretCopyView` | `object_id must be an integer` |
| 400 | `invalid_object_type` | `BindingsCreateView` | `object_type must be one of: device, vm, service` |
| 400 | `missing_query` | `PickerSearchView` | `Query parameter q is required` |
| 400 | `invalid_param` | `AuditLogView` | `user must be an integer` / `limit and offset must be integers` / `limit must be >= 1` |
| 401 | `not_authenticated` | every view (`RequireNetboxPermMixin` check) | `Authentication required` |
| 401 | `pw_not_authenticated` | every view via the gateway (`PassworkGateway.require_session()`) | `Passwork session not found` (or `Passwork session could not be decrypted`, if `SESSION_ENCRYPT_KEY` has changed) |
| 401 | `pw_session_expired` | every view via the gateway | text from the client/gateway exception, e.g. `Refresh token rejected` or `Token expired or TOTP required for /api/v1/...` |
| 401 | `invalid_credentials` | `PassworkLoginView` | `Invalid credentials` (or `CSRF error: …`, if Passwork already refused to issue a CSRF token — text from the client exception) |
| 401 | `invalid_totp` | `PassworkTotpView` | `Invalid TOTP code` |
| 403 | `netbox_permission_denied` | every view with a required permission; `SecretDetailView` — separately, when `reveal=true` without `reveal_secret` | `Permission denied` |
| 403 | `pw_access_denied` | `SecretDetailView` (`get_item`), `PickerFoldersView`/`PickerVaultFoldersView`/`PickerSearchView` | `Access denied for /api/v1/...` |
| 404 | `binding_not_found` | `SecretDetailView`, `SecretCopyView`, `BindingsDeleteView` | `Binding not found` |
| 405 | — | `PassworkView`: unsupported method (a plain Django `HttpResponseNotAllowed` response with an `Allow` header, no JSON body) | — |
| 409 | `duplicate_binding` | `BindingsCreateView` | `Binding already exists` |
| 502 | `pw_bad_response` | every view via the gateway | `Passwork returned a non-JSON response` |
| 504 | `pw_timeout` | every view via the gateway | text from the exception, e.g. `GET /api/v1/... timed out` or `Token refresh timed out` |

Additional notes:

- **502** `pw_bad_response` and **504** `pw_timeout` correspond to the `PassworkBadResponse`/
  `PassworkTimeout` exceptions from [exceptions.py](../netbox_passwork/exceptions.py) and are
  caught in `PassworkView.dispatch` ([views.py](../netbox_passwork/views.py)) for every view
  that talks to Passwork.
- `PassworkSessionExpired` (**401** `pw_session_expired`) is raised in
  `PassworkGateway.require_session()`/`_load()` ([gateway.py](../netbox_passwork/gateway.py))
  when the refresh token has expired, or when Passwork responded to
  `/api/v1/sessions/refresh` with **401 or 403** (both are treated as a refused token refresh,
  and the Passwork session record is deleted in that case), and also when the actual data
  request (`get_item`/`list_vaults`/`search_items`) got a 401 from Passwork (in that case the
  record is not deleted — the session is assumed to still be alive, but that particular
  request's token was rejected).
- `PassworkAccessDenied` maps to **401** during login/TOTP (`invalid_credentials`/
  `invalid_totp` — the operation overrides the context) and to **403** (`pw_access_denied`)
  when accessing a secret or the picker (`SecretDetailView`, `PickerFoldersView`/
  `PickerVaultFoldersView`/`PickerSearchView`) — depending on the calling context.

## 4. Authentication

- Every view except `PassworkLoginView` and `PassworkTotpView` requires:
  1. An authenticated NetBox user (`request.user.is_authenticated`) — otherwise `401 not_authenticated` (`RequireNetboxPermMixin.dispatch`).
  2. The user holding the corresponding NetBox object permission — otherwise `403 netbox_permission_denied`.
  3. For views that talk to Passwork (`PassworkLoginView`, `PassworkTotpView`, `SecretDetailView`, `SecretCopyView`, `PickerFoldersView`, `PickerFolderContentsView`, `PickerVaultFoldersView`, `PickerSearchView`) — a valid Passwork session in the Django session (`request.session["pw_session"]`, except for `PassworkLoginView`, which doesn't need one yet). All of them go through the base `PassworkView` (ADR-0001), and `dispatch` runs the same sequence of checks every time: NetBox permissions → 405 for an unsupported method (`OPTIONS` doesn't require a Passwork session) → Passwork session (`self.gateway.require_session()`, via `PassworkGateway`) → the view method's own parameters/body. Passwork failures (`PassworkError`) are turned into `{"code","detail"}` at the same point. A missing or expired Passwork session results in a `401` (`pw_not_authenticated`/`pw_session_expired`).
- `PassworkLoginView` and `PassworkTotpView` only require an authenticated NetBox user — `PassworkLoginView` doesn't need a Passwork session yet; `PassworkTotpView` only expects the `pw_session` obtained at the login step, so it can continue the flow.
- The plugin does not disable Django's standard CSRF protection (there's no `csrf_exempt` anywhere in the code), so every `POST`/`DELETE` request (`auth/login/`, `auth/totp/`, `secrets/<pw_id>/copy/`, `bindings/`, `bindings/<id>/`) requires a valid CSRF token, the same as any other request within NetBox.
- The Passwork session itself (access/refresh tokens, Passwork's CSRF token) is stored in the Django session in encrypted form — encryption/decryption is handled by `PassworkGateway` ([gateway.py](../netbox_passwork/gateway.py)) using the `SESSION_ENCRYPT_KEY` from the plugin configuration; the client (`PassworkAuthClient`) has no involvement in session encryption.

## 5. Serializers

Defined in [serializers.py](../netbox_passwork/serializers.py):

- **`PassworkBindingSerializer`** (a `ModelSerializer` for `PassworkBinding`) — used in `BindingsCreateView`'s response (201), and also re-exported by [api/serializers.py](../netbox_passwork/api/serializers.py) for the NetBox events pipeline (following the `<plugin>.api.serializers.<Model>Serializer` convention). Fields: `id`, `object_type`, `object_id`, `passwork_item_id`, `created`, `created_by`; `id`, `created`, and `created_by` are read-only.
- **`SecretListItemSerializer`** — an auxiliary serializer (`pw_id`); the actual `SecretsListView` response is built by hand as a list of `{"pw_id": ..., "binding_id": ...}` dicts, not through this serializer directly.
- **`CustomFieldSerializer`** — describes a `custom_fields` entry (`name`, `value`, `is_secret`); used as a data shape that `SecretDetailView` assembles by hand (`name`, `is_secret`, `type`, `value`).
- **`SecretDetailSerializer`** — describes the shape of `SecretDetailView`'s response: `pw_id`, `name`, `login`, `description`, `password` (only when `reveal=true`), `custom_fields`, `passwork_url`. This response is also built by hand rather than via this serializer's `.data`.
- **`AuditLogSerializer`** (a `ModelSerializer` for `PassworkAuditLog`) — used in `AuditLogView`. Fields: `id`, `timestamp`, `netbox_user` (a string representation via `StringRelatedField`), `passwork_item_id`, `object_type`, `object_id`, `action`, `ip_address`.

The `AuditLogView` response is wrapped for pagination: `{"count": <total records>, "results": [...]}`.
