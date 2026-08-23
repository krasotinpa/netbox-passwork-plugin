# netbox-passwork Architecture

## 1. Overview

`netbox-passwork` is a NetBox plugin that embeds the **Passwork** password manager into object
tabs on `dcim.Device`, `virtualization.VirtualMachine`, and `ipam.Service`. The plugin does not
store the secrets themselves (passwords, custom fields) in the NetBox database — it acts as a
**proxy layer** between the browser and the Passwork REST API v1, and only keeps in its own
database:

- bindings of secrets to NetBox objects (which `passwork_item_id` belongs to which
  device/VM/service) — the [`PassworkBinding`](../netbox_passwork/models.py) model;
- an audit log of secret access (reveal/copy) — [`PassworkAuditLog`](../netbox_passwork/models.py).

Binding change history (creation/deletion) is kept in NetBox's standard changelog
(`core.ObjectChange`): `PassworkBinding` inherits `ChangeLoggedModel`, and entries are
created automatically by NetBox core signals (see [data-model.md](data-model.md)).

Data flow:

```
Browser (passwork.js)
   │  fetch() → /plugins/passwork/...  (JSON, CSRF, X-CSRFToken)
   ▼
Plugin Django views (netbox_passwork/views.py)
   │  NetBox permission check (RequireNetboxPermMixin) + binding check (PassworkBinding);
   │  405 for unsupported methods
   ▼
PassworkView.dispatch() → PassworkGateway (netbox_passwork/gateway.py)
   │  eight operations (login/confirm_totp/get_item/list_vaults/search_items/list_folder_contents/list_vault_folders/require_session);
   │  Passwork session from request.session: decryption, refreshing the token if needed;
   │  the Passwork session read once is reused for the rest of the request
   ▼
PassworkAuthClient (netbox_passwork/passwork_client.py)
   │  HTTPS requests in X-Browser-Mode: X-Browser-Mode, X-CSRF-Token, Bearer token
   ▼
Passwork REST API v1 (external server, configured via PASSWORK_URL)
```

Authentication against Passwork happens separately, on behalf of the NetBox user
(login/password/TOTP through modal dialogs). The result is a set of Passwork tokens
(`access_token`, `refresh_token`, `csrf_token`), which the **gateway encrypts and decrypts**
(`PassworkGateway`, [`gateway.py`](../netbox_passwork/gateway.py)) with Fernet using the
[`SESSION_ENCRYPT_KEY`](../netbox_passwork/config.py) key, and stores in the current NetBox
user's Django session (`request.session["pw_session"]`), not in the NetBox database. This makes
the plugin itself, on the server side, a thin proxy that checks permissions and writes audit
records — all actual secret handling (decrypting the password, building requests) happens
directly against Passwork.

## 2. Plugin modules (`netbox_passwork/*.py`)

| File | Role |
|---|---|
| [`__init__.py`](../netbox_passwork/__init__.py) | Django app entry point: exports `config = NetboxPassworkConfig` for the NetBox plugin loader, and defines `__version__` via `importlib.metadata.version("netbox-passwork")`. |
| [`config.py`](../netbox_passwork/config.py) | `NetboxPassworkConfig(PluginConfig)` — plugin metadata (`base_url = "passwork"`, `min_version = "4.5"`), `required_settings = ["PASSWORK_URL", "SESSION_ENCRYPT_KEY"]`, `default_settings` (`PASSWORK_VERIFY_SSL=True`, `TOKEN_REFRESH_MARGIN=60`, `PASSWORK_REQUEST_TIMEOUT=5`, `SECRET_REVEAL_TIMEOUT=30`). Its `ready()` calls `_register_views()` from `template_extensions.py`, wiring up the "Passwork" tab on NetBox models at application startup. |
| [`models.py`](../netbox_passwork/models.py) | Django models: `PassworkBinding` (inherits NetBox's `ChangeLoggedModel` — change history goes into the standard changelog; links a NetBox object to a `passwork_item_id`, with a uniqueness constraint on the binding and custom permissions `view_secrets`/`reveal_secret`/`add_binding`/`delete_binding`/`view_auditlog` in `Meta.permissions`), and `PassworkAuditLog` (a log of reveal/copy events — who, when, which secret, from which IP). Neither model stores actual Passwork secrets (passwords, field values). |
| [`views.py`](../netbox_passwork/views.py) | Django `View` classes serving the JSON API under `/plugins/passwork/...`. The base `PassworkView` (`RequireNetboxPermMixin` + gateway, ADR-0001) drives `dispatch`: NetBox permissions → 405 for an unsupported method → gateway (`self.gateway`) → Passwork session (except for `OPTIONS`) → the view's method → `PassworkError`/`ApiError` → JSON `{"code","detail"}`. Built on it: `PassworkLoginView`/`PassworkTotpView` (Passwork login and TOTP confirmation), `SecretDetailView` (secret details/reveal — checks the binding and the `reveal_secret_passworkbinding` permission, writes a `PassworkAuditLog` entry when `reveal=true`), `SecretCopyView` (audits a copy without returning any data), `PickerFoldersView`/`PickerFolderContentsView`/`PickerVaultFoldersView`/`PickerSearchView` (list vaults, list a node's direct children, list a vault's flat folder tree, and search secrets — optionally scoped to one vault — through the gateway: `list_vaults()`/`list_folder_contents()`/`list_vault_folders()`/`search_items()` — for the picker modal). Separately (without the gateway): `SecretsListView` (list of an object's bound secrets), `BindingsCreateView`/`BindingsDeleteView` (creating and hard-deleting bindings; events are written to the standard NetBox changelog), `AuditLogView` (paginated audit log listing, page size capped at 500). The module also defines `ApiError(code, detail, http_status)` — a plugin-level API failure (invalid parameters, missing binding), which `PassworkView.dispatch` turns into JSON the same way as `PassworkError` — plus the helpers `_error`/`_json_body`/`_text`/`_reveal_requested`/`_object_id`/`_bound_object`/`_parse_int`. |
| [`urls.py`](../netbox_passwork/urls.py) | Django `urlpatterns`, mounted by NetBox under `/plugins/passwork/` (`base_url` from `config.py`): the `auth/`, `secrets/`, `bindings/`, `picker/`, and `audit/` groups. |
| [`gateway.py`](../netbox_passwork/gateway.py) | `PassworkGateway` — the single point through which the plugin talks to Passwork on behalf of a Passwork session (ADR-0001): the only place that reads the plugin config, the only place that encrypts/decrypts the three Passwork session fields with Fernet (`access_token`, `refresh_token`, `csrf_token`), reads/writes/deletes the `pw_session` record in storage (in production, `request.session`), and refreshes the access token with `TOKEN_REFRESH_MARGIN` taken into account. Eight operations: `login()`, `confirm_totp()`, `get_item()`, `list_vaults()`, `search_items()`, `list_folder_contents()`, `list_vault_folders()`, `require_session()`. `build_gateway(request)` is the single composition point (assembling `PassworkAuthClient` + reading `PLUGINS_CONFIG["netbox_passwork"]`). Failures are raised as `PassworkError` with a `code`/`http_status`. The Passwork session record is read from storage (and refreshed if needed) once per HTTP request and reused by every gateway operation within that request. |
| [`permissions.py`](../netbox_passwork/permissions.py) | `PLUGIN_PERMISSIONS` — maps short permission keys (`view_secrets`, `reveal_secret`, `add_binding`, `delete_binding`, `view_auditlog`) to the full NetBox permission codenames of the form `netbox_passwork.<perm>_passworkbinding` (all custom permissions are physically declared on the `PassworkBinding` model). `require_netbox_perm()` is a decorator for function-based views, and `RequireNetboxPermMixin` is a mixin for class-based views that checks `request.user.is_authenticated` and `request.user.has_perm(...)` in `dispatch()`, returning 401/403 in the same `{"code","detail"}` format. |
| [`passwork_client.py`](../netbox_passwork/passwork_client.py) | `PassworkAuthClient` — an HTTP client for the Passwork REST API v1 built on `requests.Session`, running in `X-Browser-Mode: 1` (no Client-Side Encryption). A plain implementation with no Django dependency: the base URL, SSL verification, timeout, and refresh margin are all passed through the constructor; `urllib3.disable_warnings()` is only called when `verify_ssl=False`. Methods: `login()` (CSRF token → `/api/v1/users/login` → checks whether TOTP is required via `/api/v1/users/info` and a test request), `confirm_totp()`, `refresh_if_needed()` (refreshes the access token via `/api/v1/sessions/refresh`, or raises `PassworkSessionExpired` if the refresh token has expired or was rejected), `get_item()` (fetches a secret from `/api/v1/items/{pw_id}`, decodes `passwordEncrypted`/`customs` from base64, and flags `is_secret` for `password`/`totp` field types), plus the public picker operations `list_vaults()` (`/api/v1/vaults`), `list_folder_contents()` (`/api/v1/folders?vaultId=...` for subfolders, filtered by `parentFolderId`, + `/api/v1/items?vaultId=...[&folderId=...]` for the passwords, filtered to `folderId=null` for the vault node — plain listing endpoints, Api reference §11.5/§13.6, not the text search), `list_vault_folders()` (`/api/v1/folders?vaultId=...` — the flat folder list for the picker tree) and `search_items()` (`POST /api/v1/items/search` with the query and the optional `vaultIds` scope in the JSON body; ids in URLs are URL-encoded; 401 → `PassworkSessionExpired`, 403 → `PassworkAccessDenied`). The module has nothing to do with session encryption (that's `PassworkGateway`'s job) and does not import `cryptography`. It catches `requests.Timeout` and raises `PassworkTimeout`, and `_decode()` is the shared response JSON parser that raises `PassworkBadResponse` for a non-JSON body. |
| [`serializers.py`](../netbox_passwork/serializers.py) | DRF serializers: `PassworkBindingSerializer` (for the `PassworkBinding` model), `SecretListItemSerializer`/`CustomFieldSerializer`/`SecretDetailSerializer` (shape the Passwork secret data, not tied to any DB model — the secret is never persisted), and `AuditLogSerializer` (for `AuditLogView`). |
| [`api/serializers.py`](../netbox_passwork/api/serializers.py) | Re-exports `PassworkBindingSerializer` following the NetBox convention `<plugin>.api.serializers.<Model>Serializer`, which the NetBox events pipeline (webhooks/event rules) looks up when serializing a change-logged object. |
| [`utils.py`](../netbox_passwork/utils.py) | `get_client_ip(request)` — extracts the real client IP from `X-Forwarded-For`, taking the **rightmost** address in the chain (`forwarded_for.split(",")[-1].strip()`), which protects against a client spoofing its IP by injecting fake addresses at the front of the header, provided the nearest proxy is trusted. The module contains nothing else: the Fernet helpers (`_get_fernet`/`fernet_encrypt`/`fernet_decrypt`) that used to duplicate session encryption inside `PassworkAuthClient` were removed in v1.3.0 as part of the move to the Passwork gateway. |
| [`exceptions.py`](../netbox_passwork/exceptions.py) | A hierarchy of domain exceptions with no dependency on Django/DRF. The base `PassworkError` carries `code`, `http_status`, `detail` (ADR-0001); subclasses set the defaults: `PassworkSessionExpired` (`pw_session_expired`/401 — the refresh token expired or was rejected, a fresh login is required), `PassworkAccessDenied` (`pw_access_denied`/403 — Passwork returned a 403; during login/TOTP the operation overrides this with a contextual `invalid_credentials`/`invalid_totp` code and 401), `PassworkTimeout` (`pw_timeout`/504 — the request exceeded `PASSWORK_REQUEST_TIMEOUT`), `PassworkBadResponse` (`pw_bad_response`/502 — Passwork's response wasn't JSON, e.g. a reverse-proxy's HTML error page). These are caught in `PassworkView.dispatch` ([views.py](../netbox_passwork/views.py)) and mapped to HTTP statuses (401/403/504/502). |
| [`admin.py`](../netbox_passwork/admin.py) | Django admin — registers `PassworkBinding` and `PassworkAuditLog`. Both `ModelAdmin` classes are strictly **read-only**: `has_add_permission`, `has_change_permission`, and `has_delete_permission` all return `False`, and every field is listed in `readonly_fields`. Changes are only possible through the plugin's API — this guarantees that binding creation/deletion events always go through an HTTP request and get recorded in the NetBox changelog. |
| [`template_extensions.py`](../netbox_passwork/template_extensions.py) | Registers the "Passwork" tab on NetBox models: `PassworkTabMixin` (a shared `ViewTab` with `label="Passwork"`, a badge showing the number of active bindings via `_passwork_badge()`, `weight=1500`, `hide_if_empty=False`) and `_register_views()`, called from `config.ready()`. The module exports an empty `template_extensions = []` — the plugin's NetBox extensions are implemented not through `PluginTemplateExtension` but through `register_model_view` (see section 3). |

## 3. Tab registration on NetBox objects

The tab is wired up by the `_register_views()` function in
[`template_extensions.py`](../netbox_passwork/template_extensions.py), called once at
application startup from `NetboxPassworkConfig.ready()` in
[`config.py`](../netbox_passwork/config.py). For each of the three models, the function
declares a separate `ObjectView` decorated with `register_model_view(<Model>, "passwork",
path="passwork")` from `utilities.views`:

- `dcim.Device` → `DevicePassworkView`, template [`device_passwork.html`](../netbox_passwork/templates/netbox_passwork/device_passwork.html) (`passwork_object_type = "device"`);
- `virtualization.VirtualMachine` → `VMPassworkView`, template [`vm_passwork.html`](../netbox_passwork/templates/netbox_passwork/vm_passwork.html) (`passwork_object_type = "vm"`);
- `ipam.Service` → `ServicePassworkView`, template [`service_passwork.html`](../netbox_passwork/templates/netbox_passwork/service_passwork.html) (`passwork_object_type = "service"`).

All three inherit from `PassworkTabMixin`, which sets up the shared `ViewTab(label="Passwork",
badge=_passwork_badge, weight=1500, hide_if_empty=False)` and passes `object_type`/`object_id`
into the template context via `get_extra_context()`. The tab's badge is the count of
`PassworkBinding` records for that object, computed by `_passwork_badge()`.

Each of the three templates is a thin wrapper around the corresponding NetBox object's base
template, sharing one common block:

- `device_passwork.html` extends `dcim/device/base.html`;
- `vm_passwork.html` extends `virtualization/virtualmachine/base.html`;
- `service_passwork.html` extends `generic/object.html` (unlike Device/VM, `ipam.Service` has no `base.html` of its own with tabs, so the generic NetBox object template is used instead).

All three include the shared partial
[`secrets_tab.html`](../netbox_passwork/templates/netbox_passwork/secrets_tab.html) inside
`{% block content %}`, which holds the markup for the secrets table and the modal dialogs. The
tab itself does not show binding history — that's available in NetBox's standard change log
(Operations → Change Log).

## 4. Frontend

All client-side code lives in a single file —
[`static/netbox_passwork/passwork.js`](../netbox_passwork/static/netbox_passwork/passwork.js) —
with no build step or bundler. Naming convention: **every function in the module is prefixed
with `pw`** (`pwFetch`, `pwLoadSecretsTab`, `pwShowLoginModal`, `pwSubmitLogin`, `pwSubmitTotp`,
`pwOpenPicker`, `pwPickerLoadVaults`, `pwPickerSearchInput`, `pwRevealSecret`, `pwCopyField`,
`pwCreateBinding`, `pwDeleteBinding`, and so on).

Key pieces:

- `PW_API_BASE = '/plugins/passwork'` — the base prefix for every request; the `PW_REVEAL_TIMEOUT`/`PW_REQUEST_TIMEOUT` timeouts come from the globals `window.PW_SECRET_REVEAL_TIMEOUT`/`window.PW_REQUEST_TIMEOUT` (defaulting to 30/5 seconds), matching `SECRET_REVEAL_TIMEOUT`/`PASSWORK_REQUEST_TIMEOUT` from `config.py`.
- `pwModal()`/`pwShowModal()`/`pwHideModal()` — a wrapper around Bootstrap modals with a manual fallback (in case `bootstrap` isn't available globally in the NetBox theme).
- `pwCsrfToken()` — reads the CSRF token from `window.CSRF_TOKEN` (exposed by NetBox in `base.html`), falling back to the `csrftoken` cookie.
- `pwFetch(url, options)` — a single wrapper around `fetch()`: adds the `Content-Type: application/json` and `X-CSRFToken` headers, and forcibly aborts the request via `AbortController` once `PW_REQUEST_TIMEOUT` elapses.
- Modal dialogs: `login_modal.html` (Passwork login/password, handled by `pwSubmitLogin()`), `totp_modal.html` (TOTP code entry, `pwSubmitTotp()`), `picker_modal.html` (the Explorer-style secret picker: a folder tree on the left — vaults are roots, a vault's folders arrive as one flat list — the selected node's direct children on the right with breadcrumbs, and a debounced search with an optional this-vault-only scope; `pwOpenPicker()`/`pwPickerSelect()`/`pwPickerSearchInput()`/`pwCreateBinding()`, with all picker state living for one modal opening) — all three are pulled into [`secrets_tab.html`](../netbox_passwork/templates/netbox_passwork/secrets_tab.html) via `{% include %}`.
- `secrets_tab.html` — the shared tab partial: renders the "Secrets" card with two header buttons — "Bind secret" (opens the picker) and "Authenticate" (hidden by default; opens the login modal directly) — and the table of bound secrets, includes the three modals and `passwork.js` itself, and, right before including it, defines the globals `const PW_OBJECT_TYPE = "{{ object_type }}"` and `const PW_OBJECT_ID = "{{ object_id }}"`. These are supplied by the plugin's view via `PassworkTabMixin.get_extra_context()` and are used by the JS code (`pwLoadSecretsTab()` and others) as the `object_type`/`object_id` parameters on every request to `/plugins/passwork/...`.

## 5. Request flow: revealing a secret

```
Browser (pwRevealSecret() → pwFetch)
    │  GET /plugins/passwork/secrets/{pw_id}/detail/?object_type=..&object_id=..&reveal=true
    │  headers: X-CSRFToken, Django session cookie
    ▼
PassworkView.dispatch()  [views.py]  (SecretDetailView — subclass, ADR-0001)
    │  1. check_netbox_permissions(): user.has_perm("view_secrets_passworkbinding");
    │     SecretDetailView extends this: reveal=true additionally requires
    │     has_perm("reveal_secret_passworkbinding")
    │  2. method check: GET is supported → otherwise 405 (a plain Django response, before the
    │     gateway is even built)
    │  3. self.gateway = build_gateway(request); self.gateway.require_session()
    ▼
PassworkGateway.require_session() → _load()  [gateway.py]
    │  request.session["pw_session"] → decryption (Fernet)
    │  refresh_if_needed()   → POST /api/v1/sessions/refresh if needed
    │  the record is only saved back if the refresh actually changed it (write-on-change)
    │  the record read here is cached on the gateway — not re-read for the rest of this request
    │  ⇠ PassworkError (pw_not_authenticated / pw_session_expired / pw_timeout / pw_bad_response)
    │    → dispatch responds with {"code","detail"} at the exception's status
    ▼
SecretDetailView.get()
    │  4. _bound_object(request, pw_id): object_id from the query string (400 invalid_object_id
    │     if not numeric), then PassworkBinding.objects.filter(object_type, object_id,
    │     passwork_item_id).exists() → 404 binding_not_found (guards against an arbitrary pw_id);
    │     both failures go through ApiError
    │  5. self.gateway.get_item(pw_id) → PassworkAuthClient.get_item(pw_id, session) — the
    │     Passwork session record is not read from storage a second time (reused by the gateway)
    │     ⇠ PassworkAccessDenied/Timeout/BadResponse/SessionExpired → 403/504/502/401 in dispatch
    ▼
PassworkAuthClient.get_item()  [passwork_client.py]
    │  GET {PASSWORK_URL}/api/v1/items/{pw_id}
    │  headers: X-Browser-Mode, X-CSRF-Token, Authorization: Bearer <access_token>
    ▼
Passwork REST API v1
    │  ⇢ passwordEncrypted (base64), customs[] (base64 name/value/type)
    ▼
PassworkAuthClient.get_item() decodes password/custom_fields
    ▼
SecretDetailView.get() builds response_data (password is only included if reveal=true)
    │  6. if reveal=true: PassworkAuditLog.objects.create(action="reveal", netbox_user,
    │     ip_address=get_client_ip())
    ▼
JsonResponse → Browser (pwRevealSecret() displays the password until PW_REVEAL_TIMEOUT expires)
```

At no point along this path is the secret (password/custom fields) saved to the NetBox
database — only the fact that it was accessed (`PassworkAuditLog`). A similar but shorter chain
(with no call to Passwork) is used by `SecretCopyView` — the same `PassworkView.dispatch` (the
`reveal_secret` permission, `require_session()`), then the same `_bound_object` (400/404 via
`ApiError`), and an audit record with `action="copy"`.
