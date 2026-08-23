# Passwork integration

This document describes how the `netbox-passwork` v1.0.14 plugin interacts with the Passwork
API: the client, the login and 2FA flow, token refresh, secret retrieval, helper endpoints
(picker), session encryption, and plugin settings.

Key files:

- [gateway.py](../netbox_passwork/gateway.py) — the Passwork gateway (ADR-0001): the Passwork
  session (Fernet encryption, storage in the Django session, renewal) and eight operations.
- [passwork_client.py](../netbox_passwork/passwork_client.py) — a pure HTTP client for the
  Passwork API, with no Django and no session encryption.
- [utils.py](../netbox_passwork/utils.py) — helper functions (client IP); no longer involved in
  session encryption.
- [config.py](../netbox_passwork/config.py) — plugin configuration (`required_settings`, `default_settings`).
- [views.py](../netbox_passwork/views.py) — the plugin's views; some go through the gateway (`PassworkView`, ADR-0001).

---

## 1. The `PassworkAuthClient` client

The `PassworkAuthClient` class in [passwork_client.py](../netbox_passwork/passwork_client.py) is a
thin wrapper around `requests.Session` implementing Passwork API v1 calls.

```python
class PassworkAuthClient:
    """
    Passwork API v1, X-Browser-Mode.
    Based on a working authentication script.
    """

    def __init__(
        self,
        base_url: str,
        verify_ssl: bool = True,
        timeout: int = 5,
        refresh_margin: int = 60,
    ):
        ...
```

The client is a pure HTTP implementation with no Django dependency and no encryption: it does not
read `settings` and knows nothing about `SESSION_ENCRYPT_KEY`/Fernet (that is the gateway's
concern, see §6); everything it needs is passed through the constructor (callers take the values
from `PLUGINS_CONFIG["netbox_passwork"]`).

- `base_url` — the Passwork server URL (without a trailing `/`, trimmed in the constructor).
- `verify_ssl` — TLS certificate verification (`self._session.verify = verify_ssl`); only when
  `False` is `urllib3.disable_warnings()` called (not called at module import time).
- `timeout` — request timeout in seconds, used in every `_get`/`_post` call.
- `refresh_margin` — how many seconds before access-token expiry it should be renewed
  (`TOKEN_REFRESH_MARGIN`), see §3.

All requests go through the same `requests.Session` (`self._session`), so the `accessToken`
cookie set by Passwork at login is automatically preserved across calls within one client
instance.

Base headers are built by `_base_headers()`:

```python
def _base_headers(self, csrf_token: str = "") -> dict:
    h = {"X-Browser-Mode": "1", "X-Master-Key-Hash": ""}
    if csrf_token:
        h["X-CSRF-Token"] = csrf_token
    return h
```

`X-Browser-Mode: 1` makes Passwork behave as if it were talking to a browser client (in
particular, returning `accessToken` via a cookie rather than only in the response body).
`X-Master-Key-Hash` is always empty — the plugin operates without a client-side master key (see
the CSE section below).

The low-level `_post`/`_get` wrappers pass the response through `_decode()`, which:

- tries to parse the body as JSON, otherwise raises `PassworkBadResponse` (for example, if a
  proxy in front of Passwork returned an HTML error page);
- if the response is wrapped by Passwork in an envelope `{"format": "base64", "content": "..."}`,
  decodes the base64 and parses the embedded JSON.

`requests.Timeout` in `_post`/`_get` is caught and re-raised as `PassworkTimeout`.

---

## 2. Login and 2FA flow

The `login(username, password)` method:

1. **CSRF token.** `POST /api/v1/csrf-tokens/generate` with an empty body and the base headers
   (no CSRF/Authorization). The `csrfToken` is taken from the response. If the response contains
   `errors`, `PassworkAccessDenied` is raised.
2. **Login.** `POST /api/v1/users/login` with the body
   `{"username": ..., "password": ..., "hostname": ""}` and the `X-CSRF-Token` header obtained in
   step 1. If the response contains `errors`, `PassworkAccessDenied` is raised again ("Invalid
   credentials").
   - The `csrfToken` from the login response body replaces the original CSRF token (Passwork
     rotates it after login).
   - `refreshToken` is taken from the JSON response body.
   - `accessToken` does **not** arrive in the body — it is read from the session cookie:
     `urllib.parse.unquote(self._session.cookies.get("accessToken", ""))`.
3. **Building `session_data`** with token expiry timestamps set as hardcoded offsets from the
   current time (`now + 3600` for access, `now + 86400` for refresh) — see the "Refresh" section
   below.
4. **Checking whether TOTP is required.** This is not a dedicated official flag in the login
   response but a heuristic:
   - `GET /api/v1/users/info` is called with the freshly obtained `access_token`;
   - if `isTwoFactorAuthEnabled` in the response is true, the client makes a **probe request**
     `GET /api/v1/items/search?query=_totp_check_`;
   - if that probe request returns HTTP 401 with a body containing an error with the code
     `twoFactorAuthRequired`, the `requires_totp` flag in `session_data` is set to `True`.
   - This is a known limitation: the heuristic is fragile and requires an extra round trip to
     Passwork.

If `requires_totp` is true, `PassworkLoginView` (`POST /auth/login/` in
[views.py](../netbox_passwork/views.py)) returns `{"status": "totp_required", "requires_totp": true}`
to the client without completing the login — the frontend must prompt for the code and call
`/auth/totp/`.

The `confirm_totp(code, session_data)` method:

- `POST /api/v1/users/2fa/totp/authorize` with the body `{"code": code}` and headers
  `Authorization: Bearer <access_token>` + `X-CSRF-Token` from `session_data`;
- on HTTP 401 or if the response contains `errors` — `PassworkAccessDenied` ("Invalid TOTP code");
- on success `session_data["requires_totp"]` is reset to `False`.

`PassworkTotpView` (`POST /auth/totp/`) requires that a `pw_session` already exist in the Django
session (i.e. the first login stage already completed), decrypts it, calls `confirm_totp`, and
writes `pw_session` back with the encrypted result.

---

## 3. Token refresh

`refresh_if_needed(session_data)`:

```python
now = int(time.time())

if now >= session_data["refresh_token_expired_at"]:
    raise PassworkSessionExpired("Refresh token expired")

if session_data["access_token_expired_at"] - now >= self.refresh_margin:
    return session_data

# otherwise — refresh the access token
```

- If the refresh token has already expired — `PassworkSessionExpired` (re-login required).
- If **more** than `refresh_margin` seconds remain before the access token expires (a constructor
  parameter; callers pass `TOKEN_REFRESH_MARGIN` from `PLUGINS_CONFIG["netbox_passwork"]`,
  defaulting to `60`), the token is not refreshed.
- Otherwise `POST /api/v1/sessions/refresh` is called with the body
  `{"refreshToken": session_data["refresh_token"]}` and the header
  `Authorization: Bearer <old access_token>`.
  - HTTP 401 **or 403** → `PassworkSessionExpired` ("Refresh token rejected") — 403 was added in
    v1.3.0 (in some cases Passwork rejects an expired refresh token this way).
  - On success, the new `accessToken` is again read from the session cookie
    (`self._session.cookies.get("accessToken", ...)`), and `access_token_expired_at` is
    recalculated as `now + 3600`.

This is called from [gateway.py](../netbox_passwork/gateway.py) (`PassworkGateway._load()`) inside
`require_session()` — **once per HTTP request**: the loaded (and, if needed, renewed) Passwork
session is reused by every gateway operation within that request, without decrypting the stored
record again. On `PassworkSessionExpired`, the `pw_session` record is removed from storage and the
client receives `401 {"code": "pw_session_expired", "detail": ...}`.

**Known limitation:** token TTLs (`3600` seconds for access, `86400` seconds for refresh) are
hardcoded in the client and are not read from the actual Passwork response. If the Passwork server
is configured with different token lifetimes, the two can drift out of sync — the plugin might
treat a token as still valid after Passwork has already rejected it (or, conversely, refresh a
token earlier than necessary).

---

## 4. Retrieving a secret: `get_item`

`get_item(pw_id, session_data)` performs `GET /api/v1/items/{pw_id}` with the headers
`Authorization: Bearer <access_token>` and `X-CSRF-Token`.

Error mapping by the Passwork response's HTTP status:

| Status | Behavior |
|--------|-----------|
| `401`  | `PassworkSessionExpired` — the token expired or TOTP is required |
| `403`  | `PassworkAccessDenied` — access to the secret is denied |
| `404`  | `{}` (empty dict) is returned, no exception raised |

Decrypting the data assumes that **client-side encryption (CSE) is disabled** on the Passwork side
(see the README: `Passwork 7.6+ (CSE off)`). If CSE were enabled, the `passwordEncrypted` field
would be encrypted with the user's master key, which the plugin's backend has no access to. With
CSE disabled, `passwordEncrypted` is simply `base64(plaintext)`:

```python
if isinstance(data, dict) and data.get("passwordEncrypted"):
    data["password"] = base64.b64decode(data["passwordEncrypted"]).decode("utf-8")
else:
    data["password"] = None
```

Custom fields (`customs` in the Passwork response) are decoded the same way — each field has
base64-encoded `name`, `value`, and `type`. The result is placed into `data["custom_fields"]` as a
list of dicts:

```python
{
    "name": name,
    "value": value,
    "is_secret": field_type in ("password", "totp"),
    "type": field_type,
}
```

The `is_secret` flag is true for fields of type `password` or `totp` — these are the fields the
plugin's frontend hides by default and requires an explicit "reveal" for (just like the secret's
main password).

---

## 5. Other endpoints (picker)

The secret-selection UI used when creating a binding (`PassworkBinding`) relies on GET
endpoints of Passwork. The picker views go through the gateway (`PassworkGateway`, ADR-0001),
which calls the client's public operations:

- **`PickerFoldersView`** (`GET /picker/folders/` in the plugin itself) →
  `PassworkGateway.list_vaults()` → the `list_vaults(session_data)` client method →
  `GET /api/v1/vaults` — the list of Passwork vaults for the selection tree.
- **`PickerFolderContentsView`** (`GET /picker/folders/<vault_id>/items/[?folder_id=...]`) →
  `PassworkGateway.list_folder_contents(vault_id, folder_id)` → the
  `list_folder_contents(vault_id, folder_id, session_data)` client method → two Passwork
  **listing** requests (Api reference §11.5 / §13.6 — not the text search):
  `GET /api/v1/folders?vaultId=<vault_id>` (the vault's flat folder list, filtered here to the
  node's direct children by `parentFolderId`, which is `null` at the vault root) and
  `GET /api/v1/items?vaultId=<vault_id>` for the vault node, or
  `GET /api/v1/items?vaultId=<vault_id>&folderId=<folder_id>` for a folder node. The response is
  `{"folders": [{"id", "name"}, ...], "items": [...]}` — **direct children only** (Explorer
  semantics): Passwork has no "root only" parameter and without `folderId` returns every password
  in the vault, so for the vault node the client filters the items down to those whose own
  `folderId` is null. The `folderId`/`parentFolderId` fields and the folder-listing shape are
  taken from the `Api reference.pdf` shipped inside a Passwork installation
  (`/var/www/files/api-schema/` on Linux; §11.5 GET /v1/folders, §13.6 GET /v1/items).
- **`PickerVaultFoldersView`** (`GET /picker/folders/<vault_id>/folders/`) →
  `PassworkGateway.list_vault_folders(vault_id)` → the `list_vault_folders(vault_id,
  session_data)` client method → `GET /api/v1/folders?vaultId=<vault_id>` — the vault's **flat**
  folder list, normalized to `[{"id", "name", "parentFolderId"}, ...]`. One request per vault:
  the picker's JS builds the whole tree (and the breadcrumbs) from `parentFolderId` on the
  client, so expanding folders costs no extra requests.
- **`PickerSearchView`** (`GET /picker/search/?q=...[&vault_id=...]` in the plugin) →
  `PassworkGateway.search_items(query, vault_id)` → the `search_items(query, session_data,
  vault_id)` client method → `POST /api/v1/items/search` (Api reference §13.29) with
  `{"query": ..., "vaultIds": [...]}` in the JSON body — full-text search over secrets,
  optionally scoped to one vault. The POST variant is used because array-parameter encoding for
  the GET variant is not documented; search results carry `vaultId`, `folderId` and the full
  `path`, which the picker uses for the "show in folder" jump without extra requests.

The client operations return Passwork's `items` lists, and 401/403 from Passwork are translated
into `PassworkSessionExpired`/`PassworkAccessDenied` (same as `get_item`).

Vault and folder ids are encoded with `urllib.parse.quote(..., safe="")` before being
substituted into a URL — only inside the client (`list_folder_contents`, `list_vault_folders`).
The search query never touches a URL at all: it travels in the POST body, so it has no
query-parameter injection surface. (Historically the search used the GET variant, and encoding
the query was a v1.0.13 injection fix — without it, characters such as `&`, `#`, or a space in
`q` made it possible to inject extra query parameters, e.g. `q=x&perPage=100000`.)

Passwork failures in all picker views are translated into HTTP responses by the base
`PassworkView` (a uniform `{"code", "detail"}` shape): `PassworkSessionExpired` → `401
pw_session_expired`, `PassworkAccessDenied` → `403 pw_access_denied` (the picker used to return
`200` with an empty list), `PassworkTimeout` → `504 pw_timeout`, `PassworkBadResponse` → `502
pw_bad_response`. A missing Passwork session yields `401 pw_not_authenticated` before `q` is even
parsed.

---

## 6. Session encryption (Fernet)

Passwork tokens are never returned to the browser — they are kept **server-side**, in the Django
session, under the `pw_session` key, and encrypted with
[Fernet](https://cryptography.io/en/latest/fernet/) using the `SESSION_ENCRYPT_KEY` key from
`PLUGINS_CONFIG["netbox_passwork"]` before being stored.

Since v1.3.0, encryption is implemented **in a single place** — `PassworkGateway`
(`_encrypt`/`_decrypt` in [gateway.py](../netbox_passwork/gateway.py)). Only `build_gateway()`
reads the key, from `PLUGINS_CONFIG["netbox_passwork"]["SESSION_ENCRYPT_KEY"]`, and passes it into
the gateway's constructor. The former duplicate of the same logic —
`PassworkAuthClient.encrypt_session`/`decrypt_session` in
[passwork_client.py](../netbox_passwork/passwork_client.py) (key passed as the constructor
parameter `session_encrypt_key`) and `fernet_encrypt`/`fernet_decrypt`/`_get_fernet` in
[utils.py](../netbox_passwork/utils.py) — has been removed, eliminating the duplicate encryption
logic. The `pw_session` record format in storage is byte-for-byte compatible with versions ≤1.2.x
— users who are already logged in are not signed out when the plugin is upgraded.

Only three fields of the Passwork session are encrypted:

```python
_ENCRYPTED_FIELDS = ("access_token", "refresh_token", "csrf_token")
```

The remaining fields (`access_token_expired_at`, `refresh_token_expired_at`, `requires_totp`) are
stored in the clear — they are not secrets.

`PassworkGateway.require_session()` (called by `PassworkView.dispatch` for views built on the
gateway, except `OPTIONS`, see §5 in [architecture.md](architecture.md)) calls `_load()` on every
such request: it decrypts `storage["pw_session"]` → calls `refresh_if_needed` → writes the record
back into storage **only if** renewal changed it (avoiding unnecessary session writes). Failure
modes:

- `PassworkSessionExpired` (the refresh token expired, or Passwork rejected it with 401/403 — see
  §3) → the `pw_session` record is removed, and the client receives
  `401 {"code": "pw_session_expired", "detail": ...}`;
- `InvalidToken` (for example, `SESSION_ENCRYPT_KEY` was changed and the old record can no longer
  be decrypted) → the record is removed, `logger.warning(...)` is logged, and the client receives
  `401 {"code": "pw_not_authenticated", "detail": "Passwork session could not be decrypted"}`.

### Key generation

The key must be a valid Fernet key (32 bytes, base64-url-encoded). Per [README.md](../README.md),
it is generated like this:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

The key should be kept in an environment variable (for example, `PW_SESSION_KEY`), not directly in
`configuration.py`:

```python
'SESSION_ENCRYPT_KEY': os.environ['PW_SESSION_KEY'],
```

---

## 7. Plugin settings (`config.py`)

All settings are read from `settings.PLUGINS_CONFIG["netbox_passwork"]`. They are defined in
[config.py](../netbox_passwork/config.py):

```python
required_settings = ["PASSWORK_URL", "SESSION_ENCRYPT_KEY"]
default_settings = {
    "PASSWORK_VERIFY_SSL": True,
    "TOKEN_REFRESH_MARGIN": 60,
    "PASSWORK_REQUEST_TIMEOUT": 5,
    "SECRET_REVEAL_TIMEOUT": 30,
}
```

| Setting                      | Required | Default value          | Purpose |
|------------------------------|:-----------:|------------------------|------------|
| `PASSWORK_URL`               | yes         | — (no default)         | The Passwork server's base URL; passed to `PassworkAuthClient(base_url=...)`. |
| `SESSION_ENCRYPT_KEY`        | yes         | — (no default)         | The Fernet key used to encrypt `access_token`/`refresh_token`/`csrf_token` in the Django session. |
| `PASSWORK_VERIFY_SSL`        | no          | `True`                  | Whether to verify Passwork's TLS certificate (`PassworkAuthClient(verify_ssl=...)`). |
| `TOKEN_REFRESH_MARGIN`       | no          | `60` (sec.)             | How many seconds before access-token expiry to call `sessions/refresh`. |
| `PASSWORK_REQUEST_TIMEOUT`   | no          | `5` (sec.)              | Timeout for HTTP requests to Passwork (`PassworkAuthClient(timeout=...)`); `PassworkTimeout` is raised if exceeded. |
| `SECRET_REVEAL_TIMEOUT`      | no          | `30` (sec.)             | How many seconds after "reveal" the secret is automatically hidden again on the frontend. |

`required_settings` are checked by NetBox when the plugin loads — without `PASSWORK_URL` and
`SESSION_ENCRYPT_KEY` the plugin will not start.
`default_settings` are substituted automatically for missing keys, but the client and view code
still reads them defensively, via `cfg.get("...", <default>)`.
