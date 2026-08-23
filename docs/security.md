# Security

This document describes the security controls of the `netbox-passwork` plugin (v1.3.0),
how they are implemented in the code, and the known limitations. It is based on the current
code ([views.py](../netbox_passwork/views.py), [permissions.py](../netbox_passwork/permissions.py),
[utils.py](../netbox_passwork/utils.py), [models.py](../netbox_passwork/models.py),
[gateway.py](../netbox_passwork/gateway.py),
[passwork.js](../netbox_passwork/static/netbox_passwork/passwork.js)) and on
[CHANGELOG.md](../CHANGELOG.md).

The plugin integrates Passwork into NetBox: a secrets tab on Device/VM/Service, proxied access
to secret values, bindings, an audit log and binding change history. Since the product handles
passwords, security is a core concern of the architecture.

---

## 1. Protection against access to arbitrary secrets (binding check)

The key control of the plugin: before proxying a request to Passwork and returning secret data,
the server checks that a `PassworkBinding` exists for the requested triple
`(object_type, object_id, pw_id)`.

Implemented in [`SecretDetailView`](../netbox_passwork/views.py):

```python
if not PassworkBinding.objects.filter(
    object_type=object_type,
    object_id=object_id,
    passwork_item_id=pw_id,
).exists():
    return _error("binding_not_found", "Binding not found", 404)
```

The binding check runs **before** `client.get_item(pw_id, ...)` is called, that is, before the
Passwork API is contacted at all. This prevents a user holding a valid Passwork session from
fetching the data of an arbitrary `pw_id` that is not bound to a NetBox object they have
`view_secrets` on. The same check is present in `SecretCopyView` before the audit record is written.
It is itself preceded by the object-level check (section 2.1), so the response never discloses
whether a hidden object has bindings.

Covered by the tests in `test_proxy.py` (`TestSecretDetailView`) and `test_security.py`
(`TestSecurityHardening`).

---

## 2. RBAC — permissions based on NetBox ObjectPermission

The plugin defines five custom permissions on the `PassworkBinding` model
([models.py](../netbox_passwork/models.py), `Meta.permissions`):

| Permission       | Django permission code                            | Purpose                                       |
|------------------|---------------------------------------------------|-----------------------------------------------|
| `view_secrets`   | `netbox_passwork.view_secrets_passworkbinding`    | View the Passwork tab and the list of secrets |
| `reveal_secret`  | `netbox_passwork.reveal_secret_passworkbinding`   | Reveal and copy a secret value                |
| `add_binding`    | `netbox_passwork.add_binding_passworkbinding`     | Bind a secret to an object                    |
| `delete_binding` | `netbox_passwork.delete_binding_passworkbinding`  | Remove a binding                              |
| `view_auditlog`  | `netbox_passwork.view_auditlog_passworkbinding`   | View the audit log                            |

The check is performed in [`permissions.py`](../netbox_passwork/permissions.py) in two
equivalent ways:

- **`RequireNetboxPermMixin`** — a mixin for class-based views that verifies authentication and
  `request.user.has_perm(perm)` in `dispatch()`, before the handler runs; every view in
  [views.py](../netbox_passwork/views.py) uses it through the `permission_required` attribute.
- **`require_netbox_perm(perm_key)`** — the equivalent decorator for function-based views.

Both return `401` (`not_authenticated`) if the user is not authenticated and `403`
(`netbox_permission_denied`) if the permission is missing. `SecretDetailView` additionally
checks `reveal_secret` separately for the `?reveal=true` parameter — listing secrets and
revealing a password are therefore guarded by different permissions.

Permissions are assigned through the standard NetBox mechanism — `ObjectPermission`
(Admin → Users → Permissions), as described in [README.md](../README.md), section
"Permissions (RBAC)". They are attached to the `ContentType` of the `PassworkBinding` model.

### 2.1. Object-level check (ObjectPermission constraints)

On top of the plugin permissions, every object-scoped operation — secrets list, secret detail,
reveal, copy, binding create and binding delete — requires `view` access to the bound NetBox
object itself (`dcim.view_device` / `virtualization.view_virtualmachine` / `ipam.view_service`),
evaluated against the user's `ObjectPermission` constraints (issue #1,
[ADR-0002](adr/0002-object-level-permissions.md)). A user whose `view_device` is constrained to
"devices of site A only" cannot touch secrets bound to devices of other sites, even knowing
their `object_type`/`object_id` — and a user with no `view` permission on the object type at all
cannot touch its secrets regardless of plugin permissions.

Implemented in `bound_object_access()` ([permissions.py](../netbox_passwork/permissions.py)) via
NetBox's `restrict()`, which applies constraints, superuser status and `EXEMPT_VIEW_PERMISSIONS`
exactly as NetBox core does. An object that exists but is hidden by constraints is answered with
**404** (`object_not_found`), the same convention NetBox core uses; the check runs **before**
the binding lookup, so binding existence is never disclosed for hidden objects. Orphaned
bindings (the bound object was deleted) are unreadable for everyone but deletable with
`delete_binding` alone, so leftovers can be cleaned up.

Covered by the matrix tests in `test_permissions.py` (`TestObjectGateMatrix`,
`TestOrphanedBindings`, `TestBoundObjectAccess`).

---

## 3. Audit log and history

Two independent journals, neither of which stores password values:

- **`PassworkAuditLog`** ([models.py](../netbox_passwork/models.py)) — one record per secret
  reveal (`reveal`) and copy (`copy`): the NetBox user, `passwork_item_id`,
  `object_type`/`object_id`, the action, the IP address and a timestamp. Created in
  `SecretDetailView` and `SecretCopyView` ([views.py](../netbox_passwork/views.py)).
  The `reveal` record is written inside `transaction.atomic()`:

  ```python
  if reveal:
      response_data["password"] = item.get("password", "")
      with transaction.atomic():
          PassworkAuditLog.objects.create(...)
  ```

  The `copy` record (in `SecretCopyView`) is written without an explicit `transaction.atomic()`.

  The journal is only reachable through the `view_auditlog` permission (`AuditLogView`) and
  supports filtering and pagination (`limit`/`offset`, with `limit` capped at 500).

- **Binding history — the built-in NetBox changelog** (`core.ObjectChange`): creating and
  deleting a `PassworkBinding` is recorded by NetBox core signals (user, request ID, before/after
  snapshots). Access to those records is governed by the standard NetBox permissions on
  `core.ObjectChange`. Compared with a plugin-specific journal this means the client IP is not
  recorded and records are subject to `CHANGELOG_RETENTION` (90 days by default) — see
  [Known limitations](#7-known-limitations).

Neither `PassworkAuditLog` nor the `ObjectChange` snapshots have fields that could hold a
password value or any other secret data — they contain identifiers, metadata and (in the audit
log) an IP address only.

---

## 4. Passwork session and token encryption

Authentication against Passwork is separate from the NetBox session (`PassworkLoginView`,
`PassworkTotpView` in [views.py](../netbox_passwork/views.py)). The tokens returned by Passwork
(`access_token`, `refresh_token`, `csrf_token`) are encrypted and decrypted by
**`PassworkGateway`** — the only place in the plugin where this happens
([gateway.py](../netbox_passwork/gateway.py), Fernet, key `SESSION_ENCRYPT_KEY` from
`PLUGINS_CONFIG`, read only by `build_gateway(request)`) — and stored encrypted in the Django
session (`request.session["pw_session"]`).

On each request to a Passwork-facing view the gateway (`self.gateway.require_session()` →
`_load()`) decrypts the record **once** (the result is reused by every gateway operation within
that request), refreshes the access token if needed (`refresh_if_needed`) and writes the record
back — but only if the refresh actually changed it. When the Passwork session expires
(`PassworkSessionExpired` — the refresh token has expired, or Passwork answered
`/api/v1/sessions/refresh` with 401 **or** 403) the record is dropped and the client receives
`401 pw_session_expired`.

If `SESSION_ENCRYPT_KEY` is rotated (or the record is corrupted in any other way), decryption
fails with `InvalidToken`: the broken record is dropped with a `logger.warning` and the client
receives `401 pw_not_authenticated` — the user simply logs in to Passwork again instead of being
stuck with a permanent, unexplained `401`. Other exceptions (timeouts, non-JSON responses and
anything unexpected) are not masked as `401`.

`PassworkGateway.require_session()` is used by every view that talks to Passwork
(`PassworkLoginView`/`PassworkTotpView`, `SecretDetailView`, `SecretCopyView`,
`PickerFoldersView`, `PickerVaultFoldersView`, `PickerSearchView`); the plugin installs no Django middleware of its own
(see [ADR-0001](adr/0001-passwork-gateway-not-middleware.md)).

Tokens are kept on the server only (in the Django session, never in the browser), and passwords
are neither logged nor cached on the server.

---

## 5. Audit log IP anti-spoofing

`get_client_ip()` ([utils.py](../netbox_passwork/utils.py)) provides the IP address recorded in
`PassworkAuditLog`. It takes the **rightmost** address of the `X-Forwarded-For` header:

```python
def get_client_ip(request) -> str | None:
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded_for:
        return forwarded_for.split(",")[-1].strip()
    return request.META.get("REMOTE_ADDR")
```

The leftmost address of `X-Forwarded-For` is fully client-controlled and trivially forged with an
arbitrary request header, so the trusted value is the one appended by the last trusted proxy,
i.e. the rightmost entry in the chain. This assumes exactly one trusted reverse proxy in front of
the application (nginx, for example) that appends its own address to `X-Forwarded-For`.

---

## 6. XSS protection in the frontend

All rendering in [passwork.js](../netbox_passwork/static/netbox_passwork/passwork.js) builds the
DOM through `document.createElement()` and assigns user-supplied and secret values through
`textContent` rather than `innerHTML`. Click handlers are attached with `addEventListener` and
receive their values through closures instead of being embedded into inline `onclick`
attributes, and links to Passwork are scheme-checked (`safeLink()`, rejecting `javascript:`).

Regression coverage: jsdom-based JS tests in
[`netbox_passwork/tests/js/xss.test.js`](../netbox_passwork/tests/js/xss.test.js).

---

## 7. Known limitations

### Binding history is limited by the NetBox changelog

Binding history relies on `core.ObjectChange`, so it does not record the client IP and its
records are removed according to `CHANGELOG_RETENTION` (90 days by default). Reveal and copy
events are recorded separately in `PassworkAuditLog`, which is not affected by that retention
setting.

### The audit log is not scoped per object

`AuditLogView` returns every audit record to any user holding `view_auditlog`, without scoping
by object. This is intentional — the permission is meant to be administrative — but it means
`view_auditlog` should not be granted to users who are only allowed to see a subset of objects.

### Token lifetimes are hardcoded

`login()` stores fixed token TTLs (`now + 3600` for the access token and `+ 86400` for the
refresh token) instead of the real lifetime reported by Passwork. If a Passwork installation uses
different lifetimes, the refresh logic can drift out of sync with the server.

### TOTP detection is heuristic

Whether an account requires TOTP is determined with a probe request (a search for
`_totp_check_`) rather than from an explicit Passwork response field. This costs one extra
request and is sensitive to changes in the Passwork API.

---

## 8. Security requirements for the environment

Running the plugin securely requires (see [README.md](../README.md)):

- **Passwork with Client-Side Encryption disabled (CSE off)** — the plugin requires Passwork
  7.6+ with CSE off (see the requirements table in the README); with CSE enabled, proxying
  secrets through the plugin's server side is architecturally impossible and unsupported.
- **HTTPS** — Passwork tokens and revealed passwords travel between the browser and NetBox. The
  clipboard copy feature has an HTTP fallback for non-HTTPS setups, but HTTPS remains a baseline
  requirement both for browser-to-NetBox traffic and for NetBox-to-Passwork traffic
  (`PASSWORK_VERIFY_SSL`).
- **Safe storage of `SESSION_ENCRYPT_KEY`** — the mandatory Fernet key used to encrypt session
  tokens. Keep it in an environment variable (for example `PW_SESSION_KEY`) and **never** in
  `configuration.py`; generate it with `Fernet.generate_key()`. Compromising this key is
  equivalent to compromising every active Passwork session stored in the Django session
  database.

---

## Summary

| Control                                          | Status                                                        |
|--------------------------------------------------|---------------------------------------------------------------|
| Binding check before proxying a secret           | Implemented, covered by tests                                 |
| RBAC (5 permissions on `PassworkBinding`)        | Implemented through NetBox `ObjectPermission`                 |
| Audit log for reveal/copy                        | Implemented (`PassworkAuditLog`), no password values stored   |
| Binding history                                  | Built-in NetBox changelog (`core.ObjectChange`)               |
| Passwork token encryption (Fernet)               | Implemented, single location — `PassworkGateway` (`gateway.py`) |
| Audit log IP anti-spoofing (`X-Forwarded-For`)   | Implemented                                                   |
| XSS protection in `passwork.js`                  | Implemented, covered by jsdom tests                           |
| Object-level NetBox permissions (constraints)    | Implemented (ADR-0002), covered by matrix tests               |
| Per-object scoping of the audit log              | **Not implemented — intentional, see Known limitations**      |
| Token lifetimes from Passwork, non-heuristic TOTP| **Not implemented — see Known limitations**                   |
