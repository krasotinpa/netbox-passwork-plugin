# Data model of the `netbox-passwork` plugin

The plugin stores **only auxiliary data** in the NetBox database: bindings between NetBox
objects and Passwork items (passwords), and an audit log of secret access. The actual Passwork
password/secret values **are never stored** in the NetBox database — see
[Passwork secrets are not stored in the database](#passwork-secrets-are-not-stored-in-the-database).

Binding change history (creation/deletion) is kept in **NetBox's standard changelog**
(`core.ObjectChange`) — the plugin no longer has a history table of its own (it was dropped by
migration `0003`, see below).

Sources: [models.py](../netbox_passwork/models.py), [migrations/](../netbox_passwork/migrations/),
[permissions.py](../netbox_passwork/permissions.py), [views.py](../netbox_passwork/views.py),
[api/serializers.py](../netbox_passwork/api/serializers.py).

## Contents

1. [`PassworkBinding`](#1-passworkbinding)
2. [Binding history via the standard NetBox changelog](#2-binding-history-via-the-standard-netbox-changelog)
3. [`PassworkAuditLog`](#3-passworkauditlog)
4. [Migrations](#4-migrations)
5. [Mini ERD](#5-mini-erd)
6. [Passwork secrets are not stored in the database](#passwork-secrets-are-not-stored-in-the-database)

---

## 1. `PassworkBinding`

Links a NetBox object (a device, virtual machine, or service) to an item (password) in
Passwork. Defined in [models.py](../netbox_passwork/models.py).

Inherits from `netbox.models.ChangeLoggedModel`, which brings in NetBox's standard change
logging and adds the `created`/`last_updated` fields.

### Fields

| Field | Type | Description |
|---|---|---|
| `object_type` | `CharField(max_length=32, choices=OBJECT_TYPE_CHOICES)` | Type of the related NetBox object. Allowed values (`OBJECT_TYPE_CHOICES`): `device` ("Device"), `vm` ("Virtual Machine"), `service` ("Service") |
| `object_id` | `PositiveIntegerField` | PK of the related NetBox object (device/VM/service) — a plain (non-FK) reference |
| `passwork_item_id` | `CharField(max_length=128, db_index=True)` | ID of the item (password) in Passwork |
| `created` | `DateTimeField(auto_now_add=True, null=True)` | When the binding was created (inherited from `ChangeLoggedModel`) |
| `last_updated` | `DateTimeField(auto_now=True, null=True)` | When the binding was last modified (inherited from `ChangeLoggedModel`) |
| `created_by` | `ForeignKey(AUTH_USER_MODEL, null=True, on_delete=SET_NULL, related_name="+")` | The NetBox user who created the binding |

The model uses an auto-incrementing `id` (`BigAutoField`) as its primary key.

### Hard delete

Deleting a binding is a physical delete: [`BindingsDeleteView`](../netbox_passwork/views.py)
calls `binding.snapshot()` (to capture state for the changelog's `prechange_data`) and then
`binding.delete()`. There is no soft delete (`deleted_at`) anymore — the deleted object's
snapshot is preserved in the resulting `ObjectChange` record with the standard `delete` action.

### Unique constraint and index

`Meta` defines (both unconditional now — the partial variants that used to key off
`deleted_at` were removed along with soft delete):

- **Constraint** `pb_unique_binding` — a `UniqueConstraint` on `["object_type", "object_id",
  "passwork_item_id"]`: the same object cannot be bound to the same Passwork item twice. Once a
  binding is deleted, the same triple can be created again.
- **Index** `pb_object_idx` — an `Index` on `["object_type", "object_id"]`. Speeds up the
  common "show this object's bindings" query (used by `SecretsListView`).

The `passwork_item_id` field also has its own `db_index=True`.

### Custom permissions (`Meta.permissions`)

`PassworkBinding.Meta.permissions` declares 5 custom permissions. NetBox/Django build a
permission's codename as `{app_label}.{action}_{model_name}` — since all of them are declared
on the `PassworkBinding` model, the resulting permission key always ends in `_passworkbinding`,
regardless of what the permission actually does:

| `action` (codename) | Description (label) | Resulting NetBox permission key |
|---|---|---|
| `view_secrets` | Can view Passwork secrets | `netbox_passwork.view_secrets_passworkbinding` |
| `reveal_secret` | Can reveal Passwork secret value | `netbox_passwork.reveal_secret_passworkbinding` |
| `add_binding` | Can create Passwork binding | `netbox_passwork.add_binding_passworkbinding` |
| `delete_binding` | Can delete Passwork binding | `netbox_passwork.delete_binding_passworkbinding` |
| `view_auditlog` | Can view Passwork audit log | `netbox_passwork.view_auditlog_passworkbinding` |

This mapping is captured in the `PLUGIN_PERMISSIONS` dictionary in
[permissions.py](../netbox_passwork/permissions.py) and is used both by the
`require_netbox_perm` decorator and by the `RequireNetboxPermMixin` mixin (checked via
`request.user.has_perm(...)`) across all of the proxying views (`SecretsListView`,
`SecretDetailView`, `SecretCopyView`, `BindingsCreateView`, `BindingsDeleteView`,
`AuditLogView`). Object-scoped views additionally require `view` access to the bound NetBox
object under the user's `ObjectPermission` constraints — `bound_object_access()` in the same
module ([ADR-0002](adr/0002-object-level-permissions.md), [security.md](security.md) §2.1).

---

## 2. Binding history via the standard NetBox changelog

Creation and deletion of a `PassworkBinding` are recorded in NetBox's standard change log — the
`core.ObjectChange` model. The mechanism is entirely stock NetBox:

- `PassworkBinding` inherits `ChangeLoggedModel`, which provides the `to_objectchange()` /
  `snapshot()` / `serialize_object()` methods;
- NetBox core's signal handlers (`core.signals.handle_changed_object`,
  `handle_deleted_object`) create an `ObjectChange` record on every `save()`/`delete()` of the
  object, **provided the operation happens inside an HTTP request** (NetBox middleware stores
  the current request in a contextvar; outside of a request — e.g. from a shell or a script —
  no changelog entry is created);
- each record captures: the user, timestamp, request ID, action (`create`/`update`/`delete`),
  and before/after state snapshots (`prechange_data`/`postchange_data`).

Where to look: NetBox's global log (**Operations → Change Log**), filtered by object type
"passwork binding". The plugin no longer has its own UI or endpoint for binding history.

Notable consequences:

- **Retention.** `ObjectChange` records are subject to NetBox's `CHANGELOG_RETENTION` setting
  (90 days by default, cleaned up by a housekeeping job).
- **No IP address.** `ObjectChange` stores the user and request ID, but not the client's IP
  (unlike `PassworkAuditLog`).
- **Events pipeline.** Changes to change-logged NetBox models also trigger the events pipeline
  (event rules / webhooks). To serialize the object, the pipeline looks for a DRF serializer
  following the convention `<plugin>.api.serializers.<Model>Serializer` — which is why the
  [api/serializers.py](../netbox_passwork/api/serializers.py) module exists, re-exporting
  `PassworkBindingSerializer`.

---

## 3. `PassworkAuditLog`

An audit log of user access to Passwork secret values (view/copy). Defined in
[models.py](../netbox_passwork/models.py). It deliberately was **not** migrated onto the
NetBox changelog: revealing/copying a password is a read operation that doesn't change any
database object, whereas the standard changelog only records mutations
(`create`/`update`/`delete`).

### Fields

| Field | Type | Description |
|---|---|---|
| `timestamp` | `DateTimeField(auto_now_add=True)` | When the event happened |
| `netbox_user` | `ForeignKey(AUTH_USER_MODEL, null=True, on_delete=SET_NULL)` | The user who performed the action |
| `passwork_item_id` | `CharField(max_length=128)` | ID of the Passwork item (no `db_index` on the field itself — indexed separately, see below) |
| `object_type` | `CharField(max_length=32)` | Type of the NetBox object the action was performed in the context of (no `choices`, unlike `PassworkBinding.object_type`) |
| `object_id` | `PositiveIntegerField` | PK of the NetBox object |
| `action` | `CharField(max_length=16, choices=ACTION_CHOICES)` | `reveal` (Reveal) or `copy` (Copy) |
| `ip_address` | `GenericIPAddressField(null=True)` | Client IP address |

`Meta.ordering = ["-timestamp"]`.

### Actions and where records are created

- **`reveal`** — created in `SecretDetailView` ([views.py](../netbox_passwork/views.py)) on a
  `GET` request with `reveal=1/true`, inside `transaction.atomic()`, right after the real
  password value is placed into the response (`response_data["password"]`).
- **`copy`** — created in `SecretCopyView` on `POST /secrets/{pw_id}/copy/`, after verifying
  that a `PassworkBinding` exists for the given `object_type`/`object_id`/`pw_id`.

Both call sites write `netbox_user=request.user`, `passwork_item_id`, `object_type`,
`object_id`, and `ip_address=get_client_ip(request)`.

### Indexes

`Meta.indexes` defines three plain indexes:

| Index name | Fields |
|---|---|
| `pal_user_idx` | `netbox_user` |
| `pal_item_idx` | `passwork_item_id` |
| `pal_ts_idx` | `-timestamp` (descending) |

These are used, among others, by `AuditLogView`, which filters/sorts the log via
`PassworkAuditLog.objects.select_related("netbox_user").order_by("-timestamp")`.

---

## 4. Migrations

Directory: [migrations/](../netbox_passwork/migrations/).

### `0001_initial.py`

The initial migration. Created three models: `PassworkBinding` (with the soft-delete fields
`deleted_at`/`deleted_by`, partial index/constraint, and all 5 custom permissions),
`PassworkBindingHistory` (the plugin's own binding history table), and `PassworkAuditLog`
(with the three indexes from section 3).

Migration dependency: `migrations.swappable_dependency(settings.AUTH_USER_MODEL)`.

### `0002_alter_ids.py`

A technical follow-up: `id` on every plugin model was switched from `AutoField` to
`BigAutoField` (64-bit primary keys).

### `0003_changelog.py`

Moves binding history over to NetBox's standard changelog
([0003_changelog.py](../netbox_passwork/migrations/0003_changelog.py)). The order of
operations matters:

1. `DeleteModel(PassworkBindingHistory)` — drop the history table first, since its
   `on_delete=PROTECT` FK would otherwise block deleting bindings;
2. `RunPython(purge_soft_deleted_bindings)` — physically delete bindings with
   `deleted_at IS NOT NULL` (before the unconditional unique constraint is applied);
3. drop the partial `pb_unique_active_binding` / `pb_active_object_idx` (they referenced
   `deleted_at`), and drop the `deleted_at`/`deleted_by` fields;
4. `RenameField(created_at → created)` plus an `AlterField` to match `ChangeLoggedModel`'s
   definition (existing creation timestamps are preserved), and add `last_updated`;
5. add the new unconditional `pb_object_idx` and `pb_unique_binding`.

> **This migration is irreversible without a database backup**: the `PassworkBindingHistory`
> table and any soft-deleted bindings are permanently removed. The accumulated old history
> records are not carried over into `ObjectChange` — this was a deliberate choice, not an
> oversight.

---

## 5. Mini ERD

```
User (settings.AUTH_USER_MODEL, from NetBox core)
  │
  ├─(created_by, SET_NULL)──┐
  │                         ▼
  │                ┌────────────────────────┐
  │                │   PassworkBinding       │
  │                │  (ChangeLoggedModel)    │
  │                │  (object_type,          │
  │                │   object_id) ──────────────▶ Device / VirtualMachine / Service
  │                │                         │      (a NetBox object; a non-FK link
  │                │  passwork_item_id ─────────▶  by object_type + object_id;
  │                │  created / last_updated │      passwork_item_id points to
  │                └───────────┬─────────────┘      an item in the external Passwork)
  │                            │
  │                            │ create/delete inside an HTTP request
  │                            ▼
  │                ┌────────────────────────┐
  │                │  core.ObjectChange      │  ← NetBox's standard changelog
  │                │  (user, request_id,     │     (retention: CHANGELOG_RETENTION)
  │                │   action, pre/post-     │
  │                │   change snapshots)     │
  │                └────────────────────────┘
  │
  │                ┌────────────────────────┐
  └─(netbox_user,──▶  PassworkAuditLog       │
     SET_NULL)     │  action: reveal/copy    │
                    │  (passwork_item_id,     │
                    │   object_type,          │
                    │   object_id — no FK,    │
                    │   an independent copy   │
                    │   of the context at the │
                    │   time of the event)    │
                    └────────────────────────┘
```

Key relationships:

- `PassworkBinding.created_by` → `User` (FK, `SET_NULL`, `related_name="+"` — no reverse relation is created on the user model).
- `PassworkAuditLog.netbox_user` → `User` (FK, `SET_NULL`).
- `PassworkBinding.object_type` + `object_id` and `PassworkAuditLog.object_type` + `object_id` are **not FKs** — they're a denormalized "type + PK" pair identifying a NetBox object (device/vm/service); referential integrity for this link is not enforced at the database level.
- `PassworkBinding.passwork_item_id` and `PassworkAuditLog.passwork_item_id` identify an item in the external Passwork system, and are likewise not FKs (the external system doesn't live in this database).
- `core.ObjectChange.changed_object` → `PassworkBinding` via a generic FK (ContentType + object_id) — changelog records outlive the binding's deletion (they keep `object_repr` and data snapshots).

---

## Passwork secrets are not stored in the database

None of the plugin's models has a field for a password/secret value. `PassworkBinding` only
stores `passwork_item_id` — a reference to the item in Passwork — and `PassworkAuditLog` only
stores event metadata (who, when, which action, from which IP). The `prechange_data`/
`postchange_data` snapshots in `ObjectChange` only contain `PassworkBinding`'s own fields
(object type/ID, Passwork item ID) — no secret values live there either. The actual secret
values (`password`, and custom field values with `is_secret=True`) are fetched by the plugin
on the fly through proxy requests to the Passwork API (see `SecretDetailView` /
`SecretCopyView` in [views.py](../netbox_passwork/views.py)) and returned to the client in the
HTTP response, without ever being saved to any NetBox table. The fact that a secret was
revealed or copied is recorded in `PassworkAuditLog`, but the secret value itself is never
stored in that record.
