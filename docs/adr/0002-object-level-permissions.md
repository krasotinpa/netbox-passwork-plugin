---
status: accepted
date: 2026-08-23
---

# Secret access requires view access to the bound object; out-of-constraint means 404

Every secret operation scoped to a NetBox object (secrets list, detail, reveal, copy, binding
create, binding delete) requires — on top of the plugin's own model-level permission — `view`
access to the bound object (`dcim.view_device` / `virtualization.view_virtualmachine` /
`ipam.view_service`), evaluated against the user's `ObjectPermission` constraints via
`restrict()` (issue #1). A user who cannot open the device page cannot touch its secrets, even
knowing the `object_type`/`object_id`. Before this, plugin permissions were checked at the model
level only, so constraints like "devices of site A only" did not separate secrets between teams.

An object that exists but falls outside the user's constraints is answered with **404**, not 403 —
the same convention NetBox core uses (an out-of-constraint object is reported as non-existent;
403 is reserved for a missing model-level permission). The issue's original acceptance criterion
said 403; it was superseded during design (see the issue comments). The object check runs
*before* the binding lookup, so the response never discloses whether a hidden object has secrets.
On binding deletion a hidden object yields `binding_not_found`, because there the client
addresses the binding, not the object.

Orphaned bindings (the bound object was deleted; bindings reference objects by plain
`object_type`/`object_id`, not a foreign key) are unreadable for everyone, but deletable with the
plugin's `delete_binding` permission alone — otherwise leftovers could never be cleaned up, since
there is no object left to check access against.

Creating and deleting a binding requires only `view` on the object, not `change`: a binding is
plugin data, not object data, and the plugin's own `add_binding`/`delete_binding` permissions
already separate who may manage bindings.

## Considered options

- 403 for an out-of-constraint object (as the issue originally said) — rejected: NetBox core
  answers 404 there, and the plugin should not leak more about hidden objects than NetBox itself.
- Checking constraints against the `PassworkBinding` record — rejected: the binding stores only
  `object_type` and an integer `object_id`, so constraints like "site A only" cannot be expressed
  on it; only the real object carries the fields constraints refer to.
- Requiring `change` on the object for binding create/delete — rejected: too strict; the plugin's
  own permissions already gate binding management, and the object gate is about *which* objects a
  user may see, not what they may edit.
- Forbidding deletion of orphaned bindings without an object to check — rejected: they would
  become undeletable garbage.
