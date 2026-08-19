---
status: accepted
date: 2026-08-17
---

# Passwork gateway — not Django middleware; Passwork errors carry HTTP meaning

The plugin should not require the NetBox administrator to edit `MIDDLEWARE` in
`configuration.py`, so the Passwork gateway is obtained from within the plugin — through a base
view (`dispatch` builds the gateway from `request`, checks the Passwork session up front when
needed, and translates gateway exceptions into JSON) rather than through actual Django middleware
or a mixin that returns "client or JsonResponse". Gateway exceptions carry a `code` and
`http_status` because the meaning of a given Passwork failure is only known inside the operation
that produced it (a login failure is 401 `invalid_credentials`, a secret-read failure is 403
`pw_access_denied`); "plain" exceptions would have forced every view to keep its own translation
table (15 `except` blocks across three different body formats).

## Considered options

- Actual Django middleware placing the gateway on `request` — rejected: requires every plugin
  user to edit their NetBox configuration.
- A `_get_pw_client()` mixin returning `tuple | JsonResponse` (the state before 1.3.0) — rejected:
  the union type pushes branching into every view, and error translation ends up scattered.
- "Plain" exceptions plus a translation table in the base view — rejected: error context is lost
  by the time translation happens.
