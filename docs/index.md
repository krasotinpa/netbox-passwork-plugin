# netbox-passwork knowledge base

`netbox-passwork` is a NetBox (4.5+) plugin that integrates the Passwork password manager. The
plugin adds a **Passwork** tab to Device, Virtual Machine, and Service pages, from which a user
can view secret metadata, reveal/copy the password, and bind or unbind Passwork secrets to and
from NetBox objects — without leaving the NetBox interface. All calls to the Passwork API are
proxied through the plugin's backend: the browser never receives Passwork tokens directly, they
are stored encrypted in the server-side Django session.

## Table of contents

- [architecture.md](architecture.md) — plugin architecture and module responsibilities
- [data-model.md](data-model.md) — data models and migrations
- [api.md](api.md) — the plugin's HTTP routes
- [passwork-integration.md](passwork-integration.md) — Passwork API integration (auth, tokens, session encryption)
- [security.md](security.md) — security model and known limitations
- [development.md](development.md) — development, tests, releases
- [adr/](adr/) — architecture decision records (currently one: [0001](adr/0001-passwork-gateway-not-middleware.md) — Passwork gateway instead of a middleware mixin)

## Change process

The project requires a strict **branch + pull request** workflow, mandatory for both humans and
AI agents (see [CONTRIBUTING.md](../CONTRIBUTING.md)):

- No direct commits to `main` — every task is developed on its own branch, one task per branch.
- Changes land in `main` only through a PR.
- Branch naming: `feature/<description>`, `fix/<description>`, `docs/<description>`,
  `chore/<description>` (kebab-case).
- **A PR is merged only after a maintainer has explicitly approved it.** For AI agents this
  is spelled out as a mandatory rule: an agent does not open or merge a PR until the maintainer
  has explicitly confirmed it.
- Before opening a PR: behavioral changes must be covered by tests, the documentation (`docs/`)
  must stay consistent with the change, and the PR must not include unrelated refactoring.

## Related documents

- [README.md](../README.md) — installation, configuration, access control (RBAC), upgrade/rollback process
- [CHANGELOG.md](../CHANGELOG.md) — version history
- [CONTRIBUTING.md](../CONTRIBUTING.md) — contribution process (branches, PRs, maintainer approval)
