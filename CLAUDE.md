# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

**PyYAUL.Web** is a generic Python/Flask web authentication framework extracted from SkillTrails. It provides login/logout routes, CSRF protection, rate limiting, account lockout, and the ORM layer for user accounts and sessions.

This repo is one of several sub-repos managed under `devenv-skilltrails/` via `manifest.xml`.

## Architecture

```
__init__.py                     — guardian: raises ImportError (namespace package)
pyyaul/web/auth/
    blueprint.py                — BlueprintContext: Flask routes (login, logout, CSRF, rate limit)
    model.py                    — account creation, password set/change helpers
    db/
        model.py                — DBModelContext: 40+ ORM methods for accounts + sessions
        schema/
            v0.py               — SchemaV0_Base (parameterized by schema names), SchemaV0 (defaults)
            vLatest.py          — alias for latest version
pyyaul/web/compliance/
    blueprint.py            — BlueprintContext: Flask routes for reviews/findings/action items
    cli.py                  — ComplianceCLIBase: standalone CLI (no Flask) for log entries
    db/
        model.py            — DBModelContext: CRUD methods for compliance tables
        schema/
            v0.py           — ComplianceSchemaV0_Base (parameterized by schema name)
            vLatest.py      — alias for latest version
test.py                         — test runner; adds PyYAUL.Base + PyYAUL.DB to sys.path
```

`pyyaul/` has no `__init__.py` — implicit namespace package (matches PyYAUL.Base/DB convention).

## Commands

```bash
# Run tests
py -3.12 test.py
```

No pytest; tests use `pyyaul.base.unittest`. Discovers `**/_test/test*.py`.

## Dependencies

Sibling repos (added to `sys.path` in `test.py` and consumer `_execommon.py`):
- `../PyYAUL.Base` — base utilities and test framework
- `../PyYAUL.DB` — SQLAlchemy versioning base

No `pip install` required; no `pyproject.toml`.

## Consumers

- `skilltrails-admin`: `from pyyaul.web.auth.blueprint import BlueprintContext`
- `skilltrails-initdb`: indirect (via skilltrails-admin imports)

## Reverse Proxy Deployments

`BlueprintContext` uses `flask.request.remote_addr` for login IP rate limiting
and login audit logging. Consumer apps deployed behind a reverse proxy must
apply `flaskApp_proxyFix_apply(app, cfgGet('FLASK', 'PROXY_FIX', {}))` before
registering the blueprint so forwarded client IPs are trusted correctly.

For public HTTPS deployments, consumers can also opt into
`flaskApp_httpsRedirect_apply(...)` after `ProxyFix` so plaintext requests are
redirected to HTTPS while localhost development stays exempt by default. HSTS
is only emitted on HTTPS responses.

Use a `cfg.json` shape like:

```json
{
  "FLASK": {
    "PROXY_FIX": {
      "x_for": 1,
      "x_proto": 1,
      "x_host": 1
    }
  }
}
```

`x_for` must match the exact number of trusted proxy hops. Setting it higher
than the real deployment topology allows spoofed forwarded headers.

## Compliance Module Pattern

Compliance-oriented consumers keep their Flask routes in a subpackage such as
`modules/compliance/`, with route registration handled in `blueprint.py` and
database access in `db/model.py`. Shared schema base classes live in PyYAUL.Web,
while the concrete `wolc_compliance` schema is instantiated by `skilltrails-initdb`.

The module also provides `pyyaul/web/compliance/cli.py` — a reusable
`ComplianceCLIBase` class (no Flask dependency) that consumers can wrap to
create a standalone CLI script for adding log entries directly to the database.
See `skilltrails-admin/log_compliance.py` for the SkillTrails-configured wrapper.
