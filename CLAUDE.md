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
