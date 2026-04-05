# PyYAUL.Web

A Flask + SQLAlchemy library for building authenticated web experiences.
Part of the [PyYAUL](https://github.com/defcello/PyYAUL.Base) family. YAUL stands
for "Yet Another Utility Library," a nod to YAML's original expansion, "Yet
Another Markup Language."

This package is the Python counterpart to
[`goyaul-web`](https://github.com/defcello/goyaul-web).

## What's included

**`pyyaul.web.auth`** — Complete authentication and authorization framework:
- Flask blueprint: login/logout routes, CSRF protection, database-backed IP rate limiting, per-user POST rate limiting, brute-force lockout escalation
- Business logic: create/delete accounts, set passwords, privilege checks
- Database layer: parameterized PostgreSQL schema (accounts + sessions + RBAC privilege hierarchy)
- ORM model: 40+ methods for accounts, sessions, groups, and privileges

**`pyyaul.web.execommon`** - Shared `cfg.json` bootstrap utilities for
PyYAUL.Web-based applications:
- Creates `cfg.json` on first run
- Fills in missing nested defaults without overwriting existing values
- Exposes a context object with `cfgGet(...)` and `cfgSet(...)`
- Lets derived projects compose shared auth/web defaults with their own
  project-specific sections

## Requirements

- Python 3.8+
- [PyYAUL.Base](https://github.com/defcello/PyYAUL.Base) (sibling repo)
- [PyYAUL.DB](https://github.com/defcello/PyYAUL.DB) (sibling repo)
- Flask
- SQLAlchemy
- bcrypt

## Installation

Clone as a sibling repo alongside PyYAUL.Base and PyYAUL.DB, then add the repo
root to `sys.path`:

```python
import pathlib
import sys
_ROOT = pathlib.Path(__file__).parent.parent  # devenv root
sys.path.append(str(_ROOT / 'PyYAUL.Base'))
sys.path.append(str(_ROOT / 'PyYAUL.DB'))
sys.path.append(str(_ROOT / 'PyYAUL.Web'))
```

## Usage

### `cfg.json` in a derived project

PyYAUL.Web is meant to be embedded in a derived application. Each derived
project owns its own `cfg.json`, usually in that project's repo root, while
`pyyaul.web.execommon` owns the common logic for creating and extending that
file.

The intended lifecycle is:

1. Define the defaults your project wants to guarantee.
2. Call `pyyaul.web.execommon.init(...)` from your project's `_execommon.py`.
3. Let first run create `cfg.json`.
4. Edit `cfg.json` with real secrets and deployment values.
5. Add new defaults over time without clobbering values users already set.

This is important because `cfg.json` is not just a sample file. It is the live
configuration file for the derived project.

### Bootstrapping `cfg.json`

```python
from pathlib import Path

from pyyaul.web import execommon as web_execommon


PATHROOTDIR = Path(__file__).parent.resolve()

CFGDEFAULTS = web_execommon.cfgDefaults_merge(
    web_execommon.cfgDefaults_flask_make(port=82),
    web_execommon.cfgDefaults_authPostgres_make(schema_prefix='myapp'),
    {
        'APP': {
            'NAME': 'myapp',
        },
        'MYAPP': {
            'FEATURE_FLAG_X': False,
        },
    },
)

WEBCTX = web_execommon.init(PATHROOTDIR, CFGDEFAULTS)
```

On first run this creates `cfg.json`. On later runs it preserves existing
values, but fills in any newly-added default keys that are still missing.

The returned context gives you:

- `WEBCTX.cfgGet(component, keys, default=None, setDefaultIfMissing=True)`
- `WEBCTX.cfgSet(component, keys, value)`
- `WEBCTX.cfgFilePath`
- `WEBCTX.cfgDefaults`

Many projects will re-export thin wrappers from their own `_execommon.py`:

```python
def cfgGet(component, keys, default=None, setDefaultIfMissing=True):
    return web_execommon.cfgGet(component, keys, default, setDefaultIfMissing)


def cfgSet(component, keys, value):
    return web_execommon.cfgSet(component, keys, value)
```

### Shared default helpers

`pyyaul.web.execommon` currently provides these helpers:

- `cfgDefaults_flask_make(...)`
  Use this for common Flask host/port/debug settings and shared DB SSL mode.
- `cfgDefaults_postgresRoot_make(...)`
  Use this for a root/admin PostgreSQL connection section.
- `cfgDefaults_postgresRolePair_make(...)`
  Use this for a single RO/RW PostgreSQL config section.
- `cfgDefaults_authPostgres_make(...)`
  Use this for the standard PyYAUL.Web auth-related PostgreSQL sections:
  `DB_ROOT`, `DB_USERACCOUNTS`, `DB_USERSESSIONS`, `DB_ADMINACCOUNTS`,
  `DB_ADMINSESSIONS`, and shared `DB.SSL_MODE`.
- `cfgDefaults_merge(...)`
  Use this to recursively combine shared defaults with project-specific ones.

### Example generated `cfg.json`

```json
{
  "APP": {
    "NAME": "myapp"
  },
  "DB": {
    "SSL_MODE": "require"
  },
  "DB_ADMINACCOUNTS": {
    "DBNAME": "myapp_adminaccounts",
    "HOST": "127.0.0.1",
    "PORT": "5432",
    "RO_PASS": "password",
    "RO_USER": "user",
    "RW_PASS": "password",
    "RW_USER": "user",
    "SCHEMANAME": "myapp_adminaccounts"
  },
  "DB_ADMINSESSIONS": {
    "DBNAME": "myapp_adminsessions",
    "HOST": "127.0.0.1",
    "PORT": "5432",
    "RO_PASS": "password",
    "RO_USER": "user",
    "RW_PASS": "password",
    "RW_USER": "user",
    "SCHEMANAME": "myapp_adminsessions"
  },
  "DB_ROOT": {
    "DBNAME": "",
    "HOST": "127.0.0.1",
    "PORT": "5432",
    "ROOT_PASS": "password",
    "ROOT_USER": "user"
  },
  "DB_USERACCOUNTS": {
    "DBNAME": "myapp_useraccounts",
    "HOST": "127.0.0.1",
    "PORT": "5432",
    "RO_PASS": "password",
    "RO_USER": "user",
    "RW_PASS": "password",
    "RW_USER": "user",
    "SCHEMANAME": "myapp_useraccounts"
  },
  "DB_USERSESSIONS": {
    "DBNAME": "myapp_usersessions",
    "HOST": "127.0.0.1",
    "PORT": "5432",
    "RO_PASS": "password",
    "RO_USER": "user",
    "RW_PASS": "password",
    "RW_USER": "user",
    "SCHEMANAME": "myapp_usersessions"
  },
  "FLASK": {
    "DEBUG": false,
    "HOST": "0.0.0.0",
    "PORT": 82,
    "PROXY_FIX": {
      "x_for": 1,
      "x_host": 1,
      "x_proto": 1
    }
  },
  "MYAPP": {
    "FEATURE_FLAG_X": false
  }
}
```

### Extending `cfg.json` for your own app

Derived projects are expected to add their own sections on top of the shared
PyYAUL.Web defaults.

For example:

```python
CFGDEFAULTS = web_execommon.cfgDefaults_merge(
    web_execommon.cfgDefaults_flask_make(port=5000),
    web_execommon.cfgDefaults_authPostgres_make(schema_prefix='acme'),
    web_execommon.cfgDefaults_postgresRolePair_make(
        'DB_REPORTING',
        'acme_reporting',
        schemaname='acme_reporting',
    ),
    {
        'APP': {
            'NAME': 'acme-admin',
        },
        'REPORTS': {
            'TIMEZONE': 'UTC',
        },
        'SMTP': {
            'HOST': '127.0.0.1',
            'PORT': 25,
        },
    },
)
```

Because `cfgDefaults_merge(...)` is recursive, a project can override part of a
shared section without rewriting the whole structure. For example, a project
can replace only `FLASK.PORT` while keeping the default `FLASK.PROXY_FIX`
layout.

### Wiring the auth blueprint

```python
from pyyaul.web import execommon as web_execommon
from pyyaul.web.auth.db.schema.v0 import SchemaV0_Base
from pyyaul.web.auth.db.model import DBModelContext
from pyyaul.web.auth.blueprint import BlueprintContext, flaskApp_proxyFix_apply

# 1. Define your schema (parameterized by PostgreSQL schema names)
class MySchema(SchemaV0_Base):
    def __init__(self):
        super().__init__('myapp_adminaccounts', 'myapp_adminsessions')

# 2. Initialize cfg.json for this project
WEBCTX = web_execommon.init(PATHROOTDIR, CFGDEFAULTS)

# 3. Wire up the DB context
ctx = DBModelContext(
    orm_accounts_ro,
    orm_accounts_rw,
    orm_sessions_ro,
    orm_sessions_rw,
    MySchema,
)

# 4. Trust forwarded headers if the app runs behind a reverse proxy
flaskApp_proxyFix_apply(app, WEBCTX.cfgGet('FLASK', 'PROXY_FIX', {}))

# 5. Register the Flask blueprint
blueprint_ctx = BlueprintContext('adminauth', __name__, ctx)
app.register_blueprint(blueprint_ctx.blueprint)
```

If your app is deployed behind nginx, an AWS load balancer, Heroku, or another
reverse proxy, configure Werkzeug `ProxyFix` before registering the blueprint so
`flask.request.remote_addr` reflects the real client IP for login rate limiting
and audit logs:

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

Set `x_for` to the exact number of trusted proxy hops in front of the app.
Setting it higher than your real proxy chain allows spoofed `X-Forwarded-For`
headers and undermines IP-based protections.

Protected POST handlers can also opt into per-user throttling:

```python
@blueprint_ctx.blueprint.route('/account/password', methods=['POST'])
@blueprint_ctx.authSessionRequired
@blueprint_ctx.userRateLimit(max_requests=10, window_seconds=60)
def page_account_password(myapp_authsession_session_record):
    ...
```

## Notes

- `cfg.json` should never be committed with real secrets.
- IP rate limiting is backed by `table_user_login`, so it survives process restarts and works consistently with shared PostgreSQL-backed deployments.
- Per-user POST rate limiting is also **in-memory** and intended for single-instance deployments.
- UPGRADE AT YOUR OWN RISK — backwards compatibility is not guaranteed between versions.

## License

MIT
