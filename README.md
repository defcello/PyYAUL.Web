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
import pathlib, sys
_ROOT = pathlib.Path(__file__).parent.parent  # devenv root
sys.path.append(str(_ROOT / 'PyYAUL.Base'))
sys.path.append(str(_ROOT / 'PyYAUL.DB'))
sys.path.append(str(_ROOT / 'PyYAUL.Web'))
```

## Usage

```python
from pyyaul.web.auth.db.schema.v0 import SchemaV0_Base
from pyyaul.web.auth.db.model import DBModelContext
from pyyaul.web.auth.blueprint import BlueprintContext, flaskApp_proxyFix_apply

# 1. Define your schema (parameterized by PostgreSQL schema names)
class MySchema(SchemaV0_Base):
    def __init__(self):
        super().__init__('myapp_accounts', 'myapp_sessions')

# 2. Wire up the DB context
ctx = DBModelContext(orm_ro, orm_rw, sessions_orm_ro, sessions_orm_rw, MySchema())

# 3. Trust forwarded headers if the app runs behind a reverse proxy
flaskApp_proxyFix_apply(app, cfgGet('FLASK', 'PROXY_FIX', {}))

# 4. Register the Flask blueprint
blueprint_ctx = BlueprintContext('myapp', ctx, ...)
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

- IP rate limiting is backed by `table_user_login`, so it survives process restarts and works consistently with shared PostgreSQL-backed deployments.
- Per-user POST rate limiting is also **in-memory** and intended for single-instance deployments.
- UPGRADE AT YOUR OWN RISK — backwards compatibility is not guaranteed between versions.

## License

MIT
