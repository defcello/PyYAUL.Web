"""
Local developer bootstrap for sibling PyYAUL repos.

Python imports `sitecustomize` automatically during startup when it can be
found on `sys.path`. Keeping this file at the repo root means commands run from
the PyYAUL.Web checkout automatically see sibling PyYAUL.Base and PyYAUL.DB
repos without requiring callers to set `PYTHONPATH` manually.
"""

from pathlib import Path
import sys


_ROOT = Path(__file__).resolve().parent


def _sys_path_add(path: Path) -> None:
    resolved = path.resolve()
    value = str(resolved)
    if resolved.exists() and value not in sys.path:
        sys.path.append(value)


_sys_path_add(_ROOT)
_sys_path_add(_ROOT.parent / 'PyYAUL.Base')
_sys_path_add(_ROOT.parent / 'PyYAUL.DB')
