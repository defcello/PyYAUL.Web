from pathlib import Path
import sys


_ROOT = Path(__file__).resolve().parents[4]


def _sys_path_add(path: Path) -> None:
    resolved = path.resolve()
    value = str(resolved)
    if resolved.exists() and value not in sys.path:
        sys.path.append(value)


_sys_path_add(_ROOT)
_sys_path_add(_ROOT.parent / 'PyYAUL.Base')
_sys_path_add(_ROOT.parent / 'PyYAUL.DB')
