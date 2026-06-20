from pathlib import Path
import getpass
import os
import subprocess
_RESTRICTED_PATHS: set[str] = set()

def restrict_private_path(path: str | Path) -> None:
    """Best-effort local permission hardening for DB and private key material."""
    target = Path(path)
    if not target.exists():
        return
    resolved = str(target.resolve())
    if resolved in _RESTRICTED_PATHS:
        return
    try:
        os.chmod(target, 448 if target.is_dir() else 384)
    except OSError:
        pass
    if os.name == 'nt':
        grants = _windows_grants(target.is_dir())
        try:
            subprocess.run(['icacls', str(target), '/inheritance:r', '/grant:r', *grants], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        except OSError:
            pass
    _RESTRICTED_PATHS.add(resolved)

def _windows_grants(is_dir: bool) -> list[str]:
    suffix = ':(OI)(CI)F' if is_dir else ':F'
    current_user = getpass.getuser()
    return [f'{current_user}{suffix}', f'*S-1-5-18{suffix}', f'*S-1-5-32-544{suffix}']