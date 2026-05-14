from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Dependency:
    name: str
    version: str
    license: Optional[str] = None
    vulnerabilities: list[dict] = field(default_factory=list)


def scan_dependencies(project_path: str) -> list[Dependency]:
    """Collect installed packages scoped to the project's requirements when present.
    CVE data is populated separately via scan_cves_direct()."""
    required = _read_requirements(project_path)   # None = no req file → full env
    packages = _pip_freeze()

    deps = []
    for name, version in packages.items():
        if required is not None and name.lower() not in required:
            continue
        deps.append(Dependency(name=name, version=version))
    return deps


def _read_requirements(project_path: str) -> Optional[set[str]]:
    """Return lowercased package names from requirements files, or None if none found."""
    root = Path(project_path)
    names: set[str] = set()
    found = False

    # requirements.txt / requirements/*.txt
    for req_file in list(root.glob("requirements*.txt")) + list(root.glob("requirements/*.txt")):
        found = True
        names.update(_parse_requirements_txt(req_file))

    # pyproject.toml [project].dependencies
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        found = True
        names.update(_parse_pyproject(pyproject))

    # setup.cfg [options] install_requires
    setup_cfg = root / "setup.cfg"
    if setup_cfg.exists():
        found = True
        names.update(_parse_setup_cfg(setup_cfg))

    return names if found else None


def _parse_requirements_txt(path: Path) -> set[str]:
    names: set[str] = set()
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # strip version specifiers: requests>=2.0,<3 → requests
            pkg = line.split(";")[0].strip()         # drop env markers
            for op in ("==", ">=", "<=", "!=", "~=", ">", "<", "[", "@"):
                pkg = pkg.split(op)[0].strip()
            if pkg:
                names.add(pkg.lower().replace("-", "_"))
                names.add(pkg.lower())
    except Exception:
        pass
    return names


def _parse_pyproject(path: Path) -> set[str]:
    names: set[str] = set()
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            return names
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        deps = data.get("project", {}).get("dependencies", [])
        for dep in deps:
            pkg = dep.split(";")[0].strip()
            for op in ("==", ">=", "<=", "!=", "~=", ">", "<", "["):
                pkg = pkg.split(op)[0].strip()
            if pkg:
                names.add(pkg.lower().replace("-", "_"))
                names.add(pkg.lower())
    except Exception:
        pass
    return names


def _parse_setup_cfg(path: Path) -> set[str]:
    names: set[str] = set()
    try:
        import configparser
        cfg = configparser.ConfigParser()
        cfg.read(path)
        raw = cfg.get("options", "install_requires", fallback="")
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            pkg = line.split(";")[0].strip()
            for op in ("==", ">=", "<=", "!=", "~=", ">", "<", "["):
                pkg = pkg.split(op)[0].strip()
            if pkg:
                names.add(pkg.lower().replace("-", "_"))
                names.add(pkg.lower())
    except Exception:
        pass
    return names


def _pip_freeze() -> dict[str, str]:
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "freeze", "--all"],
            capture_output=True, text=True, timeout=60,
        )
    except (subprocess.TimeoutExpired, OSError):
        return {}
    packages: dict[str, str] = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if "==" in line:
            name, version = line.split("==", 1)
            packages[name] = version
        elif " @ " in line:
            name = line.split(" @ ")[0].strip()
            packages[name] = "editable"
    return packages


