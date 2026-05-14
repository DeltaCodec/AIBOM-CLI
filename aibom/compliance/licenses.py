from __future__ import annotations

import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote

import requests

_PYPI_URL = "https://pypi.org/pypi/{name}/{version}/json"
_CLASSIFIER_PREFIX = "License :: OSI Approved :: "

DEFAULT_ALLOWLIST = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "Python-2.0", "PSF-2.0", "MPL-2.0", "LGPL-2.1",
    "Unlicense", "CC0-1.0", "0BSD",
}

SPDX_ALIASES = {
    "Apache 2.0": "Apache-2.0",
    "Apache2": "Apache-2.0",
    "Apache License 2.0": "Apache-2.0",
    "Apache Software License": "Apache-2.0",
    "MIT License": "MIT",
    "BSD": "BSD-3-Clause",
    "BSD License": "BSD-3-Clause",
    "BSD 2-Clause": "BSD-2-Clause",
    "BSD 3-Clause": "BSD-3-Clause",
    "GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.1",
    "GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.1",
    "GNU General Public License v2 (GPLv2)": "GPL-2.0",
    "GNU General Public License v3 (GPLv3)": "GPL-3.0",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "ISC License (ISCL)": "ISC",
    "ISC License": "ISC",
    "Public Domain": "Unlicense",
    "Python Software Foundation License": "PSF-2.0",
    "Historical Permission Notice and Disclaimer (HPND)": "HPND",
}

COPYLEFT = {"GPL-2.0", "GPL-3.0", "LGPL-2.1", "LGPL-3.0", "AGPL-3.0", "MPL-2.0"}


@dataclass
class LicenseResult:
    package: str
    version: str
    license: Optional[str]
    spdx_id: Optional[str]
    allowed: bool
    copyleft: bool
    source: str = "unknown"   # "pypi" | "local" | "unknown"


def check_licenses(
    packages: list,
    allowlist: set[str] | None = None,
    use_pypi: bool = True,
    max_workers: int = 16,
) -> list[LicenseResult]:
    if allowlist is None:
        allowlist = DEFAULT_ALLOWLIST

    pypi_map: dict[str, tuple[str, str]] = {}  # name -> (raw_license, source)
    if use_pypi:
        pypi_map = _fetch_pypi_licenses(packages, max_workers)

    local_map = _local_licenses()

    results = []
    for dep in packages:
        key = dep.name.lower()

        if key in pypi_map:
            raw, source = pypi_map[key]
        else:
            raw_local = local_map.get(dep.name) or local_map.get(key)
            raw = raw_local or "UNKNOWN"
            source = "local" if raw_local else "unknown"

        spdx = _normalize(raw) if raw and raw != "UNKNOWN" else None
        allowed = spdx in allowlist if spdx else False
        copyleft = spdx in COPYLEFT if spdx else False

        results.append(LicenseResult(
            package=dep.name,
            version=dep.version,
            license=raw,
            spdx_id=spdx,
            allowed=allowed,
            copyleft=copyleft,
            source=source,
        ))

    return results


def _fetch_pypi_licenses(
    packages: list,
    max_workers: int,
) -> dict[str, tuple[str, str]]:
    """Query PyPI JSON API concurrently. Returns {name_lower: (raw_license, "pypi")}."""
    results: dict[str, tuple[str, str]] = {}

    def fetch(name: str, version: str) -> tuple[str, Optional[str]]:
        try:
            safe_name = quote(name, safe="")
            safe_version = quote(version, safe="")
            url = _PYPI_URL.format(name=safe_name, version=safe_version)
            resp = requests.get(url, timeout=10)
            if resp.status_code == 404:
                # version not on PyPI (editable/local) — try without version
                resp = requests.get(
                    f"https://pypi.org/pypi/{safe_name}/json", timeout=10
                )
            resp.raise_for_status()
            info = resp.json().get("info", {})
            lic_field = info.get("license") or ""
            raw = (
                info.get("license_expression")                          # PEP 639 SPDX — most precise
                or (lic_field if len(lic_field) <= 64 else None)        # skip full license texts
                or _license_from_classifiers(info.get("classifiers") or [])
            )
            return name.lower(), raw or "UNKNOWN"
        except Exception:
            return name.lower(), None

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(fetch, dep.name, dep.version): dep.name
            for dep in packages
            if dep.version != "editable"
        }
        for future in as_completed(futures):
            key, raw = future.result()
            if raw:
                results[key] = (raw, "pypi")

    return results


def _local_licenses() -> dict[str, str]:
    """pip-licenses → importlib.metadata fallback."""
    try:
        import json as _json
        result = subprocess.run(
            [sys.executable, "-m", "piplicenses", "--format", "json", "--with-system"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = _json.loads(result.stdout)
            return {e["Name"]: e.get("License", "UNKNOWN") for e in data}
    except Exception:
        pass
    return _importlib_licenses()


def _importlib_licenses() -> dict[str, str]:
    try:
        from importlib.metadata import packages_distributions, metadata
        result = {}
        for pkg in packages_distributions():
            try:
                meta = metadata(pkg)
                lic = meta.get("License") or meta.get("License-Expression")
                if not lic:
                    lic = _license_from_classifiers(meta.get_all("Classifier") or [])
                result[pkg] = lic or "UNKNOWN"
            except Exception:
                pass
        return result
    except Exception:
        return {}


def _license_from_classifiers(classifiers: list[str]) -> Optional[str]:
    for c in classifiers:
        if c.startswith(_CLASSIFIER_PREFIX):
            return c[len(_CLASSIFIER_PREFIX):]
    return None


def _normalize(license_str: str) -> Optional[str]:
    if not license_str:
        return None
    stripped = license_str.strip()
    if stripped in SPDX_ALIASES:
        return SPDX_ALIASES[stripped]
    for alias, spdx in SPDX_ALIASES.items():
        if alias.lower() in stripped.lower():
            return spdx
    return stripped
