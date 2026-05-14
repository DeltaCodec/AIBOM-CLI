from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Optional

import requests
from cvss import CVSS3, CVSS4
from packaging.version import InvalidVersion, Version

from aibom.cache import osv_cache, vuln_cache

_OSV_URL = "https://api.osv.dev/v1/vulns/{}"
_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
_NVD_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

# NVD allows 5 req/30s without an API key — serialize calls with min 7s gap to stay safe
_nvd_lock = threading.Lock()
_nvd_last_call: float = 0.0
_NVD_MIN_INTERVAL = 7.0


@dataclass
class CVEDetail:
    vuln_id: str
    cve_id: Optional[str]
    aliases: list[str]
    description: str
    severity: str
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    installed_version: str
    fix_versions: list[str]
    suggestion: str
    published: Optional[str]
    modified: Optional[str]


def scan_cves_direct(deps: list, batch_size: int = 100) -> None:
    """Query OSV batch API and populate dep.vulnerabilities in-place.

    Works for any package/version — no pip-audit, no installation required.
    Packages with version 'unknown' or 'editable' are skipped.
    """
    queryable = [d for d in deps if d.version not in ("unknown", "editable", None, "")]
    if not queryable:
        return

    # Serve cached entries; only query uncached ones
    uncached = []
    for d in queryable:
        hit = osv_cache.get(f"{d.name}-{d.version}")
        if hit is not None:
            d.vulnerabilities = hit
        else:
            uncached.append(d)

    if not uncached:
        return

    # Process in batches to respect OSV limits
    for i in range(0, len(uncached), batch_size):
        batch = uncached[i : i + batch_size]
        queries = [
            {"package": {"name": d.name, "ecosystem": "PyPI"}, "version": d.version}
            for d in batch
        ]
        try:
            resp = requests.post(
                _OSV_BATCH_URL,
                json={"queries": queries},
                timeout=30,
            )
            resp.raise_for_status()
            results = resp.json().get("results", [])
            for dep, result in zip(batch, results):
                raw_vulns = result.get("vulns") or []
                dep.vulnerabilities = [
                    {
                        "id": v.get("id", ""),
                        "description": (v.get("summary") or v.get("details") or "")[:300],
                        "fix_versions": _osv_fix_versions(v),
                    }
                    for v in raw_vulns
                ]
                osv_cache.set(f"{dep.name}-{dep.version}", dep.vulnerabilities)
        except Exception:
            pass


def _osv_fix_versions(vuln: dict) -> list[str]:
    """Extract 'fixed' version strings from an OSV vulnerability entry."""
    fixes: set[str] = set()
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                fv = event.get("fixed")
                if fv:
                    fixes.add(fv)
    return sorted(fixes)


def enrich_cves(dependencies: list, max_workers: int = 8) -> dict[str, list[CVEDetail]]:
    """Query OSV API for each vuln and return {package: [CVEDetail]}.

    Vulns are already scoped to the installed version by pip-audit.
    Falls back to NVD API when OSV carries no severity data.
    """
    tasks: list[tuple[str, str, dict]] = []
    for dep in dependencies:
        for v in getattr(dep, "vulnerabilities", []):
            tasks.append((dep.name, dep.version, v))

    if not tasks:
        return {}

    results: dict[str, list[CVEDetail]] = {}

    def fetch(pkg: str, installed: str, v: dict) -> tuple[str, CVEDetail]:
        return pkg, _fetch_osv(v, installed)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(fetch, pkg, ver, v): (pkg, ver, v) for pkg, ver, v in tasks}
        for future in as_completed(futures):
            try:
                pkg, detail = future.result()
                results.setdefault(pkg, []).append(detail)
            except Exception:
                pkg, ver, v = futures[future]
                results.setdefault(pkg, []).append(_fallback(v, ver))

    for pkg in results:
        results[pkg].sort(key=lambda d: _SEVERITY_ORDER.get(d.severity, 0), reverse=True)

    return results


def _make_suggestion(installed: str, fix_versions: list[str]) -> str:
    if not fix_versions:
        return "No fix available — monitor for patches"
    try:
        inst = Version(installed)
        candidates = sorted(Version(fv) for fv in fix_versions if _is_valid_version(fv))
        above = [v for v in candidates if v > inst]
        if above:
            return f"Upgrade to {above[0]}"
        return "Already at or above fix version"
    except InvalidVersion:
        return f"Upgrade to {fix_versions[0]}"


def _is_valid_version(v: str) -> bool:
    try:
        Version(v)
        return True
    except InvalidVersion:
        return False


def _parse_cvss_severity(vector: str) -> tuple[str, Optional[float]]:
    """Return (severity_label, base_score) from a CVSS vector string."""
    try:
        if vector.startswith("CVSS:4"):
            obj = CVSS4(vector)
            return obj.severity.upper(), float(obj.base_score)
        obj = CVSS3(vector)
        return obj.severities()[0].upper(), float(obj.base_score)
    except Exception:
        return "UNKNOWN", None


def _fetch_ghsa_severity(ghsa_id: str) -> tuple[str, Optional[float], Optional[str]]:
    """Fetch severity from the GHSA entry in OSV — no rate limit, usually has CVSS."""
    cached = vuln_cache.get(f"ghsa-{ghsa_id}")
    if cached is not None:
        return tuple(cached)  # type: ignore[return-value]
    try:
        resp = requests.get(_OSV_URL.format(ghsa_id), timeout=10)
        resp.raise_for_status()
        data = resp.json()

        cvss_vector = None
        for sev in data.get("severity", []):
            if sev.get("type") in ("CVSS_V3", "CVSS_V4"):
                cvss_vector = sev.get("score")
                break

        db = data.get("database_specific", {})
        raw_sev = db.get("severity", "").upper()

        if raw_sev in _SEVERITY_ORDER:
            score = None
            if cvss_vector:
                _, score = _parse_cvss_severity(cvss_vector)
            result = (raw_sev, score, cvss_vector)
            vuln_cache.set(f"ghsa-{ghsa_id}", list(result))
            return result
        if cvss_vector:
            sev, score = _parse_cvss_severity(cvss_vector)
            result = (sev, score, cvss_vector)
            vuln_cache.set(f"ghsa-{ghsa_id}", list(result))
            return result
    except Exception:
        pass
    return "UNKNOWN", None, None


def _fetch_nvd_severity(cve_id: str) -> tuple[str, Optional[float], Optional[str]]:
    """Return (severity, score, vector) from NVD. Rate-limited to 1 call per 7s."""
    cached = vuln_cache.get(f"nvd-{cve_id}")
    if cached is not None:
        return tuple(cached)  # type: ignore[return-value]
    global _nvd_last_call
    with _nvd_lock:
        wait = _NVD_MIN_INTERVAL - (time.monotonic() - _nvd_last_call)
        if wait > 0:
            time.sleep(wait)
        try:
            resp = requests.get(_NVD_URL.format(cve_id), timeout=15)
            _nvd_last_call = time.monotonic()
            resp.raise_for_status()
            data = resp.json()
            metrics = data["vulnerabilities"][0]["cve"].get("metrics", {})
            for key in _NVD_METRIC_KEYS:
                entries = metrics.get(key, [])
                if entries:
                    d = entries[0].get("cvssData", {})
                    sev = d.get("baseSeverity", "UNKNOWN").upper()
                    score = d.get("baseScore")
                    vector = d.get("vectorString")
                    result = (sev, score, vector)
                    vuln_cache.set(f"nvd-{cve_id}", list(result))
                    return result
        except Exception:
            _nvd_last_call = time.monotonic()
    return "UNKNOWN", None, None


def _fetch_osv(v: dict, installed: str) -> CVEDetail:
    vid = v.get("id", "")
    fix_versions = v.get("fix_versions", [])

    cached = vuln_cache.get(f"osv-{vid}-{installed}")
    if cached is not None:
        return CVEDetail(**cached)

    try:
        resp = requests.get(_OSV_URL.format(vid), timeout=10)
        resp.raise_for_status()
        data = resp.json()

        aliases = data.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
        description = (data.get("details") or v.get("description") or "").strip()
        published = data.get("published")
        modified = data.get("modified")

        cvss_vector = None
        for sev in data.get("severity", []):
            if sev.get("type") in ("CVSS_V3", "CVSS_V4"):
                cvss_vector = sev.get("score")
                break

        db = data.get("database_specific", {})
        raw_sev = db.get("severity", "").upper()

        severity = "UNKNOWN"
        cvss_score = None

        if raw_sev in _SEVERITY_ORDER:
            severity = raw_sev
            if cvss_vector:
                _, cvss_score = _parse_cvss_severity(cvss_vector)
        elif cvss_vector:
            severity, cvss_score = _parse_cvss_severity(cvss_vector)

        # Still unknown — try GHSA alias (same OSV API, no rate limit, has CVSS for most entries)
        if severity == "UNKNOWN":
            ghsa_id = next((a for a in aliases if a.startswith("GHSA-")), None)
            if ghsa_id:
                severity, cvss_score, ghsa_vector = _fetch_ghsa_severity(ghsa_id)
                if ghsa_vector and not cvss_vector:
                    cvss_vector = ghsa_vector

        # Last resort — NVD API (rate-limited, only if GHSA also failed)
        if severity == "UNKNOWN" and cve_id:
            severity, cvss_score, nvd_vector = _fetch_nvd_severity(cve_id)
            if nvd_vector and not cvss_vector:
                cvss_vector = nvd_vector

        detail = CVEDetail(
            vuln_id=vid,
            cve_id=cve_id,
            aliases=aliases,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            installed_version=installed,
            fix_versions=fix_versions,
            suggestion=_make_suggestion(installed, fix_versions),
            published=published,
            modified=modified,
        )
        vuln_cache.set(f"osv-{vid}-{installed}", asdict(detail))
        return detail
    except Exception:
        return _fallback(v, installed)


def _fallback(v: dict, installed: str) -> CVEDetail:
    vid = v.get("id", "")
    fix_versions = v.get("fix_versions", [])
    return CVEDetail(
        vuln_id=vid,
        cve_id=vid if vid.startswith("CVE-") else None,
        aliases=[],
        description=v.get("description", ""),
        severity="UNKNOWN",
        cvss_score=None,
        cvss_vector=None,
        installed_version=installed,
        fix_versions=fix_versions,
        suggestion=_make_suggestion(installed, fix_versions),
        published=None,
        modified=None,
    )
