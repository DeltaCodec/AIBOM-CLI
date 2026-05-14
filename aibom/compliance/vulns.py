from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .cve import CVEDetail


@dataclass
class VulnSummary:
    total_packages: int
    vulnerable_packages: int
    total_vulnerabilities: int
    critical: list[dict]
    all_vulns: list[dict]
    by_package: dict[str, list["CVEDetail"]] = field(default_factory=dict)


def summarize_vulnerabilities(dependencies: list) -> VulnSummary:
    all_vulns = []
    vulnerable_packages = 0

    for dep in dependencies:
        vulns = getattr(dep, "vulnerabilities", [])
        if vulns:
            vulnerable_packages += 1
            for v in vulns:
                all_vulns.append({
                    "package": dep.name,
                    "version": dep.version,
                    "vuln_id": v.get("id", ""),
                    "description": v.get("description", ""),
                    "fix_versions": v.get("fix_versions", []),
                })

    critical = [v for v in all_vulns if not v["fix_versions"]]

    return VulnSummary(
        total_packages=len(dependencies),
        vulnerable_packages=vulnerable_packages,
        total_vulnerabilities=len(all_vulns),
        critical=critical,
        all_vulns=all_vulns,
    )
