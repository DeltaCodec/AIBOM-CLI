"""Tests for compliance verdict logic."""


def _verdict(bom: dict) -> str:
    """
    Reproduce the verdict logic from _print_compliance_summary without Rich output.
    Returns 'COMPLIANT', 'NEEDS ATTENTION', or 'ACTION REQUIRED'.
    """
    s = bom.get("summary", {})
    elements = bom.get("elements", [])
    statuses = []

    # Licenses
    if s.get("nonCompliantLicenses", 0) == 0:
        statuses.append("green")
    else:
        statuses.append("red")

    # Vulnerabilities
    total_cves = s.get("totalCVEs", 0)
    sev = s.get("cveSeverityCounts", {})
    critical_high = sev.get("CRITICAL", 0) + sev.get("HIGH", 0)
    no_fix = sum(
        1 for cves in bom.get("cvesByPackage", {}).values()
        for c in cves
        if "No fix" in c.get("suggestion", "") and c.get("severity") in ("CRITICAL", "HIGH")
    )
    if total_cves == 0:
        statuses.append("green")
    elif no_fix > 0:
        statuses.append("red")
    elif critical_high > 0:
        statuses.append("amber")
    else:
        statuses.append("amber")

    # Privacy
    gdpr_flags = bom.get("gdprFlags", [])
    if not gdpr_flags:
        statuses.append("green")
    else:
        statuses.append("amber")

    # Datasets
    review_req = sum(1 for e in elements if e.get("type") == "dataset" and e.get("reviewRequired"))
    statuses.append("amber" if review_req else "green")

    # Models
    model_elems = [e for e in elements if e.get("type") == "ai_model"]
    tampered = sum(1 for e in model_elems if e.get("tamperDetected") is True)
    unverified = sum(1 for e in model_elems if e.get("tamperDetected") is None and e.get("checksums"))
    if tampered:
        statuses.append("red")
    elif unverified:
        statuses.append("amber")
    else:
        statuses.append("green")

    if "red" in statuses:
        return "ACTION REQUIRED"
    if "amber" in statuses:
        return "NEEDS ATTENTION"
    return "COMPLIANT"


class TestVerdict:
    def test_all_green_is_compliant(self, minimal_bom):
        assert _verdict(minimal_bom) == "COMPLIANT"

    def test_non_compliant_license_is_action_required(self, minimal_bom):
        bom = dict(minimal_bom)
        bom["summary"] = dict(minimal_bom["summary"], nonCompliantLicenses=1)
        assert _verdict(bom) == "ACTION REQUIRED"

    def test_no_fix_cve_is_action_required(self, bom_with_cve):
        assert _verdict(bom_with_cve) == "ACTION REQUIRED"

    def test_moderate_cve_is_needs_attention(self, minimal_bom):
        bom = dict(minimal_bom)
        bom["summary"] = dict(minimal_bom["summary"], totalCVEs=1,
                               cveSeverityCounts={"MEDIUM": 1})
        bom["cvesByPackage"] = {
            "requests==2.28.0": [{
                "vulnId": "GHSA-test", "cveId": None, "aliases": [],
                "severity": "MEDIUM", "cvssScore": None, "cvssVector": None,
                "installedVersion": "2.28.0", "fixVersions": ["2.29.0"],
                "suggestion": "Upgrade to 2.29.0",
                "description": "", "published": None, "modified": None,
            }]
        }
        assert _verdict(bom) == "NEEDS ATTENTION"

    def test_gdpr_flag_is_needs_attention(self, minimal_bom):
        bom = dict(minimal_bom)
        bom["gdprFlags"] = [{"dataset": "Reddit", "riskLevel": "HIGH",
                              "reason": "web scrape", "source": "inferred",
                              "regulation": "GDPR", "requiresDPA": True}]
        assert _verdict(bom) == "NEEDS ATTENTION"

    def test_tampered_model_is_action_required(self, minimal_bom):
        bom = dict(minimal_bom)
        bom["elements"] = [{
            "type": "ai_model", "name": "test-model",
            "tamperDetected": True,
            "checksums": [{"algorithm": "SHA256", "checksumValue": "abc123"}],
        }]
        assert _verdict(bom) == "ACTION REQUIRED"

    def test_unverified_model_is_needs_attention(self, minimal_bom):
        bom = dict(minimal_bom)
        bom["elements"] = [{
            "type": "ai_model", "name": "test-model",
            "tamperDetected": None,
            "checksums": [{"algorithm": "SHA256", "checksumValue": "abc123"}],
        }]
        assert _verdict(bom) == "NEEDS ATTENTION"

    def test_review_required_dataset_is_needs_attention(self, minimal_bom):
        bom = dict(minimal_bom)
        bom["elements"] = [{"type": "dataset", "name": "internal-data", "reviewRequired": True}]
        assert _verdict(bom) == "NEEDS ATTENTION"
