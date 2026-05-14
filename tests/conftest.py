"""Shared fixtures for ai-bom tests."""
import pytest


@pytest.fixture
def minimal_bom():
    """A minimal valid BOM dict — all counts zero, no elements."""
    return {
        "spdxVersion": "SPDX-3.0",
        "summary": {
            "totalDependencies": 0,
            "totalDatasets": 0,
            "totalModels": 0,
            "totalFrameworks": 0,
            "totalLibraries": 0,
            "totalCVEs": 0,
            "cveSeverityCounts": {},
            "nonCompliantLicenses": 0,
            "gdprFlags": 0,
            "lgpdFlags": 0,
            "vulnerablePackages": 0,
            "totalVulnerabilities": 0,
        },
        "elements": [],
        "cvesByPackage": {},
        "gdprFlags": [],
        "provenanceGaps": [],
        "auditTrail": [],
    }


@pytest.fixture
def bom_with_cve(minimal_bom):
    """BOM with one HIGH CVE that has no fix."""
    bom = dict(minimal_bom)
    bom["summary"] = dict(minimal_bom["summary"])
    bom["summary"]["totalCVEs"] = 1
    bom["summary"]["cveSeverityCounts"] = {"HIGH": 1}
    bom["cvesByPackage"] = {
        "transformers==4.30.0": [{
            "vulnId": "GHSA-xxxx-yyyy-zzzz",
            "cveId": "CVE-2024-0001",
            "aliases": [],
            "severity": "HIGH",
            "cvssScore": 8.5,
            "cvssVector": None,
            "installedVersion": "4.30.0",
            "fixVersions": [],
            "suggestion": "No fix available — monitor for patches",
            "description": "Test vulnerability",
            "published": None,
            "modified": None,
        }]
    }
    return bom
