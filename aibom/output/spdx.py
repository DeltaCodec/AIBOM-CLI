"""
Generates SPDX 3.0 compliant AI-BOM JSON.
Spec: https://spdx.github.io/spdx-spec/v3.0/
"""
import uuid
from datetime import datetime, timezone


def generate_spdx(
    project_name: str,
    project_version: str,
    dependencies: list,
    datasets: list,
    models: list,
    frameworks: list,
    license_results: list,
    gdpr_flags: list,
    vuln_summary,
    audit_trail: list[dict],
    hub_cards: dict | None = None,
    cves_by_package: dict | None = None,
    provenance_gaps: list[str] | None = None,
) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    doc_id = f"SPDXRef-DOCUMENT-{uuid.uuid4().hex[:8]}"
    license_map = {r.package: r for r in license_results}

    elements = []

    # Document root
    elements.append({
        "SPDXID": doc_id,
        "spdxVersion": "SPDX-3.0",
        "creationInfo": {
            "created": now,
            "creators": ["Tool: ai-bom-0.1.0"],
            "licenseListVersion": "3.23",
        },
        "name": f"AI-BOM for {project_name}",
        "dataLicense": "CC0-1.0",
        "documentNamespace": f"https://aibom.local/{project_name}/{uuid.uuid4().hex}",
    })

    # AI Package element
    elements.append({
        "SPDXID": f"SPDXRef-Package-{_safe(project_name)}",
        "type": "software_package",
        "name": project_name,
        "versionInfo": project_version,
        "primaryPackagePurpose": "MACHINE-LEARNING",
        "annotations": [
            {"annotationType": "REVIEW", "comment": "Auto-generated AI-BOM"},
        ],
        "aiExtension": {
            "frameworks": [
                {
                    "name": fw.name,
                    "package": fw.package,
                    "version": fw.version or "unknown",
                    "kind": getattr(fw, "kind", "library"),
                    "inDeps": getattr(fw, "in_deps", False),
                    "detectedIn": getattr(fw, "detected_in", []),
                }
                for fw in frameworks
                if getattr(fw, "kind", "library") == "framework"
            ],
            "mlLibraries": [
                {
                    "name": fw.name,
                    "package": fw.package,
                    "version": fw.version or "unknown",
                    "kind": getattr(fw, "kind", "library"),
                    "inDeps": getattr(fw, "in_deps", False),
                    "detectedIn": getattr(fw, "detected_in", []),
                }
                for fw in frameworks
                if getattr(fw, "kind", "library") == "library"
            ],
        },
    })

    cves_by_package = cves_by_package or {}

    # Dependencies
    for dep in dependencies:
        lr = license_map.get(dep.name)
        elem = {
            "SPDXID": f"SPDXRef-Dep-{_safe(dep.name)}",
            "type": "software_package",
            "name": dep.name,
            "versionInfo": dep.version,
            "licenseConcluded": lr.spdx_id if lr else "NOASSERTION",
            "licenseDeclared": lr.license if lr else "NOASSERTION",
            "complianceStatus": "compliant" if (lr and lr.allowed) else "non-compliant",
        }
        if dep.vulnerabilities:
            elem["vulnerabilities"] = dep.vulnerabilities
        pkg_cves = cves_by_package.get(dep.name)
        if pkg_cves:
            elem["cves"] = [
                {
                    "vulnId": c.vuln_id,
                    "cveId": c.cve_id,
                    "aliases": c.aliases,
                    "severity": c.severity,
                    "cvssScore": c.cvss_score,
                    "cvssVector": c.cvss_vector,
                    "installedVersion": c.installed_version,
                    "fixVersions": c.fix_versions,
                    "suggestion": c.suggestion,
                    "description": c.description,
                    "published": c.published,
                    "modified": c.modified,
                }
                for c in pkg_cves
            ]
        elements.append(elem)

    # Datasets (metadata only — never raw data)
    for ds in datasets:
        gdpr = any(f.dataset_name == ds.name for f in gdpr_flags)
        lgpd = any(f.dataset_name == ds.name and f.regulation in ("LGPD", "GDPR+LGPD") for f in gdpr_flags)
        sensitivity = getattr(ds, "sensitivity", "PUBLIC")
        # Never store path for CONFIDENTIAL/RESTRICTED datasets
        safe_path = None if sensitivity in ("CONFIDENTIAL", "RESTRICTED") else getattr(ds, "path", None)
        elem = {
            "SPDXID": f"SPDXRef-Dataset-{_safe(ds.name)}",
            "type": "dataset",
            "name": ds.name,
            "datasetSource": ds.source,
            "licenseConcluded": ds.license or "NOASSERTION",
            "confidential": getattr(ds, "confidential", False),
            "gdprRelevant": gdpr or getattr(ds, "gdpr_relevant", False),
            "lgpdRelevant": lgpd or getattr(ds, "lgpd_relevant", False),
            "detectionMethod": getattr(ds, "detection_method", "unknown"),
            "confidence": getattr(ds, "confidence", "UNKNOWN"),
            "sourceType": getattr(ds, "source_type", "unknown"),
            "sensitivity": sensitivity,
            "detectedIn": getattr(ds, "detected_in", []),
            "reviewRequired": getattr(ds, "review_required", False),
        }
        if getattr(ds, "gdpr_risk", None):
            elem["gdprRisk"] = ds.gdpr_risk
        if getattr(ds, "notes", ""):
            elem["notes"] = ds.notes
        if ds.version:
            elem["versionInfo"] = ds.version
        if safe_path:
            elem["path"] = safe_path
        if ds.hash:
            elem["checksums"] = [{"algorithm": "SHA256", "checksumValue": ds.hash}]
        elements.append(elem)

    # Models
    hub_cards = hub_cards or {}
    from aibom.scanner.model_inspector import classify_eu_ai_act
    for m in models:
        card = hub_cards.get(m.source_id) if m.source_id else None
        elem = {
            "SPDXID": f"SPDXRef-Model-{_safe(m.name)}",
            "type": "ai_model",
            "name": m.name,
            "filePath": m.path,
            "sizeBytes": m.size_bytes,
            "modelSource": m.source,
            "licenseConcluded": (card.license if card and card.license else m.license) or "NOASSERTION",
            "isCheckpoint": m.is_checkpoint,
            "isTrainingScript": m.is_training_script,
        }
        if m.source_id:
            elem["sourceId"] = m.source_id
        if m.sha256:
            elem["checksums"] = [{"algorithm": "SHA256", "checksumValue": m.sha256}]
        if m.expected_hash:
            elem["expectedHash"] = m.expected_hash
        if m.tamper_detected is not None:
            elem["tamperDetected"] = m.tamper_detected
        if card:
            elem["hubMetadata"] = {
                "pipelineTag": card.pipeline_tag,
                "libraryName": card.library_name,
                "tags": card.tags,
                "downloads": card.downloads,
                "likes": card.likes,
                "private": card.private,
            }
            if card.base_model:
                elem["baseModel"] = card.base_model
                if card.base_model_relation:
                    elem["baseModelRelation"] = card.base_model_relation
            if card.training_datasets:
                elem["trainingDatasets"] = card.training_datasets
            arch = getattr(getattr(m, "inspection", None), "architecture", None)
            risk, reasons = classify_eu_ai_act(card.pipeline_tag, card.tags, arch)
            elem["euAiActRisk"] = {"level": risk, "reasons": reasons}

        insp = getattr(m, "inspection", None)
        if insp:
            elem["inspection"] = {
                "architecture": insp.architecture,
                "modelType": insp.model_type,
                "paramCountEstimate": insp.param_count_estimate,
                "contextLength": insp.context_length,
                "hiddenSize": insp.hidden_size,
                "numLayers": insp.num_layers,
                "numAttentionHeads": insp.num_attention_heads,
                "numKvHeads": insp.num_kv_heads,
                "vocabSize": insp.vocab_size,
                "torchDtype": insp.torch_dtype,
                "libraryName": insp.library_name,
                "tokenizerType": insp.tokenizer_type,
                "pickleSafe": insp.pickle_safe,
                "pickleThreats": insp.pickle_threats,
                "safetensorsValid": insp.safetensors_valid,
                "euAiActRisk": insp.eu_ai_act_risk,
                "euAiActReasons": insp.eu_ai_act_reasons,
            }
        elements.append(elem)

    total_cves = sum(len(v) for v in cves_by_package.values())
    severity_counts: dict[str, int] = {}
    for cve_list in cves_by_package.values():
        for c in cve_list:
            severity_counts[c.severity] = severity_counts.get(c.severity, 0) + 1

    return {
        "spdxVersion": "SPDX-3.0",
        "SPDXID": doc_id,
        "name": f"AI-BOM: {project_name} v{project_version}",
        "createdAt": now,
        "summary": {
            "totalDependencies": len(dependencies),
            "totalDatasets": len(datasets),
            "datasetsByConfidence": {
                "CONFIRMED": sum(1 for d in datasets if getattr(d, "confidence", "UNKNOWN") == "CONFIRMED"),
                "INFERRED":  sum(1 for d in datasets if getattr(d, "confidence", "UNKNOWN") == "INFERRED"),
                "UNKNOWN":   sum(1 for d in datasets if getattr(d, "confidence", "UNKNOWN") == "UNKNOWN"),
            },
            "provenanceGaps": len(provenance_gaps or []),
            "totalModels": len(models),
            "totalFrameworks": sum(1 for fw in frameworks if getattr(fw, "kind", "library") == "framework"),
            "totalLibraries": sum(1 for fw in frameworks if getattr(fw, "kind", "library") == "library"),
            "vulnerablePackages": vuln_summary.vulnerable_packages,
            "totalVulnerabilities": vuln_summary.total_vulnerabilities,
            "totalCVEs": total_cves,
            "cveSeverityCounts": severity_counts,
            "gdprFlags": sum(1 for f in gdpr_flags if getattr(f, "regulation", "GDPR") in ("GDPR", "GDPR+LGPD")),
            "lgpdFlags": sum(1 for f in gdpr_flags if getattr(f, "regulation", "") in ("LGPD", "GDPR+LGPD")),
            "nonCompliantLicenses": sum(1 for r in license_results if not r.allowed),
            "hubEnrichedModels": len(hub_cards),
        },
        "elements": elements,
        "gdprFlags": [
            {
                "dataset": f.dataset_name,
                "reason": f.reason,
                "source": f.source,
                "regulation": getattr(f, "regulation", "GDPR"),
                "riskLevel": getattr(f, "risk_level", "MEDIUM"),
                "requiresDPA": f.requires_dpa,
            }
            for f in gdpr_flags
        ],
        "vulnerabilities": vuln_summary.all_vulns,
        "cvesByPackage": {
            f"{pkg}=={cve_list[0].installed_version}": [
                {
                    "vulnId": c.vuln_id,
                    "cveId": c.cve_id,
                    "aliases": c.aliases,
                    "severity": c.severity,
                    "cvssScore": c.cvss_score,
                    "cvssVector": c.cvss_vector,
                    "installedVersion": c.installed_version,
                    "fixVersions": c.fix_versions,
                    "suggestion": c.suggestion,
                    "description": c.description,
                    "published": c.published,
                    "modified": c.modified,
                }
                for c in cve_list
            ]
            for pkg, cve_list in cves_by_package.items() if cve_list
        },
        "auditTrail": audit_trail,
        "provenanceGaps": provenance_gaps or [],
    }


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "-" for c in name)
