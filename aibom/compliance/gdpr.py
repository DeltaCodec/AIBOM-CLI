from __future__ import annotations

import os
from dataclasses import dataclass

# Shared safe list and tokenizer — single source of truth with scanner
from aibom.scanner.datasets import _SAFE_DATASETS, _name_tokens, _norm_name

_GDPR_HIGH = {
    "clinical", "medical", "health", "biometric", "ssn", "passport",
    "credit", "financial", "patient",
}
_GDPR_MEDIUM = {
    "personal", "pii", "gdpr", "eu_data", "email", "phone",
    "address", "ip_address", "location", "private",
}
_GDPR_LOW = {
    "user", "customer", "person", "europe", "european",
}

_LGPD_HIGH = {
    "cpf", "cnpj", "rg", "cnh", "sus", "titulo_eleitor", "pis", "pasep",
    "saude", "financeiro", "banco",
}
_LGPD_MEDIUM = {
    "lgpd", "dados_pessoais", "dadospessoais",
}
_LGPD_LOW = {
    "brazil", "brasil", "brasileiro",
}

_ALL_GDPR = _GDPR_HIGH | _GDPR_MEDIUM | _GDPR_LOW
_ALL_LGPD = _LGPD_HIGH | _LGPD_MEDIUM | _LGPD_LOW

_RANK = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}
_DEBUG = os.environ.get("AIBOM_DEBUG", "").lower() in ("1", "true", "yes")


def _tokens_hit(name: str, keywords: set[str]) -> str | None:
    """Return the first keyword that appears as a whole token in name, or None."""
    toks = _name_tokens(name)
    return next((kw for kw in keywords if kw in toks), None)


def _risk_level(name: str, high: set, medium: set) -> str:
    """Token-based risk classification — no substring false positives."""
    if _tokens_hit(name, high):
        return "HIGH"
    if _tokens_hit(name, medium):
        return "MEDIUM"
    return "LOW"


@dataclass
class GDPRFlag:
    dataset_name: str
    reason: str
    source: str
    regulation: str  # "GDPR" | "LGPD" | "GDPR+LGPD"
    risk_level: str  # "HIGH" | "MEDIUM" | "LOW"
    requires_dpa: bool = True


def flag_gdpr(datasets: list, extra_patterns: list[str] | None = None) -> list[GDPRFlag]:
    extra_tokens = set(extra_patterns or [])
    flags = []

    for ds in datasets:
        name = ds.name

        # ── Safe-list suppression — checked BEFORE any keyword scan ──────────
        if _norm_name(name) in _SAFE_DATASETS:
            if _DEBUG:
                print(f"[aibom debug] suppressed safe dataset: {name!r}")
            continue

        gdpr_marked = getattr(ds, "gdpr_relevant", False)
        lgpd_marked = getattr(ds, "lgpd_relevant", False)
        explicit_risk: str | None = getattr(ds, "gdpr_risk", None)

        # Token-based keyword scan (whole-word only, no substring matches)
        gdpr_kw = _tokens_hit(name, _ALL_GDPR | extra_tokens)
        lgpd_kw = _tokens_hit(name, _ALL_LGPD)

        # explicit gdpr_risk from scanner metadata is authoritative
        gdpr_hit = gdpr_marked or gdpr_kw is not None or explicit_risk in ("HIGH", "MEDIUM")
        lgpd_hit = lgpd_marked or lgpd_kw is not None

        if not gdpr_hit and not lgpd_hit:
            continue

        # ── Risk level: ds.gdpr_risk is authoritative (set from metadata) ────
        # Fall back to keyword-derived level only when metadata has no opinion.
        if gdpr_hit and lgpd_hit:
            regulation = "GDPR+LGPD"
            if explicit_risk:
                risk = explicit_risk
            else:
                risk = max(
                    _risk_level(name, _GDPR_HIGH, _GDPR_MEDIUM),
                    _risk_level(name, _LGPD_HIGH, _LGPD_MEDIUM),
                    key=lambda r: _RANK[r],
                )
            reason = "Dataset contains both GDPR and LGPD-relevant personal data indicators"
        elif gdpr_hit:
            regulation = "GDPR"
            risk = explicit_risk or _risk_level(name, _GDPR_HIGH, _GDPR_MEDIUM)
            reason = (
                f"GDPR-relevant keyword: '{gdpr_kw}'" if gdpr_kw
                else "Marked gdpr_relevant in dataset metadata"
            )
        else:
            regulation = "LGPD"
            # LGPD has no separate gdpr_risk field; use keyword scan
            risk = _risk_level(name, _LGPD_HIGH, _LGPD_MEDIUM)
            reason = (
                f"LGPD-relevant keyword: '{lgpd_kw}'" if lgpd_kw
                else "Marked lgpd_relevant in dataset metadata"
            )

        flags.append(GDPRFlag(
            dataset_name=name,
            reason=reason,
            source=ds.source,
            regulation=regulation,
            risk_level=risk,
        ))

    return flags
