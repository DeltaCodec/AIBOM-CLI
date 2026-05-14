"""Single scrollable page layout — dense BI style."""
from __future__ import annotations

from dash import html

from .charts import (
    confidence_donut, cve_donut, dataset_privacy_bar,
    deps_bar, history_line, params_bar, source_type_donut,
)
from .components import (
    bi_table, chart_box, compliance_table, empty_state,
    eu_pill, metrics_strip, no_fix_banner, risk_pill,
    scan_info_bar, section_anchor, sev_pill, td, th, tr,
)
from .theme import (
    AMBER, BLUE, BORDER, CARD_BG, CHART_BG, DIM, GRIDLINE,
    RED, SURFACE, TEAL, TEXT_MUTED, WHITE,
)


# ── layout primitives ─────────────────────────────────────────────────────────

def _row(*cols, gap: str = "16px") -> html.Div:
    return html.Div(list(cols), style={
        "display": "grid",
        "gridTemplateColumns": f"repeat({len(cols)}, 1fr)",
        "gap": gap,
        "padding": "0 24px 16px",
    })


def _pad(*children) -> html.Div:
    return html.Div(list(children), style={"padding": "0 24px 16px"})


# ── section: compliance + CVE ─────────────────────────────────────────────────

def _section_compliance_cve(bom: dict) -> html.Div:
    cves_by_pkg = bom.get("cvesByPackage", {})

    no_fix_pkgs = [
        pkg for pkg, cves in cves_by_pkg.items()
        if any("No fix" in c.get("suggestion", "") and c.get("severity") in ("CRITICAL", "HIGH")
               for c in cves)
    ]

    history = bom.get("scanHistory", bom.get("history", []))

    return html.Div([
        section_anchor("compliance", "COMPLIANCE OVERVIEW"),
        _row(
            html.Div(compliance_table(bom)),
            html.Div(chart_box(cve_donut(bom), height=220)),
            html.Div(chart_box(history_line(history), height=220)),
        ),
        _pad(no_fix_banner(no_fix_pkgs)) if no_fix_pkgs else html.Div(),
    ])


# ── section: dependencies ─────────────────────────────────────────────────────

def _section_deps(bom: dict) -> html.Div:
    deps = [e for e in bom.get("elements", [])
            if e.get("SPDXID", "").startswith("SPDXRef-Dep-")]
    cves_by_pkg = bom.get("cvesByPackage", {})

    cve_counts: dict[str, int] = {}
    for key, lst in cves_by_pkg.items():
        pkg = key.split("==")[0]
        cve_counts[pkg] = cve_counts.get(pkg, 0) + len(lst)

    rows = []
    for i, d in enumerate(sorted(deps, key=lambda x: cve_counts.get(x.get("name", ""), 0), reverse=True)):
        name   = d.get("name", "—")
        ver    = d.get("versionInfo", "—")
        lic    = d.get("licenseConcluded", "—")
        nc     = cve_counts.get(name, 0)
        status = d.get("complianceStatus", "")
        color  = TEAL if status == "compliant" else RED if status == "non-compliant" else DIM
        rows.append(tr([
            td(name, mono=True),
            td(ver, muted=True, mono=True),
            td(lic, muted=True),
            td(html.Span(str(nc) if nc else "—", style={"color": RED if nc else DIM,
                                                          "fontWeight": "600" if nc else "400"})),
            td(html.Span(status or "—", style={"color": color, "fontSize": "0.76rem"})),
        ], idx=i))

    head  = th("Package", "Version", "License", "CVEs", "Status")
    table = bi_table(head, rows) if rows else empty_state("No packages found")

    return html.Div([
        section_anchor("dependencies", "DEPENDENCIES"),
        _pad(chart_box(deps_bar(bom), height=max(220, len(deps) * 22 + 60))),
        _pad(table),
    ])


# ── section: models ───────────────────────────────────────────────────────────

def _section_models(bom: dict) -> html.Div:
    elements = bom.get("elements", [])
    models   = [e for e in elements if e.get("type") == "ai_model" and not e.get("isTrainingScript")]
    scripts  = [e for e in elements if e.get("type") == "ai_model" and e.get("isTrainingScript")]

    def _model_rows(items):
        rows = []
        for i, m in enumerate(items):
            insp   = m.get("inspection", {}) or {}
            name   = m.get("name", "—")
            lib    = insp.get("libraryName") or m.get("hubMetadata", {}).get("library_name", "—")
            params = insp.get("paramCountEstimate")
            p_str  = (f"{params/1e9:.1f}B" if params and params >= 1e9
                      else f"{params/1e6:.0f}M" if params else "—")
            tamper = m.get("tamperDetected")
            if tamper is True:
                integrity = html.Span("TAMPERED", style={"color": RED, "fontWeight": "700", "fontSize": "0.72rem"})
            elif tamper is False:
                integrity = html.Span("OK", style={"color": TEAL, "fontSize": "0.72rem"})
            else:
                integrity = html.Span("UNVERIFIED", style={"color": DIM, "fontSize": "0.72rem"})
            rows.append(tr([
                td(name, mono=True),
                td(lib or "—", muted=True),
                td(p_str, muted=True),
                td(m.get("versionInfo", "—"), muted=True, mono=True),
                td(integrity),
            ], idx=i))
        return rows

    model_rows  = _model_rows(models)
    script_rows = _model_rows(scripts)

    model_table  = bi_table(th("Model", "Library", "Params", "Version", "Integrity"), model_rows) \
        if model_rows else empty_state("No AI models found", "—")
    script_table = bi_table(th("Script", "Library", "Params", "Path", "Integrity"), script_rows) \
        if script_rows else None

    children: list = [
        section_anchor("models", "MODELS & FRAMEWORKS"),
        _pad(model_table),
    ]
    if len(models) >= 2:
        children.append(_pad(chart_box(params_bar(bom), height=220)))
    if script_table:
        children += [
            html.Div("TRAINING SCRIPTS", style={
                "color": TEXT_MUTED, "fontSize": "0.6rem", "fontWeight": "700",
                "letterSpacing": "0.12em", "padding": "6px 24px 4px",
            }),
            _pad(script_table),
        ]

    return html.Div(children)


# ── section: datasets ─────────────────────────────────────────────────────────

def _section_datasets(bom: dict) -> html.Div:
    datasets = [e for e in bom.get("elements", []) if e.get("type") == "dataset"]

    rows = []
    for i, d in enumerate(datasets):
        name  = d.get("name", "—")
        src   = d.get("sourceType") or d.get("datasetSource") or "—"
        conf  = (d.get("confidence") or "UNKNOWN").upper()
        conf_color = {"CONFIRMED": TEAL, "INFERRED": AMBER, "UNKNOWN": DIM}.get(conf, DIM)
        size  = d.get("sizeInfo", "—")
        review = d.get("reviewRequired", False)
        rows.append(tr([
            td(name, mono=True),
            td(src.replace("_", " ").title(), muted=True),
            td(html.Span(conf, style={"color": conf_color, "fontSize": "0.72rem"})),
            td(str(size) if size and size != "—" else "—", muted=True),
            td(html.Span("REVIEW REQUIRED", style={"color": AMBER, "fontSize": "0.7rem"})
               if review else html.Span("OK", style={"color": DIM, "fontSize": "0.72rem"})),
        ], idx=i))

    head  = th("Dataset", "Source", "Confidence", "Size", "Status")
    table = bi_table(head, rows) if rows else empty_state("No datasets found", "—")

    return html.Div([
        section_anchor("datasets", "DATASETS"),
        _row(
            html.Div(chart_box(confidence_donut(bom), height=200)),
            html.Div(chart_box(source_type_donut(bom), height=200)),
            html.Div(chart_box(dataset_privacy_bar(bom), height=200)),
        ),
        _pad(table),
    ])


# ── section: privacy ──────────────────────────────────────────────────────────

def _section_privacy(bom: dict) -> html.Div:
    gdpr_flags = bom.get("gdprFlags", [])
    lgpd_flags = bom.get("lgpdFlags", [])

    def _flag_rows(flags):
        rows = []
        for i, f in enumerate(flags):
            rows.append(tr([
                td(f.get("dataset", "—"), mono=True),
                td(risk_pill(f.get("riskLevel", "—"))),
                td(", ".join(f.get("reasons", [])) or "—", muted=True),
                td(f.get("recommendation", "—"), muted=True),
            ], idx=i))
        return rows

    gdpr_rows = _flag_rows(gdpr_flags)
    lgpd_rows = _flag_rows(lgpd_flags)

    gdpr_table = bi_table(th("Dataset", "Risk", "Reasons", "Recommendation"), gdpr_rows) \
        if gdpr_rows else empty_state("No GDPR flags")
    lgpd_table = bi_table(th("Dataset", "Risk", "Reasons", "Recommendation"), lgpd_rows) \
        if lgpd_rows else empty_state("No LGPD flags")

    eu_items = []
    for e in bom.get("elements", []):
        _eu_raw = e.get("euAiActRisk") or e.get("euRisk")
        eu = (_eu_raw.get("level") or _eu_raw.get("riskLevel") or str(_eu_raw)
              if isinstance(_eu_raw, dict) else _eu_raw)
        if eu:
            eu_items.append(html.Div([
                html.Span(e.get("name", "—"), style={"color": WHITE, "fontSize": "0.8rem",
                                                      "marginRight": "10px", "fontFamily": "monospace"}),
                eu_pill(eu),
            ], style={"padding": "4px 12px", "borderBottom": f"1px solid {GRIDLINE}",
                      "display": "flex", "alignItems": "center"}))

    children: list = [
        section_anchor("privacy", "PRIVACY & COMPLIANCE"),
        html.Div("GDPR", style={
            "color": TEXT_MUTED, "fontSize": "0.6rem", "fontWeight": "700",
            "letterSpacing": "0.12em", "padding": "4px 24px 4px",
        }),
        _pad(gdpr_table),
        html.Div("LGPD", style={
            "color": TEXT_MUTED, "fontSize": "0.6rem", "fontWeight": "700",
            "letterSpacing": "0.12em", "padding": "4px 24px 4px",
        }),
        _pad(lgpd_table),
    ]
    if eu_items:
        eu_panel = html.Div([
            html.Div("EU AI ACT RISK", style={
                "color": TEXT_MUTED, "fontSize": "0.6rem", "fontWeight": "700",
                "letterSpacing": "0.12em", "padding": "6px 12px 4px",
                "borderBottom": f"1px solid {GRIDLINE}",
            }),
            *eu_items,
        ], style={"border": f"1px solid {GRIDLINE}", "borderRadius": "4px", "overflow": "hidden"})
        children.append(_pad(eu_panel))

    return html.Div(children)


# ── section: history ──────────────────────────────────────────────────────────

def _section_history(bom: dict) -> html.Div:
    history = bom.get("scanHistory", bom.get("history", []))

    rows = []
    for i, h in enumerate(reversed(history)):
        ts      = h.get("timestamp", "—")[:19].replace("T", " ")
        verdict = h.get("verdict", "—")
        cves    = h.get("totalCVEs", "—")
        pkgs    = h.get("totalDependencies", "—")
        v_color = {"COMPLIANT": TEAL, "NEEDS ATTENTION": AMBER, "ACTION REQUIRED": RED}.get(verdict, DIM)
        rows.append(tr([
            td(ts, mono=True, muted=True),
            td(html.Span(verdict, style={"color": v_color, "fontWeight": "600",
                                          "fontSize": "0.76rem"})),
            td(str(cves) if cves != "—" else "—", muted=True),
            td(str(pkgs) if pkgs != "—" else "—", muted=True),
        ], idx=i))

    head  = th("Timestamp", "Verdict", "CVEs", "Packages")
    table = bi_table(head, rows) if rows else empty_state(
        "No scan history — run multiple scans to see trends", "○")

    return html.Div([
        section_anchor("history", "SCAN HISTORY"),
        _pad(chart_box(history_line(history), height=200)),
        _pad(table),
    ])


# ── top-level page layout ─────────────────────────────────────────────────────

def page_layout(bom: dict) -> html.Div:
    return html.Div([
        metrics_strip(bom),
        _section_compliance_cve(bom),
        _section_deps(bom),
        _section_models(bom),
        _section_datasets(bom),
        _section_privacy(bom),
        _section_history(bom),
        scan_info_bar(bom),
    ])


# ── error layout ──────────────────────────────────────────────────────────────

def error_layout(message: str) -> html.Div:
    return html.Div([
        html.Div("⚠", style={"fontSize": "3rem", "color": RED, "marginBottom": "12px"}),
        html.H4("Failed to load BOM", style={"color": WHITE, "marginBottom": "8px"}),
        html.P(message, style={"color": TEXT_MUTED, "fontSize": "0.9rem",
                               "fontFamily": "monospace", "maxWidth": "600px"}),
    ], style={"textAlign": "center", "padding": "80px 20px"})
