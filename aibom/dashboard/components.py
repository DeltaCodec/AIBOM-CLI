"""Reusable UI building blocks — dense BI-style."""
from __future__ import annotations

import dash_bootstrap_components as dbc
from dash import html

from .theme import (
    AMBER,
    CHART_BG,
    CONF_HEX,
    DIM,
    EU_HEX,
    GRIDLINE,
    RED,
    RISK_HEX,
    ROW_EVEN,
    ROW_ODD,
    SEV_HEX,
    SURFACE,
    TEAL,
    TEXT_MUTED,
    WHITE,
)

# ── primitive helpers ─────────────────────────────────────────────────────────

def pill(text: str, color: str) -> html.Span:
    return html.Span(text, style={
        "backgroundColor": color, "color": "#fff",
        "borderRadius": "3px", "padding": "1px 7px",
        "fontSize": "0.7rem", "fontWeight": "600", "whiteSpace": "nowrap",
    })

def sev_pill(s: str) -> html.Span:
    return pill(s, SEV_HEX.get(s.upper(), DIM))

def risk_pill(r: str) -> html.Span:
    return pill(r, RISK_HEX.get(r.upper(), DIM)) if r else html.Span("—", style={"color": DIM})

def conf_pill(c: str) -> html.Span:
    return pill(c, CONF_HEX.get(c.upper(), DIM))

def eu_pill(r: str) -> html.Span:
    return pill((r or "unknown").upper(), EU_HEX.get((r or "").lower(), DIM))

def status_square(color: str) -> html.Span:
    return html.Span("", style={
        "display": "inline-block", "width": "10px", "height": "10px",
        "backgroundColor": color, "borderRadius": "2px",
        "marginRight": "7px", "verticalAlign": "middle", "flexShrink": "0",
    })


# ── table helpers ─────────────────────────────────────────────────────────────

_TH = {
    "backgroundColor": CHART_BG, "color": "#555",
    "fontSize": "0.62rem", "fontWeight": "700",
    "textTransform": "uppercase", "letterSpacing": "0.08em",
    "padding": "5px 10px", "borderBottom": f"1px solid {GRIDLINE}",
    "whiteSpace": "nowrap",
}
_TD = {
    "color": WHITE, "fontSize": "0.82rem",
    "padding": "5px 10px", "borderBottom": f"1px solid {GRIDLINE}",
    "verticalAlign": "middle",
}
_TD_MUTED = {**_TD, "color": TEXT_MUTED, "fontSize": "0.78rem"}


def th(*cols) -> html.Thead:
    return html.Thead(html.Tr([html.Th(c, style=_TH) for c in cols]))


def td(content, muted=False, mono=False, style=None) -> html.Td:
    base = _TD_MUTED if muted else _TD
    extra = {}
    if mono:
        extra = {"fontFamily": "monospace", "fontSize": "0.76rem"}
    return html.Td(content, style={**base, **(extra), **(style or {})})


def tr(cells: list, idx: int = 0, left_border: str | None = None) -> html.Tr:
    bg = ROW_ODD if idx % 2 else ROW_EVEN
    s  = {"backgroundColor": bg}
    if left_border:
        s["borderLeft"] = left_border
    return html.Tr(cells, style=s, className="bi-row")


def bi_table(head, rows, id: str | None = None) -> html.Div:
    kwargs = {"id": id} if id else {}
    return html.Div(
        html.Table([head, html.Tbody(rows)],
                   style={"width": "100%", "borderCollapse": "collapse"}, **kwargs),
        style={"overflowX": "auto", "borderRadius": "4px",
               "border": f"1px solid {GRIDLINE}"},
    )


# ── chart wrapper ─────────────────────────────────────────────────────────────

def chart_box(fig, height: int = 200) -> html.Div:
    from dash import dcc
    return html.Div(
        dcc.Graph(figure=fig, config={"displayModeBar": False},
                  style={"height": f"{height}px"}),
        style={"backgroundColor": CHART_BG, "borderRadius": "4px",
               "border": f"1px solid {GRIDLINE}"},
    )


# ── metrics strip ─────────────────────────────────────────────────────────────

def metrics_strip(bom: dict) -> html.Div:
    s  = bom.get("summary", {})
    cd = _compliance_data(bom)
    verdict_text, verdict_color = cd["verdict"]

    chips = [
        ("PACKAGES",   s.get("totalDependencies", 0), WHITE),
        ("DATASETS",   s.get("totalDatasets", 0),     WHITE),
        ("MODELS",     s.get("totalModels", 0),        WHITE),
        ("FRAMEWORKS", s.get("totalFrameworks", 0),    WHITE),
        ("LIBRARIES",  s.get("totalLibraries", 0),     WHITE),
        ("CVEs",       s.get("totalCVEs", 0),          RED if s.get("totalCVEs", 0) else TEAL),
        ("GDPR FLAGS", s.get("gdprFlags", 0) + s.get("lgpdFlags", 0),
                       AMBER if s.get("gdprFlags", 0) + s.get("lgpdFlags", 0) else TEXT_MUTED),
        ("VERDICT",    verdict_text,                   verdict_color),
    ]

    items: list = []
    for i, (label, value, color) in enumerate(chips):
        if i:
            items.append(html.Div(style={
                "width": "1px", "backgroundColor": GRIDLINE,
                "height": "36px", "margin": "0 18px", "alignSelf": "center",
            }))
        items.append(html.Div([
            html.Div(label, style={
                "color": "#555", "fontSize": "0.6rem",
                "letterSpacing": "0.1em", "textTransform": "uppercase",
                "marginBottom": "3px",
            }),
            html.Div(str(value), style={
                "color": color, "fontSize": "1.35rem",
                "fontWeight": "700", "lineHeight": "1",
            }),
        ]))

    return html.Div(items, style={
        "display": "flex", "alignItems": "center",
        "padding": "12px 24px",
        "backgroundColor": SURFACE,
        "borderBottom": f"1px solid {GRIDLINE}",
        "flexWrap": "wrap", "gap": "4px",
    })


# ── section anchor + header ───────────────────────────────────────────────────

def section_anchor(section_id: str, title: str) -> html.Div:
    return html.Div([
        html.Div(id=f"section-{section_id}",
                 style={"position": "relative", "top": "-64px", "visibility": "hidden",
                        "pointerEvents": "none"}),
        html.Div(title, style={
            "color": TEAL, "fontSize": "0.7rem", "fontWeight": "700",
            "letterSpacing": "0.12em", "textTransform": "uppercase",
            "padding": "10px 24px 8px",
        }),
    ], style={"borderTop": f"1px solid {GRIDLINE}", "backgroundColor": SURFACE})


# ── compliance data (shared logic) ────────────────────────────────────────────

_STATUS_COLORS = {"green": TEAL, "amber": AMBER, "red": RED}


def _compliance_data(bom: dict) -> dict:
    s        = bom.get("summary", {})
    elements = bom.get("elements", [])
    out      = {}

    nc = s.get("nonCompliantLicenses", 0)
    out["licenses"] = ("green", "All compliant", TEAL) if not nc \
        else ("red", f"{nc} non-compliant", RED)

    total_cves = s.get("totalCVEs", 0)
    no_fix = sum(
        1 for cves in bom.get("cvesByPackage", {}).values()
        for c in cves
        if "No fix" in c.get("suggestion", "") and c.get("severity") in ("CRITICAL", "HIGH")
    )
    if not total_cves:
        out["vulns"] = ("green", "No vulnerabilities", TEAL)
    elif no_fix:
        out["vulns"] = ("red", f"{no_fix} with no fix", RED)
    else:
        out["vulns"] = ("amber", f"{total_cves} moderate", AMBER)

    gdpr_flags = bom.get("gdprFlags", [])
    out["privacy"] = ("green", "No flags", TEAL) if not gdpr_flags \
        else ("amber", f"{len(gdpr_flags)} flagged", AMBER)

    review_req = sum(1 for e in elements if e.get("type") == "dataset" and e.get("reviewRequired"))
    out["datasets"] = ("green", "All documented", TEAL) if not review_req \
        else ("amber", f"{review_req} require review", AMBER)

    model_elems = [e for e in elements if e.get("type") == "ai_model"]
    tampered = sum(1 for e in model_elems if e.get("tamperDetected") is True)
    if tampered:
        out["models"] = ("red", f"{tampered} TAMPERED", RED)
    elif not model_elems:
        out["models"] = ("green", "No models", DIM)
    else:
        unverified = sum(1 for e in model_elems
                         if e.get("tamperDetected") is None and e.get("checksums"))
        out["models"] = ("green",
                         f"{unverified} unverified (no baseline)" if unverified else "All verified",
                         DIM if unverified else TEAL)

    statuses = [v[0] for v in out.values()]
    if "red" in statuses:
        out["verdict"] = ("ACTION REQUIRED", RED)
    elif "amber" in statuses:
        out["verdict"] = ("NEEDS ATTENTION", AMBER)
    else:
        out["verdict"] = ("COMPLIANT", TEAL)
    return out


_VERDICT_BG = {"ACTION REQUIRED": RED, "NEEDS ATTENTION": AMBER, "COMPLIANT": TEAL}


def compliance_table(bom: dict) -> html.Div:
    data = _compliance_data(bom)
    verdict_text, verdict_color = data["verdict"]

    rows = []
    for label, key in [
        ("Licenses",       "licenses"),
        ("Vulnerabilities","vulns"),
        ("Privacy",        "privacy"),
        ("Datasets",       "datasets"),
        ("Models",         "models"),
    ]:
        status, text, color = data[key]
        sq_color = _STATUS_COLORS.get(status, DIM)
        rows.append(html.Div([
            status_square(sq_color),
            html.Span(label, style={"color": TEXT_MUTED, "fontSize": "0.8rem",
                                    "width": "100px", "display": "inline-block"}),
            html.Span(text, style={"color": color, "fontSize": "0.8rem"}),
        ], style={"display": "flex", "alignItems": "center",
                  "padding": "6px 12px", "borderBottom": f"1px solid {GRIDLINE}"}))

    return html.Div([
        html.Div(rows),
        html.Div(verdict_text, style={
            "backgroundColor": _VERDICT_BG.get(verdict_text, TEAL),
            "color": "#fff", "fontWeight": "700", "fontSize": "1rem",
            "textAlign": "center", "padding": "9px",
            "letterSpacing": "0.04em",
        }),
    ], style={"border": f"1px solid {GRIDLINE}", "borderRadius": "4px", "overflow": "hidden"})


# ── empty state ───────────────────────────────────────────────────────────────

def empty_state(message: str, icon: str = "✓") -> html.Div:
    color = TEAL if icon == "✓" else TEXT_MUTED
    return html.Div([
        html.Div(icon, style={"fontSize": "2rem", "color": color, "marginBottom": "6px"}),
        html.P(message, style={"color": TEXT_MUTED, "fontSize": "0.85rem", "margin": "0"}),
    ], style={"textAlign": "center", "padding": "30px 20px"})


# ── no-fix banner ─────────────────────────────────────────────────────────────

def no_fix_banner(pkgs: list[str]) -> dbc.Alert:
    pkg_str = ", ".join(pkgs[:5]) + ("…" if len(pkgs) > 5 else "")
    return dbc.Alert([
        html.Strong(f"⚠  {len(pkgs)} vulnerabilit{'y has' if len(pkgs)==1 else 'ies have'} no upstream fix"),
        html.Span(f" — consider removing or isolating: {pkg_str}", style={"color": RED}),
    ], color="danger", style={"fontSize": "0.82rem", "padding": "8px 12px", "marginBottom": "10px"})


# ── scan info bar ─────────────────────────────────────────────────────────────

def scan_info_bar(bom: dict) -> html.Div:
    name    = bom.get("name", "—")
    created = bom.get("createdAt", "")[:19].replace("T", " ") + " UTC"
    return html.Div([
        html.Span(name, style={"color": TEXT_MUTED, "fontSize": "0.75rem",
                                "fontFamily": "monospace", "marginRight": "24px"}),
        html.Span(f"Generated {created}", style={"color": "#444", "fontSize": "0.72rem"}),
    ], style={
        "padding": "8px 24px",
        "backgroundColor": CHART_BG,
        "borderTop": f"1px solid {GRIDLINE}",
    })
