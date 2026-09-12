"""Plotly chart builders — BI-style dark analytics."""
from __future__ import annotations

import plotly.graph_objects as go

from .theme import (
    AMBER,
    AXIS_STYLE,
    BLUE,
    CHART_BG,
    CHART_STYLE,
    CHART_TITLE,
    DIM,
    RED,
    SEV_HEX,
    TEAL,
    WHITE,
)


def _cs(**overrides) -> dict:
    """Merge CHART_STYLE with overrides (handles duplicate 'margin' key)."""
    return {**CHART_STYLE, **overrides}


def _empty(msg: str = "No data") -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(text=msg, xref="paper", yref="paper",
                       x=0.5, y=0.5, showarrow=False,
                       font=dict(size=12, color="#555"))
    fig.update_layout(**_cs(xaxis_visible=False, yaxis_visible=False))
    return fig


def _donut(labels, values, colors, title: str, center_text: str = "") -> go.Figure:
    fig = go.Figure(go.Pie(
        labels=labels, values=values,
        marker=dict(colors=colors, line=dict(color=CHART_BG, width=2)),
        hole=0.6,
        textinfo="label+value",
        hovertemplate="%{label}: %{value}<extra></extra>",
        textfont=dict(size=10),
    ))
    if center_text:
        fig.add_annotation(text=center_text, xref="paper", yref="paper",
                           x=0.5, y=0.5, showarrow=False,
                           font=dict(size=15, color=WHITE))
    fig.update_layout(**_cs(
        margin=dict(t=28, b=4, l=4, r=4),
        title=dict(text=title, **CHART_TITLE),
    ))
    return fig


# ── CVE severity donut ────────────────────────────────────────────────────────

def cve_donut(bom: dict) -> go.Figure:
    counts = bom.get("summary", {}).get("cveSeverityCounts", {})
    total  = sum(counts.values())
    if not total:
        fig = go.Figure()
        fig.add_annotation(text="✓", xref="paper", yref="paper",
                           x=0.5, y=0.62, showarrow=False,
                           font=dict(size=42, color=TEAL))
        fig.add_annotation(text="No CVEs", xref="paper", yref="paper",
                           x=0.5, y=0.3, showarrow=False,
                           font=dict(size=11, color="#555"))
        fig.update_layout(**_cs(
            margin=dict(t=28, b=4, l=4, r=4),
            xaxis_visible=False, yaxis_visible=False,
            title=dict(text="CVE SEVERITY", **CHART_TITLE),
        ))
        return fig

    order  = ["CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW", "UNKNOWN"]
    labels = [s for s in order if counts.get(s, 0)]
    values = [counts[s] for s in labels]
    return _donut(labels, values, [SEV_HEX[s] for s in labels],
                  "CVE SEVERITY", f"<b>{total}</b>")


# ── dataset confidence donut ──────────────────────────────────────────────────

def confidence_donut(bom: dict) -> go.Figure:
    datasets = [e for e in bom.get("elements", []) if e.get("type") == "dataset"]
    if not datasets:
        return _empty("No datasets")

    counts = {"CONFIRMED": 0, "INFERRED": 0, "UNKNOWN": 0}
    for d in datasets:
        c = (d.get("confidence") or "UNKNOWN").upper()
        counts[c] = counts.get(c, 0) + 1

    pairs = [(k, v) for k, v in counts.items() if v]
    labels, values = zip(*pairs) if pairs else ([], [])
    _c = {"CONFIRMED": TEAL, "INFERRED": AMBER, "UNKNOWN": RED}
    return _donut(list(labels), list(values),
                  [_c.get(label, DIM) for label in labels],
                  "DATASET CONFIDENCE", str(sum(values)))


# ── source type donut ─────────────────────────────────────────────────────────

_SRC_LABELS = {
    "web_scrape": "Web Scrape", "licensed": "Licensed",
    "synthetic": "Synthetic",  "internal": "Internal",
    "huggingface": "HuggingFace", "unknown": "Unknown",
}
_SRC_COLORS = [TEAL, BLUE, AMBER, RED, "#9b77d4", DIM]


def source_type_donut(bom: dict) -> go.Figure:
    datasets = [e for e in bom.get("elements", []) if e.get("type") == "dataset"]
    if not datasets:
        return _empty("No datasets")

    counts: dict[str, int] = {}
    for d in datasets:
        raw = (d.get("sourceType") or d.get("datasetSource") or "unknown").lower()
        src = _SRC_LABELS.get(raw, raw.replace("_", " ").title())
        counts[src] = counts.get(src, 0) + 1

    if not counts:
        return _empty("No source data")

    items = sorted(counts.items(), key=lambda x: -x[1])
    labels, values = zip(*items)
    colors = _SRC_COLORS[:len(labels)]
    return _donut(list(labels), list(values), colors,
                  "SOURCE TYPE", str(sum(values)))


# ── privacy risk horizontal bar ───────────────────────────────────────────────

def dataset_privacy_bar(bom: dict) -> go.Figure:
    flags    = bom.get("gdprFlags", [])
    datasets = [e for e in bom.get("elements", []) if e.get("type") == "dataset"]
    if not datasets:
        return _empty("No datasets")

    flag_risk = {f.get("dataset", ""): f.get("riskLevel", "MEDIUM") for f in flags}
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
    for d in datasets:
        risk = flag_risk.get(d.get("name", ""))
        key = risk if risk in counts else "NONE"
        counts[key] += 1

    pairs = [(label, v) for label, v in [("NONE", counts["NONE"]), ("LOW", counts["LOW"]),
                                   ("MEDIUM", counts["MEDIUM"]), ("HIGH", counts["HIGH"])] if v]
    if not pairs:
        return _empty("No risk data")

    labels, values = zip(*pairs)
    clr_map = {"NONE": DIM, "LOW": "#4a7c6a", "MEDIUM": AMBER, "HIGH": RED}
    fig = go.Figure(go.Bar(
        y=list(labels), x=list(values), orientation="h",
        marker=dict(color=[clr_map[label] for label in labels]),
        text=[str(v) for v in values], textposition="outside",
        textfont=dict(color="#888", size=11),
        hovertemplate="%{y}: %{x}<extra></extra>",
    ))
    fig.update_layout(**_cs(
        margin=dict(t=28, b=8, l=55, r=30),
        xaxis=dict(visible=False, range=[0, max(values) * 1.35]),
        yaxis=dict(**AXIS_STYLE),
        title=dict(text="PRIVACY RISK", **CHART_TITLE),
    ))
    return fig


# ── dependencies bar (CVE count per package) ──────────────────────────────────

def deps_bar(bom: dict) -> go.Figure:
    deps = [e for e in bom.get("elements", [])
            if e.get("SPDXID", "").startswith("SPDXRef-Dep-")]
    if not deps:
        return _empty("No packages scanned")

    cve_counts: dict[str, int] = {}
    for key, lst in bom.get("cvesByPackage", {}).items():
        pkg = key.split("==")[0]
        cve_counts[pkg] = cve_counts.get(pkg, 0) + len(lst)

    _compliance_color = {"compliant": TEAL, "non-compliant": RED}
    names, bar_vals, colors, hover = [], [], [], []
    for d in sorted(deps, key=lambda x: cve_counts.get(x.get("name", ""), 0), reverse=True)[:20]:
        name = d.get("name", "?")
        ver  = d.get("versionInfo", "")
        nc   = cve_counts.get(name, 0)
        status = d.get("complianceStatus", "")
        names.append(f"{name}=={ver}" if ver else name)
        bar_vals.append(max(nc, 0.05))
        colors.append(_compliance_color.get(status, DIM))
        hover.append(f"{name} {ver}<br>CVEs: {nc}<br>License: {d.get('licenseConcluded','?')}")

    fig = go.Figure(go.Bar(
        y=names, x=bar_vals, orientation="h",
        marker=dict(color=colors, opacity=0.85),
        hovertext=hover, hoverinfo="text",
        text=[str(c) if c > 0.05 else "" for c in bar_vals],
        textposition="outside",
        textfont=dict(color="#888", size=10),
    ))
    fig.update_layout(**_cs(
        margin=dict(t=28, b=8, l=160, r=30),
        xaxis=dict(visible=False),
        yaxis=dict(**AXIS_STYLE, autorange="reversed"),
        height=max(180, len(names) * 24 + 40),
        title=dict(text="PACKAGES (CVE COUNT · teal=compliant · red=flagged)", **CHART_TITLE),
    ))
    return fig


# ── model params comparison bar ───────────────────────────────────────────────

def params_bar(bom: dict) -> go.Figure:
    models = [e for e in bom.get("elements", [])
              if e.get("type") == "ai_model" and not e.get("isTrainingScript")]
    inspected = [(m["name"], m["inspection"].get("paramCountEstimate"))
                 for m in models if m.get("inspection", {}).get("paramCountEstimate")]
    if len(inspected) < 2:
        return _empty("Multiple models needed for comparison")

    names = [n[:24] for n, _ in inspected]
    params = [p for _, p in inspected]
    labels = [f"{p/1e9:.1f}B" if p >= 1e9 else f"{p/1e6:.0f}M" for p in params]

    fig = go.Figure(go.Bar(
        x=names, y=params,
        marker=dict(color=BLUE, opacity=0.8),
        text=labels, textposition="outside",
        textfont=dict(color="#888", size=10),
        hovertemplate="%{x}: %{text}<extra></extra>",
    ))
    fig.update_layout(**_cs(
        margin=dict(t=28, b=48, l=8, r=8),
        xaxis=dict(**AXIS_STYLE, tickangle=-20),
        yaxis=dict(visible=False),
        title=dict(text="MODEL PARAMETER COUNT", **CHART_TITLE),
    ))
    return fig


# ── history line ──────────────────────────────────────────────────────────────

_VSCORE = {"COMPLIANT": 3, "NEEDS ATTENTION": 2, "ACTION REQUIRED": 1}
_VCOLOR = {"COMPLIANT": TEAL, "NEEDS ATTENTION": AMBER, "ACTION REQUIRED": RED}


def history_line(entries: list[dict]) -> go.Figure:
    if not entries:
        return _empty("No scan history — run multiple scans to see trends")

    xs       = [e.get("timestamp", "")[:16] for e in entries]
    verdicts = [e.get("verdict", "COMPLIANT") for e in entries]
    ys       = [_VSCORE.get(v, 2) for v in verdicts]
    ptcolors = [_VCOLOR.get(v, AMBER) for v in verdicts]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=xs, y=ys, mode="lines+markers",
        line=dict(color=BLUE, width=1.5),
        marker=dict(size=9, color=ptcolors, line=dict(color=CHART_BG, width=1.5)),
        text=verdicts,
        hovertemplate="<b>%{text}</b><br>%{x}<extra></extra>",
    ))
    fig.update_layout(**_cs(
        margin=dict(t=28, b=36, l=120, r=12),
        xaxis=dict(**AXIS_STYLE),
        yaxis=dict(tickvals=[1, 2, 3],
                   ticktext=["ACTION REQUIRED", "NEEDS ATTENTION", "COMPLIANT"],
                   **AXIS_STYLE),
        title=dict(text="COMPLIANCE TREND OVER TIME", **CHART_TITLE),
    ))
    return fig
