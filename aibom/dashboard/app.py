"""Dash app factory — fixed navbar, jump-menu sidebar, single scrollable page."""
from __future__ import annotations

import json
from pathlib import Path

import dash
import dash_bootstrap_components as dbc
from dash import Input, Output, State, clientside_callback, dcc, html

from .layouts import error_layout, page_layout
from .theme import (
    BACKGROUND,
    BORDER,
    SIDEBAR_BG,
    TEAL,
    TEXT_MUTED,
    WHITE,
)

# ── jump menu sections ────────────────────────────────────────────────────────

_SECTIONS = [
    ("compliance",   "Compliance"),
    ("dependencies", "Dependencies"),
    ("models",       "Models"),
    ("datasets",     "Datasets"),
    ("privacy",      "Privacy"),
    ("history",      "History"),
]

_SIDEBAR_STYLE = {
    "position": "fixed",
    "top":      "56px",
    "left":     "0",
    "width":    "180px",
    "height":   "calc(100vh - 56px)",
    "backgroundColor": SIDEBAR_BG,
    "borderRight": f"1px solid {BORDER}",
    "padding": "16px 0",
    "overflowY": "auto",
    "zIndex": "100",
}

_CONTENT_STYLE = {
    "marginLeft": "180px",
    "marginTop":  "56px",
    "minWidth":   "800px",
    "backgroundColor": BACKGROUND,
    "minHeight":  "calc(100vh - 56px)",
}

_LINK_BASE = {
    "display": "block",
    "padding": "0.65rem 1.25rem",
    "color": TEXT_MUTED,
    "textDecoration": "none",
    "fontSize": "0.85rem",
    "fontWeight": "500",
    "borderLeft": "3px solid transparent",
    "cursor": "pointer",
}


def _sidebar() -> html.Div:
    links = []
    for sec_id, label in _SECTIONS:
        links.append(html.A(
            label,
            href=f"#section-{sec_id}",
            id=f"jump-{sec_id}",
            style=_LINK_BASE,
        ))
    return html.Div(links, style=_SIDEBAR_STYLE, id="sidebar")


def _navbar_children(bom: dict) -> list:
    name    = bom.get("name", "AI-BOM")
    created = bom.get("createdAt", "")[:16].replace("T", " ") + " UTC"
    return [
        dbc.NavbarBrand([
            html.Span("AI", style={"color": TEAL, "fontWeight": "800"}),
            html.Span("-BOM", style={"color": WHITE, "fontWeight": "600"}),
        ], href="#", style={"textDecoration": "none"}),
        html.Span(name, style={
            "color": TEXT_MUTED, "fontSize": "0.8rem",
            "marginLeft": "16px", "flex": "1",
            "overflow": "hidden", "textOverflow": "ellipsis",
            "whiteSpace": "nowrap",
        }),
        html.Span(created, style={
            "color": TEXT_MUTED, "fontSize": "0.78rem", "marginRight": "16px",
        }),
    ]


# ── scroll spy (clientside) ───────────────────────────────────────────────────

_SECTION_IDS   = str([s for s, _ in _SECTIONS])
_SCROLL_SPY_JS = f"""
function(_n) {{
    var sectionIds = {_SECTION_IDS};
    var teal = '{TEAL}';
    var muted = '{TEXT_MUTED}';

    function update() {{
        var active = sectionIds[0];
        for (var i = 0; i < sectionIds.length; i++) {{
            var el = document.getElementById('section-' + sectionIds[i]);
            if (!el) continue;
            if (el.getBoundingClientRect().top <= 90) active = sectionIds[i];
        }}
        for (var j = 0; j < sectionIds.length; j++) {{
            var link = document.getElementById('jump-' + sectionIds[j]);
            if (!link) continue;
            if (sectionIds[j] === active) {{
                link.style.color = teal;
                link.style.fontWeight = '600';
                link.style.borderLeft = '3px solid ' + teal;
                link.style.backgroundColor = '#2a2a2a';
            }} else {{
                link.style.color = muted;
                link.style.fontWeight = '500';
                link.style.borderLeft = '3px solid transparent';
                link.style.backgroundColor = 'transparent';
            }}
        }}
    }}

    if (window._aibomScrollSpy) window.removeEventListener('scroll', window._aibomScrollSpy);
    window._aibomScrollSpy = update;
    window.addEventListener('scroll', update, {{ passive: true }});
    update();
    return window.dash_clientside.no_update;
}}
"""


# ── app factory ───────────────────────────────────────────────────────────────

def create_app(bom_file: str) -> dash.Dash:
    bom_path = Path(bom_file).resolve()

    def _read_bom() -> tuple[dict | None, str | None]:
        try:
            return json.loads(bom_path.read_text(encoding="utf-8")), None
        except json.JSONDecodeError as exc:
            return None, f"Invalid JSON in {bom_path}: {exc}"
        except OSError as exc:
            return None, str(exc)

    bom, _err = _read_bom()

    app = dash.Dash(
        __name__,
        external_stylesheets=[dbc.themes.DARKLY],
        title="AI-BOM Dashboard",
        suppress_callback_exceptions=True,
        update_title=None,
    )

    if bom is None:
        app.layout = html.Div(
            error_layout(_err),
            style={"backgroundColor": BACKGROUND, "minHeight": "100vh"},
        )
        return app

    app.index_string = app.index_string.replace(
        "</head>",
        f"""<style>
body {{ background-color: {BACKGROUND}; }}
tr.bi-row:hover td {{ background-color: rgba(255,255,255,0.03) !important; }}
::-webkit-scrollbar {{ width: 6px; height: 6px; }}
::-webkit-scrollbar-track {{ background: {BACKGROUND}; }}
::-webkit-scrollbar-thumb {{ background: #333; border-radius: 3px; }}
#sidebar a:hover {{ color: {TEAL} !important; background-color: #242424; }}
html {{ scroll-behavior: smooth; }}
</style></head>""",
    )

    app.layout = html.Div([
        # fires once to wire scroll spy, then every 3 s to check for file changes
        dcc.Interval(id="_scroll-init", interval=400, max_intervals=1),
        dcc.Interval(id="_file-poll",   interval=3000, max_intervals=-1),
        dcc.Store(id="_last-mtime", data={"mtime": bom_path.stat().st_mtime, "path": str(bom_path)}),
        dbc.Navbar(
            dbc.Container(fluid=True, children=_navbar_children(bom), id="_navbar-inner"),
            dark=True,
            id="_navbar",
            style={
                "backgroundColor": SIDEBAR_BG,
                "borderBottom": f"1px solid {BORDER}",
                "position": "fixed", "top": "0", "width": "100%",
                "zIndex": "200", "height": "56px",
            },
        ),
        _sidebar(),
        html.Div(page_layout(bom), style=_CONTENT_STYLE, id="page-content"),
    ], style={"backgroundColor": BACKGROUND})

    # ── scroll spy ────────────────────────────────────────────────────────────
    clientside_callback(
        _SCROLL_SPY_JS,
        Output("_scroll-init", "disabled"),
        Input("_scroll-init", "n_intervals"),
        prevent_initial_call=False,
    )

    _POINTER = Path.home() / ".aibom_last_scan"
    # Pointer file is user-writable; only follow it to paths under the directory
    # the dashboard was originally launched against, to prevent path traversal.
    _ALLOWED_ROOT = bom_path.parent.resolve()

    def _is_within_allowed_root(candidate: Path) -> bool:
        try:
            return candidate.resolve().is_relative_to(_ALLOWED_ROOT)
        except (OSError, ValueError):
            return False

    # ── file-change watcher ───────────────────────────────────────────────────
    @app.callback(
        Output("page-content",   "children"),
        Output("_navbar-inner",  "children"),
        Output("_last-mtime",    "data"),
        Input("_file-poll",      "n_intervals"),
        State("_last-mtime",     "data"),
        prevent_initial_call=True,
    )
    def _reload_on_change(_, last_state):
        last_path  = last_state.get("path",  str(bom_path))
        last_mtime = last_state.get("mtime", 0)

        # follow the pointer to the newest scan file (constrained to the launch dir)
        current_path = last_path
        if _POINTER.exists():
            pointed = _POINTER.read_text(encoding="utf-8").strip()
            if pointed:
                pointed_path = Path(pointed)
                if pointed_path.exists() and _is_within_allowed_root(pointed_path):
                    current_path = str(pointed_path)

        try:
            mtime = Path(current_path).stat().st_mtime
        except OSError:
            return dash.no_update, dash.no_update, last_state

        if current_path == last_path and mtime == last_mtime:
            return dash.no_update, dash.no_update, last_state

        try:
            new_bom = json.loads(Path(current_path).read_text(encoding="utf-8"))
        except Exception as exc:
            return error_layout(str(exc)), dash.no_update, {"path": current_path, "mtime": mtime}

        new_state = {"path": current_path, "mtime": mtime}
        return page_layout(new_bom), _navbar_children(new_bom), new_state

    return app
