"""Color constants — matches CLI palette exactly."""

TEAL       = "#7dd3b0"
BLUE       = "#78b4f0"
AMBER      = "#f0c070"
RED        = "#e06c6c"
DIM        = "#666666"
WHITE      = "#e0e0e0"
BACKGROUND = "#1a1a1a"
SURFACE    = "#242424"
BORDER     = "#333333"
SIDEBAR_BG = "#1e1e1e"
CARD_BG    = "#2a2a2a"
TEXT_MUTED = "#888888"

CHART_BG  = "#1a1a1a"
GRIDLINE  = "#2a2a2a"
ROW_EVEN  = "#1a1a1a"
ROW_ODD   = "#1f1f1f"
ROW_HOVER = "#252525"

PLOT_BG = dict(
    paper_bgcolor=BACKGROUND,
    plot_bgcolor=SURFACE,
    font=dict(color=WHITE),
)

# BI-style chart base — sharp, dark, muted axes
CHART_STYLE = dict(
    paper_bgcolor=CHART_BG,
    plot_bgcolor=CHART_BG,
    font=dict(color="#888888", size=10),
    margin=dict(t=28, b=8, l=8, r=8),
    showlegend=False,
)
CHART_TITLE = dict(font=dict(color=TEAL, size=11, family="monospace"), x=0, xanchor="left")
AXIS_STYLE  = dict(gridcolor=GRIDLINE, color="#666", tickfont=dict(size=10), linecolor=GRIDLINE)

SEV_HEX = {
    "CRITICAL": "#c0392b",
    "HIGH":     RED,
    "MODERATE": AMBER,
    "MEDIUM":   AMBER,
    "LOW":      DIM,
    "UNKNOWN":  DIM,
}

RISK_HEX  = {"HIGH": RED,  "MEDIUM": AMBER, "LOW": DIM}
CONF_HEX  = {"CONFIRMED": TEAL, "INFERRED": AMBER, "UNKNOWN": RED}
EU_HEX    = {"high": RED, "limited": AMBER, "minimal": DIM, "unknown": DIM}
