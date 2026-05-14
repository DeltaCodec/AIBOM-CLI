from rich.console import Console
from rich.panel import Panel
from rich import box


def _resolve_version() -> str:
    try:
        from importlib.metadata import version
        return version("ai-bom")
    except Exception:
        pass
    try:
        from pathlib import Path
        import re
        pyproject = Path(__file__).parent.parent / "pyproject.toml"
        m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject.read_text(), re.MULTILINE)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "0.1.0"


def print_banner(console: Console) -> None:
    version = _resolve_version()
    content = (
        "[bold white]AI-BOM[/]\n"
        "[bold #7dd3b0]A I   B I L L   O F   M A T E R I A L S   G E N E R A T O R[/]\n"
        "\n"
        f"[dim white]v{version}[/]  "
        "[#7dd3b0]SPDX 3.0[/]  [dim]·[/]  "
        "[#78b4f0]CVE / NVD[/]  [dim]·[/]  "
        "[#f0c070]EU AI Act[/]  [dim]·[/]  "
        "[#7dd3b0]LGPD / GDPR[/]"
    )
    console.print(
        Panel(content, box=box.MINIMAL, border_style="#7dd3b0", padding=(1, 2))
    )
