import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
import rich.box
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.table import Table

from aibom.banner import print_banner
from aibom.compliance import (
    check_licenses,
    enrich_cves,
    flag_gdpr,
    scan_cves_direct,
    summarize_vulnerabilities,
)
from aibom.output import AuditTrail, generate_spdx
from aibom.scanner import (
    classify_eu_ai_act,
    detect_frameworks,
    enrich_datasets_from_model_cards,
    enrich_models,
    get_provenance_gaps,
    infer_from_model_lineage,
    scan_code_refs,
    scan_datasets,
    scan_dependencies,
    scan_hf_cache,
    scan_models,
)
from aibom.scanner.dep_check import check_missing_deps
from aibom.scanner.deps import Dependency, _pip_freeze
from aibom.scanner.hf_cache import resolve_hf_model_snapshot, scan_single_model_dir

console = Console()

# ── library_name → required pip packages ─────────────────────────────────────
_LIB_PACKAGES: dict[str, list[str]] = {
    "transformers":          ["transformers", "torch", "tokenizers", "safetensors", "huggingface_hub"],
    "sentence-transformers": ["sentence-transformers", "transformers", "torch", "tokenizers", "huggingface_hub"],
    "diffusers":             ["diffusers", "transformers", "torch", "accelerate", "huggingface_hub"],
    "peft":                  ["peft", "transformers", "torch"],
    "trl":                   ["trl", "transformers", "torch"],
    "timm":                  ["timm", "torch"],
    "keras":                 ["tensorflow", "keras"],
    "tf-keras":              ["tensorflow", "tf-keras"],
    "onnx":                  ["onnxruntime"],
    "openvino":              ["openvino"],
    "llama-cpp-python":      ["llama-cpp-python"],
    "mlx":                   ["mlx"],
}


def _pypi_latest_version(pkg: str) -> Optional[str]:
    """Return the latest PyPI release version for pkg, cached for 24 h."""
    import requests

    from aibom.cache import pypi_cache

    cache_key = f"latest-{pkg}"
    cached = pypi_cache.get(cache_key)
    if cached is not None:
        return cached
    try:
        resp = requests.get(f"https://pypi.org/pypi/{pkg}/json", timeout=8)
        resp.raise_for_status()
        ver = resp.json().get("info", {}).get("version")
        if ver:
            pypi_cache.set(cache_key, ver)
        return ver
    except Exception:
        return None


def _fetch_requires_dist(pkg: str, version: str, wanted: set[str]) -> dict[str, str]:
    """Fetch requires_dist from PyPI for pkg==version and return {dep: min_version}
    for each dep whose name is in *wanted*."""
    import requests
    from packaging.requirements import Requirement

    from aibom.cache import pypi_cache

    wanted_norm = {w.lower().replace("-", "_") for w in wanted}
    cache_key = f"{pkg}-{version}"
    cached = pypi_cache.get(cache_key)
    if cached is not None:
        requires_dist = cached
    else:
        try:
            resp = requests.get(
                f"https://pypi.org/pypi/{pkg}/{version}/json", timeout=12
            )
            resp.raise_for_status()
            requires_dist = resp.json().get("info", {}).get("requires_dist") or []
            pypi_cache.set(cache_key, requires_dist)
        except Exception:
            return {}

    result: dict[str, str] = {}
    for req_str in requires_dist:
        try:
            req = Requirement(req_str)
            key = req.name.lower().replace("-", "_")
            if key not in wanted_norm:
                continue
            # Skip optional/extra deps (e.g. requires = torch ; extra == "torch")
            if req.marker and "extra" in str(req.marker):
                continue
            # Use the minimum >= / ~= / == bound as the pinned version
            for spec in sorted(req.specifier, key=lambda s: s.version):
                if spec.operator in (">=", "==", "~="):
                    result[req.name] = spec.version
                    break
        except Exception:
            continue
    return result


def _infer_snapshot_deps(snapshot: Path) -> list[Dependency]:
    """Infer runtime requirements from model snapshot files + config.json.

    Version resolution order (per package):
      1. Locally installed (pip freeze)
      2. config.json hint  (transformers_version)
      3. PyPI requires_dist of the anchor package  ← pins transitive deps
      4. "unknown" fallback
    """
    packages: set[str] = set()
    cfg: dict = {}

    config_path = snapshot / "config.json"
    if config_path.exists():
        try:
            cfg = json.loads(config_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            pass

    lib = (cfg.get("library_name") or "").lower()
    if lib in _LIB_PACKAGES:
        packages.update(_LIB_PACKAGES[lib])
    elif cfg.get("transformers_version") or cfg.get("architectures") or cfg.get("model_type"):
        packages.update(_LIB_PACKAGES["transformers"])

    # File-presence signals
    files: set[str] = set()
    subdirs: set[str] = set()
    if snapshot.is_dir():
        for item in snapshot.iterdir():
            (files if item.is_file() else subdirs).add(item.name)
    suffixes = {Path(f).suffix for f in files}

    if ".safetensors" in suffixes:
        packages.add("safetensors")
    if "tokenizer.json" in files:
        packages.add("tokenizers")
    if "sentence_bert_config.json" in files or "1_Pooling" in subdirs:
        packages.update(_LIB_PACKAGES["sentence-transformers"])
    if suffixes & {".pt", ".pth", ".bin", ".ckpt"}:
        packages.add("torch")
    if ".onnx" in suffixes:
        packages.add("onnxruntime")
    if config_path.exists():
        packages.add("huggingface_hub")

    if not packages:
        return []

    # ── version resolution ────────────────────────────────────────────────────
    installed = _pip_freeze()
    transformers_v = cfg.get("transformers_version")

    # Determine the anchor package + version to pull transitive requirements from
    anchor_pkg: str | None = None
    anchor_ver: str | None = None
    if transformers_v and "transformers" in packages:
        anchor_pkg, anchor_ver = "transformers", transformers_v
    elif lib in _LIB_PACKAGES:
        anchor_pkg = lib

    # Seed known versions
    pinned: dict[str, str] = {}
    if transformers_v:
        pinned["transformers"] = transformers_v

    # Fetch requires_dist of anchor to pin transitive packages
    if anchor_pkg and anchor_ver:
        transitive = _fetch_requires_dist(anchor_pkg, anchor_ver, packages)
        for name, ver in transitive.items():
            norm = name.lower().replace("-", "_")
            if norm not in {k.lower().replace("-", "_") for k in pinned}:
                pinned[name] = ver

    # Build final Dependency list
    deps = []
    for pkg in sorted(packages):
        pkg_norm = pkg.lower().replace("-", "_")

        # 1. locally installed
        version = (
            installed.get(pkg)
            or installed.get(pkg.replace("-", "_"))
            or installed.get(pkg.replace("_", "-"))
        )
        # 2. config.json / transitive pin
        if not version:
            version = next(
                (v for k, v in pinned.items() if k.lower().replace("-", "_") == pkg_norm),
                None,
            )
        # 3. importlib.metadata — finds packages installed in any venv on sys.path
        if not version:
            try:
                import importlib.metadata as _ilm
                version = _ilm.version(pkg)
            except Exception:
                try:
                    version = _ilm.version(pkg.replace("-", "_") if "-" in pkg else pkg.replace("_", "-"))
                except Exception:
                    pass
        # 4. PyPI latest release — last resort when not locally installed
        if not version:
            version = _pypi_latest_version(pkg)
        # 5. unknown
        deps.append(Dependency(name=pkg, version=version or "unknown"))

    return deps


@click.group()
@click.version_option("0.1.0", prog_name="ai-bom")
def main():
    """AI Bill of Materials generator for ML projects."""


@main.command()
@click.argument("project_path", default=".", type=click.Path(exists=True))
@click.option("--config", "-c", default="aibom.yaml", help="Config file path")
@click.option("--output", "-o", default=None, help="Output JSON path (default: auto-named)")
@click.option("--output-dir", default=None, help="Directory to store output (default: current dir)")
@click.option("--allowlist", multiple=True, help="Extra allowed SPDX license IDs")
@click.option("--no-audit", is_flag=True, help="Skip writing audit trail")
@click.option("--no-pypi", is_flag=True, help="Skip PyPI license lookups (use local metadata only)")
@click.option("--no-hub", is_flag=True, help="Skip HuggingFace Hub API enrichment")
@click.option("--no-cache", is_flag=True, help="Skip HuggingFace local cache scanning")
@click.option("--no-cve", is_flag=True, help="Skip OSV CVE enrichment")
@click.option("--quiet", "-q", is_flag=True, help="Suppress progress output")
def scan(
    project_path: str,
    config: str,
    output: Optional[str],
    output_dir: Optional[str],
    allowlist: tuple,
    no_audit: bool,
    no_pypi: bool,
    no_hub: bool,
    no_cve: bool,
    no_cache: bool,
    quiet: bool,
):
    """Scan a project directory and generate an AI-BOM."""
    _scan_start = time.perf_counter()
    if not quiet:
        print_banner(console)
    cfg = _load_config(config)
    project_name = cfg.get("project", {}).get("name") or Path(project_path).resolve().name
    project_version = cfg.get("project", {}).get("version") or "0.0.0"
    output_path = cfg.get("output", {}).get("path") or output or _auto_output_name(project_name, output_dir)

    audit = AuditTrail()
    audit.record("scan_started", project=project_name, path=project_path)

    project_p = Path(project_path).resolve()
    is_model_dir_scan = _is_model_dir(project_p)

    # Also treat models--org--name cache dirs as single-model scans
    _hf_snapshot: Path | None = None
    if not is_model_dir_scan:
        _hf_snapshot = resolve_hf_model_snapshot(project_p)
        if _hf_snapshot:
            is_model_dir_scan = True

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        disable=quiet,
    ) as progress:
        t = progress.add_task("Scanning dependencies...", total=None)
        if is_model_dir_scan:
            scan_target = _hf_snapshot or project_p
            # Only use scan_dependencies when requirements.txt is explicitly present —
            # otherwise it falls back to the full env and bleeds every installed package.
            has_reqs = any(scan_target.glob("requirements*.txt"))
            if has_reqs:
                deps = scan_dependencies(str(scan_target))
            else:
                progress.update(t, description="Inferring model runtime requirements...")
                deps = _infer_snapshot_deps(scan_target)
            progress.update(t, description=f"Found {len(deps)} inferred requirement(s)")
        else:
            deps = scan_dependencies(project_path)
            progress.update(t, description=f"Found {len(deps)} packages")
        audit.record("deps_scanned", count=len(deps))

        progress.update(t, description="Scanning source code for model/dataset references...")
        model_code_refs, dataset_code_refs = scan_code_refs(project_path)
        audit.record("code_refs_scanned", models=len(model_code_refs), datasets=len(dataset_code_refs))

        hf_cache_models = []
        if not no_cache:
            if is_model_dir_scan:
                scan_target = _hf_snapshot or project_p
                progress.update(t, description="Inspecting model directory...")
                m = scan_single_model_dir(scan_target)
                if m:
                    hf_cache_models = [m]
            else:
                referenced = {r.name for r in model_code_refs if r.source == "huggingface"}
                if referenced:
                    progress.update(t, description=f"Scanning HF cache for {len(referenced)} referenced model(s)...")
                    hf_cache_models = scan_hf_cache(cfg.get("hf_cache_dir"), filter_ids=referenced)
                elif not model_code_refs:
                    progress.update(t, description="Scanning HuggingFace local cache...")
                    hf_cache_models = scan_hf_cache(cfg.get("hf_cache_dir"))
            audit.record("hf_cache_scanned", count=len(hf_cache_models))

        # When scanning a specific model dir/snapshot, restrict file scanning to that dir
        effective_scan_path = str(_hf_snapshot or project_p) if is_model_dir_scan else project_path

        progress.update(t, description="Scanning datasets...")
        datasets = scan_datasets(effective_scan_path, cfg.get("datasets"), dataset_code_refs)
        audit.record("datasets_scanned", count=len(datasets))

        progress.update(t, description="Scanning models...")
        models = scan_models(effective_scan_path, cfg.get("models"), model_code_refs, hf_cache_models)
        audit.record("models_scanned", count=len(models))

        hub_cards = {}
        if not no_hub:
            hf_count = sum(1 for m in models if m.source == "huggingface" and m.source_id)
            if hf_count:
                progress.update(t, description=f"Fetching HuggingFace metadata for {hf_count} model(s)...")
                hub_cards = enrich_models(models)
                audit.record("hub_enriched", count=len(hub_cards))

        # Enrich datasets from model card metadata (CONFIRMED) + known lineage (INFERRED)
        progress.update(t, description="Enriching dataset provenance...")
        card_datasets = enrich_datasets_from_model_cards(datasets, models, hub_cards)
        datasets.extend(card_datasets)
        lineage_datasets = infer_from_model_lineage(models, hub_cards, datasets)
        datasets.extend(lineage_datasets)
        provenance_gaps = get_provenance_gaps(models, datasets)
        if card_datasets or lineage_datasets:
            audit.record("dataset_provenance_enriched",
                         card=len(card_datasets), lineage=len(lineage_datasets),
                         gaps=len(provenance_gaps))

        inspected = sum(1 for m in models if m.inspection is not None)
        if inspected:
            progress.update(t, description=f"Classifying EU AI Act risk for {inspected} model(s)...")
            for m in models:
                if m.inspection:
                    card = hub_cards.get(m.source_id) if m.source_id else None
                    pipeline = card.pipeline_tag if card else None
                    tags = card.tags if card else []
                    risk, reasons = classify_eu_ai_act(pipeline, tags, m.inspection.architecture)
                    m.inspection.eu_ai_act_risk = risk
                    m.inspection.eu_ai_act_reasons = reasons
            audit.record("eu_ai_act_classified", count=inspected)

        progress.update(t, description="Detecting frameworks...")
        pkg_map = {d.name: d.version for d in deps}
        frameworks = detect_frameworks(project_path, pkg_map, dep_names={d.name for d in deps})
        audit.record("frameworks_detected", names=[f.name for f in frameworks])

        missing_deps = check_missing_deps(models, pkg_map)

        progress.update(t, description="Fetching licenses from PyPI..." if not no_pypi else "Checking licenses...")
        extra_allows = set(allowlist) | set(cfg.get("license_allowlist", []))
        from aibom.compliance.licenses import DEFAULT_ALLOWLIST
        license_results = check_licenses(
            deps,
            DEFAULT_ALLOWLIST | extra_allows if extra_allows else None,
            use_pypi=not no_pypi,
        )
        audit.record("licenses_checked")

        progress.update(t, description="Flagging GDPR risks...")
        gdpr_extra = cfg.get("gdpr_sources", [])
        gdpr_flags = flag_gdpr(datasets, gdpr_extra)
        audit.record("gdpr_flagged", count=len(gdpr_flags))

        if not no_cve and deps:
            progress.update(t, description=f"Querying OSV for CVEs ({len(deps)} package(s))...")
            scan_cves_direct(deps)

        progress.update(t, description="Summarizing vulnerabilities...")
        vuln_summary = summarize_vulnerabilities(deps)
        audit.record("vulns_summarized", count=vuln_summary.total_vulnerabilities)

        cves_by_package = {}
        if not no_cve and vuln_summary.total_vulnerabilities:
            progress.update(t, description="Enriching CVE details from OSV...")
            cves_by_package = enrich_cves(deps)
            vuln_summary.by_package = cves_by_package
            total_cves = sum(len(v) for v in cves_by_package.values())
            audit.record("cves_enriched", count=total_cves)

        progress.update(t, description="Generating SPDX 3.0 AI-BOM...")
        audit.record("bom_generated", output=output_path)

        bom = generate_spdx(
            project_name=project_name,
            project_version=project_version,
            dependencies=deps,
            datasets=datasets,
            models=models,
            frameworks=frameworks,
            license_results=license_results,
            gdpr_flags=gdpr_flags,
            vuln_summary=vuln_summary,
            audit_trail=[] if no_audit else audit.to_list(),
            hub_cards=hub_cards,
            cves_by_package=cves_by_package,
            provenance_gaps=provenance_gaps,
        )

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(bom, indent=2))
        try:
            Path.home().joinpath(".aibom_last_scan").write_text(str(out.resolve()), encoding="utf-8")
        except OSError:
            pass
        if not no_audit:
            audit.flush_to_history(output_path)
        _scan_elapsed = time.perf_counter() - _scan_start
        progress.update(t, description=f"[green]Done → {out.resolve()}[/]")

    if not quiet:
        _print_summary(bom, license_results, gdpr_flags, vuln_summary, provenance_gaps, missing_deps)
        _print_compliance_summary(bom)
        console.print(
            f"\n[dim]Scan completed in {_scan_elapsed:.1f}s  ·  {out.resolve()}[/]"
        )

    sys.exit(0)


def _latest_bom_file() -> Optional[str]:
    """Return the path of the last scan written by this CLI, falling back to newest aibom-*.json in cwd."""
    pointer = Path.home() / ".aibom_last_scan"
    if pointer.exists():
        p = Path(pointer.read_text(encoding="utf-8").strip())
        if p.exists():
            return str(p)
    candidates = sorted(Path(".").glob("aibom-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return str(candidates[0]) if candidates else None


@main.command()
@click.argument("bom_file", default=None, required=False, type=click.Path())
@click.option("--host", default="127.0.0.1", help="Host to bind")
@click.option("--port", default=8050, type=int, help="Port to bind")
@click.option("--debug", is_flag=True)
@click.option("--no-browser", is_flag=True, help="Don't open browser automatically")
def dashboard(bom_file: Optional[str], host: str, port: int, debug: bool, no_browser: bool):
    """Launch the AI-BOM Dash dashboard.

    BOM_FILE defaults to the most recently generated aibom-*.json in the current directory.
    """
    import webbrowser
    print_banner(console)

    if bom_file is None:
        bom_file = _latest_bom_file()
        if bom_file is None:
            console.print("[#e06c6c]Error:[/] No aibom-*.json found in current directory. "
                          "Run [bold]aibom scan[/] first, or pass a BOM file path.")
            sys.exit(1)
        console.print(f"[dim]Using latest scan:[/] {bom_file}")

    if not Path(bom_file).exists():
        console.print(f"[#e06c6c]Error:[/] File not found: {bom_file}")
        sys.exit(1)

    # Validate BOM before launching
    import json as _json
    try:
        bom_data = _json.loads(Path(bom_file).read_text(encoding="utf-8"))
        if "spdxVersion" not in bom_data:
            console.print(f"[#e06c6c]Error:[/] {bom_file} does not look like a valid SPDX BOM (missing spdxVersion)")
            sys.exit(1)
    except _json.JSONDecodeError as exc:
        console.print(f"[#e06c6c]Error:[/] {bom_file} is not valid JSON: {exc}")
        sys.exit(1)

    try:
        from aibom.dashboard.app import create_app
        app = create_app(bom_file)
        url = f"http://{host}:{port}"
        console.print(f"[#7dd3b0]Dashboard running at[/] [bold]{url}[/]")
        if not no_browser:
            webbrowser.open(url)
        app.run(host=host, port=port, debug=debug)
    except ImportError as e:
        console.print(f"[#e06c6c]Dashboard deps missing:[/] {e}")
        console.print("Run: pip install ai-bom[dashboard]")
        sys.exit(1)


@main.command()
@click.argument("model_ids", nargs=-1, required=True)
def resolve(model_ids: tuple[str, ...]):
    """Resolve one or more vendor model-id strings.

    Parses each MODEL_ID (as found in code, config, or IaC) and reports its
    model provider, hosting provider, and whether it's a floating alias that
    can silently resolve to a different model version. Pure string parsing —
    no network access, no vendor SDK or API key required.
    """
    from aibom.scanner.vendor_resolver import resolve_model_id

    print_banner(console)
    _section("MODEL IDENTIFIER RESOLUTION")

    exit_code = 0
    for model_id in model_ids:
        r = resolve_model_id(model_id)
        console.print(f"  [bold white]{r.raw}[/]")
        if not r.resolved:
            exit_code = 1
            console.print(f"    [#e06c6c]unresolved[/] — {r.note}")
            console.print()
            continue

        provider_line = f"    provider: [bold]{r.model_provider}[/]"
        if r.hosting_provider and r.hosting_provider != r.model_provider:
            provider_line += f"  (governed by: [bold]{r.hosting_provider}[/])"
        console.print(provider_line)

        if r.floating_alias:
            exit_code = 1
            console.print("    [#e0b96c]floating alias[/] — no pinned snapshot")
        elif r.snapshot:
            console.print(f"    pinned snapshot: {r.snapshot}")

        if r.note:
            console.print(f"    [dim]{r.note}[/]")
        console.print()

    sys.exit(exit_code)


_MODEL_WEIGHT_SUFFIXES = {".safetensors", ".bin", ".pt", ".pth", ".ckpt", ".onnx", ".h5"}


def _is_model_dir(path: Path) -> bool:
    """True when path looks like a model snapshot directory."""
    if not path.is_dir():
        return False
    if not (path / "config.json").exists():
        return False
    return any(f.suffix in _MODEL_WEIGHT_SUFFIXES for f in path.iterdir() if f.is_file())


def _auto_output_name(project_name: str, output_dir: Optional[str]) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_-]", "-", project_name).strip("-")
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"aibom-{safe}-{ts}.json"
    if output_dir:
        return str(Path(output_dir) / filename)
    return filename


def _load_config(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        console.print(f"[#f0c070]Warning:[/] could not parse config {p}: {exc}")
        return {}


_SEVERITY_COLOR = {
    "CRITICAL": "#e06c6c",
    "HIGH":     "#e06c6c",
    "MODERATE": "#f0c070",
    "MEDIUM":   "#f0c070",
    "LOW":      "#7dd3b0",
    "UNKNOWN":  "dim",
}


def _target_version(suggestion: str) -> str:
    if suggestion.startswith("Upgrade to "):
        return f"[green]{suggestion[len('Upgrade to'):].strip()}[/]"
    if "No fix" in suggestion:
        return "[red]no fix[/]"
    return "[dim]—[/]"


_CONFIDENCE_COLOR = {"CONFIRMED": "#7dd3b0", "INFERRED": "#f0c070", "UNKNOWN": "#e06c6c"}
_SOURCE_TYPE_LABEL = {
    "web_scrape": "web scrape",
    "licensed":   "licensed",
    "synthetic":  "synthetic",
    "internal":   "internal",
    "unknown":    "unknown",
}


def _section(title: str) -> None:
    console.print()
    console.print(f"[bold white]{title}[/]")
    console.print(Rule(style="dim"))


def _print_summary(bom: dict, license_results, gdpr_flags, vuln_summary, provenance_gaps: list | None = None, missing_deps=None):
    s = bom["summary"]

    # ── Summary panel ─────────────────────────────────────────────────────────
    total_cves = s.get("totalCVEs") or vuln_summary.total_vulnerabilities
    cve_part = (
        f"  [dim]·[/]  CVEs [bold #e06c6c]{total_cves}[/]"
        if total_cves else
        "  [dim]·[/]  CVEs [dim]0[/]"
    )
    fw_count  = s.get("totalFrameworks", 0)
    lib_count = s.get("totalLibraries", 0)
    fw_part = (
        f"Frameworks [bold white]{fw_count}[/]  [dim]·[/]  Libraries [bold white]{lib_count}[/]"
        if fw_count or lib_count else
        f"Frameworks [bold white]{s.get('totalFrameworks', 0)}[/]"
    )
    stats = (
        f"Packages [bold white]{s['totalDependencies']}[/]  [dim]·[/]  "
        f"Datasets [bold white]{s['totalDatasets']}[/]  [dim]·[/]  "
        f"Models [bold white]{s['totalModels']}[/]  [dim]·[/]  "
        f"{fw_part}"
        f"{cve_part}"
    )
    console.print()
    console.print(Panel(
        f"[bold white]AI-BOM Summary[/]\n{stats}",
        box=rich.box.ROUNDED,
        border_style="#7dd3b0",
        padding=(0, 2),
    ))

    # ── Dependencies table ────────────────────────────────────────────────────
    if license_results:
        _section("DEPENDENCIES")
        cves_by_package = bom.get("cvesByPackage", {})
        cve_count: dict[str, int] = {}
        for pinned, cve_list in cves_by_package.items():
            pkg = pinned.partition("==")[0]
            cve_count[pkg.lower()] = cve_count.get(pkg.lower(), 0) + len(cve_list)

        dt = Table(show_header=True, header_style="bold white", box=rich.box.SIMPLE)
        dt.add_column("Package",    no_wrap=True)
        dt.add_column("Version",    no_wrap=True)
        dt.add_column("License",    no_wrap=True)
        dt.add_column("Compliance", no_wrap=True)
        dt.add_column("CVEs",       no_wrap=True, justify="right")

        for r in sorted(license_results, key=lambda x: x.package.lower()):
            if r.allowed:
                comp = "[#7dd3b0]compliant[/]"
            elif r.spdx_id:
                comp = "[#f0c070]non-compliant[/]"
            else:
                comp = "[dim]unknown[/]"

            lic = r.spdx_id or r.license or "[dim]UNKNOWN[/]"
            if r.copyleft:
                lic = f"[#f0c070]{lic}[/]"

            n_cve = cve_count.get(r.package.lower(), 0)
            cve_cell = f"[#f0c070]{n_cve}[/]" if n_cve else "[dim]—[/]"

            ver = r.version if r.version != "unknown" else "[dim]unknown[/]"
            dt.add_row(r.package, ver, lic, comp, cve_cell)

        console.print(dt)

    # ── CVE details ───────────────────────────────────────────────────────────
    cves_by_package = bom.get("cvesByPackage", {})
    if cves_by_package:
        _section("VULNERABILITIES")
        sev_counts = s.get("cveSeverityCounts", {})
        _sev_order = ["CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW", "UNKNOWN"]
        sev_parts = "  ".join(
            f"[{_SEVERITY_COLOR.get(k, 'white')}]{k}: {v}[/]"
            for k, v in sorted(sev_counts.items(),
                key=lambda x: _sev_order.index(x[0]) if x[0] in _sev_order else 99)
        )
        console.print(f"Total [bold white]{s.get('totalCVEs', 0)}[/]  {sev_parts}")
        console.print()

        t = Table(show_header=True, header_style="bold white", box=rich.box.SIMPLE)
        t.add_column("Package",    no_wrap=True)
        t.add_column("Installed",  no_wrap=True)
        t.add_column("Update To",  no_wrap=True)
        t.add_column("Vuln ID",    no_wrap=True)
        t.add_column("CVE ID",     no_wrap=True)
        t.add_column("Severity",   no_wrap=True)

        no_fix_packages: list[str] = []
        for pinned, cve_list in sorted(cves_by_package.items()):
            pkg, _, ver = pinned.partition("==")
            for c in cve_list:
                sev = c["severity"]
                color = _SEVERITY_COLOR.get(sev, "white")
                fix = _target_version(c["suggestion"])
                if "No fix" in c.get("suggestion", ""):
                    no_fix_packages.append(f"{pkg} ({c['cveId'] or c['vulnId']})")
                t.add_row(
                    pkg,
                    ver or c["installedVersion"],
                    fix,
                    c["vulnId"],
                    c["cveId"] or "[dim]—[/]",
                    f"[{color}]{sev}[/]",
                )
        console.print(t)
        if no_fix_packages:
            console.print()
            for entry in no_fix_packages:
                console.print(f"  [#e06c6c bold]⚠ No fix available:[/] {entry} — no upstream patch exists, consider removing or isolating this dependency")

    # ── Model inspection ──────────────────────────────────────────────────────
    _print_model_inspections(bom)

    # ── Non-compliant licenses ────────────────────────────────────────────────
    non_compliant = [r for r in license_results if not r.allowed and r.spdx_id]
    if non_compliant:
        _section("NON-COMPLIANT LICENSES")
        t = Table(show_header=True, header_style="bold white", box=rich.box.SIMPLE)
        t.add_column("Package", no_wrap=True)
        t.add_column("License", no_wrap=True)
        for r in non_compliant[:20]:
            t.add_row(f"{r.package}=={r.version}", r.spdx_id or r.license or "UNKNOWN")
        console.print(t)

    # ── Datasets table ────────────────────────────────────────────────────────
    datasets_elements = [e for e in bom.get("elements", []) if e.get("type") == "dataset"]
    if datasets_elements:
        _section("DATASETS")
        dst = Table(show_header=True, header_style="bold white", box=rich.box.SIMPLE)
        dst.add_column("Name",        no_wrap=True)
        dst.add_column("Confidence",  no_wrap=True)
        dst.add_column("Source Type", no_wrap=True)
        dst.add_column("GDPR Risk",   no_wrap=True)
        dst.add_column("Privacy",     no_wrap=True)
        dst.add_column("Flags",       no_wrap=True)

        _gdpr_risk_col = {"HIGH": "#e06c6c", "MEDIUM": "#f0c070", "LOW": "dim white"}

        for e in sorted(datasets_elements, key=lambda x: (
            {"CONFIRMED": 0, "INFERRED": 1, "UNKNOWN": 2}.get(x.get("confidence", "UNKNOWN"), 2),
            x.get("name", "").lower()
        )):
            conf = e.get("confidence", "UNKNOWN")
            cc = _CONFIDENCE_COLOR.get(conf, "dim")
            conf_cell = f"[{cc}]{conf}[/]"

            src_type = _SOURCE_TYPE_LABEL.get(e.get("sourceType", "unknown"), e.get("sourceType", "—"))

            gdpr_risk = e.get("gdprRisk")
            risk_cell = (
                f"[{_gdpr_risk_col.get(gdpr_risk, 'dim')}]{gdpr_risk}[/]"
                if gdpr_risk else "[dim]—[/]"
            )

            gdpr = e.get("gdprRelevant", False)
            lgpd = e.get("lgpdRelevant", False)
            if gdpr and lgpd:
                privacy = "[#78b4f0]GDPR+LGPD[/]"
            elif gdpr:
                privacy = "[#78b4f0]GDPR[/]"
            elif lgpd:
                privacy = "[#78b4f0]LGPD[/]"
            else:
                privacy = "[dim]—[/]"

            flags = []
            if e.get("reviewRequired"):
                flags.append("[#f0c070]REVIEW_REQUIRED[/]")
            flags_cell = " ".join(flags) if flags else "[dim]—[/]"

            dst.add_row(e.get("name", ""), conf_cell, src_type, risk_cell, privacy, flags_cell)

        console.print(dst)

    # ── Provenance gaps ───────────────────────────────────────────────────────
    if provenance_gaps:
        _section("PROVENANCE GAPS")
        for gap_model in provenance_gaps:
            console.print(
                f"  [#e06c6c]•[/] [bold white]{gap_model}[/]  "
                f"[dim]dataset origin unknown — manual review recommended[/]"
            )

    # ── Missing dependencies ──────────────────────────────────────────────────
    if missing_deps:
        _section("MISSING DEPENDENCIES")
        for result in missing_deps:
            console.print(
                f"  [bold #e06c6c]⚠  {result.model_name}[/]  "
                f"[dim](family: {result.family})[/]"
            )
            mt = Table(show_header=True, header_style="dim", box=rich.box.SIMPLE,
                       padding=(0, 2))
            mt.add_column("Package",  no_wrap=True, style="bold white")
            mt.add_column("Required for", no_wrap=False, style="dim")
            mt.add_column("Install", no_wrap=True, style="#78b4f0")
            for pkg, reason in result.missing.items():
                mt.add_row(pkg, reason, f"pip install {pkg}")
            console.print(mt)

    # ── ML Libraries & Frameworks table ──────────────────────────────────────
    pkg_elem = next(
        (e for e in bom.get("elements", [])
         if e.get("SPDXID", "").startswith("SPDXRef-Package-")
         and "aiExtension" in e),
        None,
    )
    ae = (pkg_elem or {}).get("aiExtension", {}) if pkg_elem else {}
    # Frameworks first, then libraries — alphabetical within each group
    fw_items = sorted(
        ae.get("frameworks", []), key=lambda x: x.get("name", "").lower()
    ) + sorted(
        ae.get("mlLibraries", []), key=lambda x: x.get("name", "").lower()
    )
    if fw_items:
        _section("ML LIBRARIES & FRAMEWORKS")
        ft = Table(show_header=True, header_style="bold white", box=rich.box.SIMPLE)
        ft.add_column("Name",        no_wrap=True)
        ft.add_column("Type",        no_wrap=True)
        ft.add_column("Version",     no_wrap=True)
        ft.add_column("Detected In", no_wrap=True)
        for fw in fw_items:
            kind = fw.get("kind", "library")
            type_cell = (
                "[#78b4f0]framework[/]" if kind == "framework"
                else "[#7dd3b0]library[/]"
            )
            ver = fw.get("version") or "—"
            if fw.get("inDeps") and ver not in ("—", "unknown"):
                ver_cell = f"{ver} [dim](in deps)[/]"
            elif fw.get("inDeps"):
                ver_cell = "[dim](in deps)[/]"
            else:
                ver_cell = ver if ver != "unknown" else "[dim]unknown[/]"
            detected = fw.get("detectedIn") or []
            if not detected:
                det_cell = "[dim]—[/]"
            elif detected[0] == "(no source files scanned)":
                det_cell = "[dim]no source files scanned[/]"
            elif detected[0] == "(installed, not imported)":
                det_cell = "[#f0c070]⚠ installed only — verify if needed[/]"
            else:
                first = detected[0]
                det_cell = first if len(detected) == 1 else f"{first} +{len(detected) - 1}"
            ft.add_row(fw.get("name", ""), type_cell, ver_cell, det_cell)
        console.print(ft)

    # ── Privacy flags panel ───────────────────────────────────────────────────
    if gdpr_flags:
        console.print()
        _risk_color = {"HIGH": "#e06c6c", "MEDIUM": "#f0c070", "LOW": "dim white"}

        # Deduplicate by dataset name, keeping highest risk entry
        seen: dict[str, object] = {}
        for f in gdpr_flags:
            name = f.dataset_name
            if name not in seen:
                seen[name] = f
            elif getattr(f, "risk_level", "") == "HIGH":
                seen[name] = f

        lines = []
        for name, f in sorted(seen.items()):
            rc = _risk_color.get(getattr(f, "risk_level", "MEDIUM"), "#f0c070")
            lines.append(
                f"[{rc}]{getattr(f, 'risk_level', 'MEDIUM')}[/]  "
                f"[bold white]{name}[/]  [dim]·[/]  {f.reason}"
            )

        console.print(Panel(
            "\n".join(lines),
            title="[bold white]Privacy Flags[/]",
            border_style="#f0c070",
            box=rich.box.ROUNDED,
            padding=(0, 2),
        ))


_EU_RISK_COLOR = {"high": "#e06c6c", "limited": "#f0c070", "minimal": "dim white", "unknown": "dim"}
_PICKLE_COLOR = {"safe": "#7dd3b0", "unsafe": "#e06c6c", "skipped": "dim"}
_SYM_COLOR = {"green": "#7dd3b0", "amber": "#f0c070", "red": "#e06c6c"}


def _print_compliance_summary(bom: dict) -> None:
    s = bom.get("summary", {})
    elements = bom.get("elements", [])

    # ── 1. Licenses ───────────────────────────────────────────────────────────
    non_compliant = s.get("nonCompliantLicenses", 0)
    if non_compliant == 0:
        lic_sym, lic_text, lic_st = "✓", "[#7dd3b0]All compliant[/]", "green"
    else:
        n = non_compliant
        lic_sym, lic_text, lic_st = (
            "✗", f"[#e06c6c]{n} non-compliant package{'s' if n != 1 else ''}[/]", "red"
        )

    # ── 2. Vulnerabilities ────────────────────────────────────────────────────
    sev_counts = s.get("cveSeverityCounts", {})
    total_cves = s.get("totalCVEs", 0)
    critical_high = sev_counts.get("CRITICAL", 0) + sev_counts.get("HIGH", 0)
    no_fix_count = sum(
        1 for cve_list in bom.get("cvesByPackage", {}).values()
        for c in cve_list
        if "No fix" in c.get("suggestion", "") and c.get("severity") in ("CRITICAL", "HIGH")
    )
    if total_cves == 0:
        vuln_sym, vuln_text, vuln_st = "✓", "[#7dd3b0]None found[/]", "green"
    elif no_fix_count > 0:
        vuln_sym, vuln_text, vuln_st = (
            "✗",
            f"[#e06c6c]{no_fix_count} unpatched (no fix available)[/]",
            "red",
        )
    elif critical_high > 0:
        vuln_sym, vuln_text, vuln_st = (
            "⚠",
            f"[#f0c070]{critical_high} high/critical — fix available[/]",
            "amber",
        )
    else:
        vuln_sym, vuln_text, vuln_st = (
            "⚠", f"[#f0c070]{total_cves} moderate[/]", "amber"
        )

    # ── 3. Privacy ────────────────────────────────────────────────────────────
    gdpr_flags = bom.get("gdprFlags", [])
    high_flags = [f for f in gdpr_flags if f.get("riskLevel") == "HIGH"]
    high_privacy = len(high_flags)
    if not gdpr_flags:
        priv_sym, priv_text, priv_st = "✓", "[#7dd3b0]No flags[/]", "green"
    elif high_privacy > 0:
        _names = [f.get("dataset", "?") for f in high_flags[:3]]
        _suffix = ", ..." if len(high_flags) > 3 else ""
        _names_str = ", ".join(_names) + _suffix
        priv_sym, priv_text, priv_st = (
            "⚠",
            f"[#f0c070]{high_privacy} dataset{'s' if high_privacy != 1 else ''} flagged HIGH risk ({_names_str})[/]",
            "amber",
        )
    else:
        n = len(gdpr_flags)
        _names = [f.get("dataset", "?") for f in gdpr_flags[:3]]
        _suffix = ", ..." if n > 3 else ""
        _names_str = ", ".join(_names) + _suffix
        priv_sym, priv_text, priv_st = (
            "⚠", f"[#f0c070]{n} dataset{'s' if n != 1 else ''} flagged ({_names_str})[/]", "amber"
        )

    # ── 4. Datasets ───────────────────────────────────────────────────────────
    dataset_elems = [e for e in elements if e.get("type") == "dataset"]
    review_req = sum(1 for e in dataset_elems if e.get("reviewRequired"))
    if review_req == 0:
        ds_sym, ds_text, ds_st = "✓", "[#7dd3b0]All documented[/]", "green"
    else:
        ds_sym, ds_text, ds_st = (
            "⚠",
            f"[#f0c070]{review_req} dataset{'s' if review_req != 1 else ''} require manual review[/]",
            "amber",
        )

    # ── 5. Models ─────────────────────────────────────────────────────────────
    model_elems = [e for e in elements if e.get("type") == "ai_model"]
    tampered  = sum(1 for e in model_elems if e.get("tamperDetected") is True)
    unverified = sum(
        1 for e in model_elems
        if e.get("tamperDetected") is None and e.get("checksums")
    )
    if tampered > 0:
        mdl_sym, mdl_text, mdl_st = (
            "✗",
            f"[#e06c6c]{tampered} model{'s' if tampered != 1 else ''} TAMPERED[/]",
            "red",
        )
    elif model_elems:
        # unverified = no expected_hash set → no baseline established, not a problem
        mdl_sym, mdl_text, mdl_st = (
            "✓",
            "[#7dd3b0]All verified[/]" if not unverified
            else f"[dim white]{unverified} unverified (no baseline set)[/]",
            "green",
        )
    else:
        mdl_sym, mdl_text, mdl_st = "✓", "[dim]No models scanned[/]", "green"

    # ── Overall verdict ───────────────────────────────────────────────────────
    statuses = [lic_st, vuln_st, priv_st, ds_st, mdl_st]
    if "red" in statuses:
        ov_sym  = "✗"
        ov_text = "[bold #e06c6c]ACTION REQUIRED[/]"
        ov_col  = "#e06c6c"
    elif "amber" in statuses:
        ov_sym  = "⚠"
        ov_text = "[bold #f0c070]NEEDS ATTENTION[/]"
        ov_col  = "#f0c070"
    else:
        ov_sym  = "✓"
        ov_text = "[bold #7dd3b0]COMPLIANT[/]"
        ov_col  = "#7dd3b0"

    # ── Render ────────────────────────────────────────────────────────────────
    _section("COMPLIANCE SUMMARY")

    rows = [
        ("Licenses",        lic_sym,  lic_st,  lic_text),
        ("Vulnerabilities", vuln_sym, vuln_st, vuln_text),
        ("Privacy",         priv_sym, priv_st, priv_text),
        ("Datasets",        ds_sym,   ds_st,   ds_text),
        ("Models",          mdl_sym,  mdl_st,  mdl_text),
    ]

    t = Table(show_header=False, box=rich.box.SIMPLE, padding=(0, 1))
    t.add_column("Label", style="dim white", width=20, no_wrap=True)
    t.add_column("Value", no_wrap=True)

    for label, sym, status, text in rows:
        col = _SYM_COLOR.get(status, "dim")
        t.add_row(label, f"[{col}]{sym}[/]  {text}")

    t.add_row("", "")
    t.add_row("[bold white]Overall[/]", f"[bold {ov_col}]{ov_sym}[/]  {ov_text}")

    console.print(t)


def _fmt_params(n: Optional[int]) -> str:
    if n is None:
        return "[dim]—[/]"
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.1f}B"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.0f}M"
    return str(n)


def _print_model_inspections(bom: dict) -> None:
    inspected = [
        e for e in bom.get("elements", [])
        if e.get("type") == "ai_model" and e.get("inspection")
    ]
    if not inspected:
        return

    _section("MODEL INSPECTION")

    t = Table(show_header=True, header_style="bold white", box=rich.box.SIMPLE)
    t.add_column("Model",        no_wrap=True)
    t.add_column("Architecture", no_wrap=True)
    t.add_column("Params",       no_wrap=True, min_width=6)
    t.add_column("Context",      no_wrap=True, min_width=7)
    t.add_column("Dtype",        no_wrap=True, min_width=7)
    t.add_column("Framework",    no_wrap=True)
    t.add_column("Pickle",       no_wrap=True, min_width=14)
    t.add_column("EU AI Act",    no_wrap=True, min_width=9)
    t.add_column("Integrity",    no_wrap=True, min_width=19)

    for elem in inspected:
        insp = elem["inspection"]
        arch = insp.get("architecture") or insp.get("modelType") or "[dim]—[/]"
        params = _fmt_params(insp.get("paramCountEstimate"))
        ctx = str(insp.get("contextLength")) if insp.get("contextLength") else "[dim]—[/]"
        dtype = insp.get("torchDtype") or "[dim]—[/]"

        ps = insp.get("pickleSafe") or "skipped"
        if ps == "safetensors":
            pickle_cell = "[#7dd3b0]safetensors ✓[/]"
        else:
            pc = _PICKLE_COLOR.get(ps, "dim")
            pickle_cell = f"[{pc}]{ps}[/]"
            if insp.get("pickleThreats"):
                pickle_cell += f" [{pc}]({len(insp['pickleThreats'])} threat(s))[/]"

        risk = insp.get("euAiActRisk") or "unknown"
        rc = _EU_RISK_COLOR.get(risk, "dim")
        eu_cell = f"[{rc}]{risk.upper()}[/]"

        lib = (
            insp.get("libraryName")
            or elem.get("hubMetadata", {}).get("libraryName")
        )
        fw_cell = f"[#78b4f0]{lib}[/]" if lib else "[dim]unknown[/]"

        sha = elem.get("checksums", [{}])[0].get("checksumValue") if elem.get("checksums") else None
        if elem.get("tamperDetected") is True:
            sha_str = f"[dim white]{sha[:8]}...[/] " if sha else ""
            integrity = f"{sha_str}[#e06c6c]TAMPERED[/]"
        elif elem.get("tamperDetected") is False:
            sha_str = f"[dim white]{sha[:8]}...[/] " if sha else ""
            integrity = f"{sha_str}[#7dd3b0]VERIFIED[/]"
        elif sha:
            integrity = f"[dim white]{sha[:8]}...[/] [dim]UNVERIFIED[/]"
        else:
            integrity = "[dim]—[/]"

        t.add_row(elem["name"], arch, params, ctx, dtype, fw_cell, pickle_cell, eu_cell, integrity)

    console.print(t)

    for elem in inspected:
        if elem.get("tamperDetected") is True:
            console.print(f"[#e06c6c bold]TAMPER ALERT:[/] {elem['name']} — SHA256 mismatch vs expected hash")

    for elem in inspected:
        threats = elem["inspection"].get("pickleThreats", [])
        if threats:
            console.print(f"[#e06c6c]Pickle threats in {elem['name']}:[/]")
            for thr in threats:
                console.print(f"  • {thr}")


if __name__ == "__main__":
    main()
