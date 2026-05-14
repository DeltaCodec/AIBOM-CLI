import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Maps import_name → (display_name, pip_package_name)
FRAMEWORKS: dict[str, tuple[str, str]] = {
    "ray":        ("Ray", "ray"),
    "deepspeed":  ("DeepSpeed", "deepspeed"),
    "vllm":       ("vLLM", "vllm"),
    "nemo":       ("NVIDIA NeMo", "nemo"),
    "horovod":    ("Horovod", "horovod"),
    "mlflow":     ("MLflow", "mlflow"),
    "wandb":      ("Weights & Biases", "wandb"),
    "optuna":     ("Optuna", "optuna"),
    "bentoml":    ("BentoML", "bentoml"),
}

ML_LIBRARIES: dict[str, tuple[str, str]] = {
    "torch":                 ("PyTorch", "torch"),
    "tensorflow":            ("TensorFlow", "tensorflow"),
    "tf":                    ("TensorFlow", "tensorflow"),
    "jax":                   ("JAX", "jax"),
    "transformers":          ("HuggingFace Transformers", "transformers"),
    "sentence_transformers": ("Sentence Transformers", "sentence-transformers"),
    "diffusers":             ("HuggingFace Diffusers", "diffusers"),
    "timm":                  ("timm", "timm"),
    "faiss":                 ("FAISS", "faiss-cpu"),
    "sklearn":               ("scikit-learn", "scikit-learn"),
    "xgboost":               ("XGBoost", "xgboost"),
    "lightgbm":              ("LightGBM", "lightgbm"),
    "einops":                ("einops", "einops"),
    "accelerate":            ("HuggingFace Accelerate", "accelerate"),
    "peft":                  ("PEFT", "peft"),
    "trl":                   ("TRL", "trl"),
    "unsloth":               ("Unsloth", "unsloth"),
    "bitsandbytes":          ("bitsandbytes", "bitsandbytes"),
}

# Combined import-name → (display_name, pip_package, kind) for AST scanning
_IMPORT_MAP: dict[str, tuple[str, str, str]] = {
    imp: (name, pkg, "framework") for imp, (name, pkg) in FRAMEWORKS.items()
}
_IMPORT_MAP.update({
    imp: (name, pkg, "library") for imp, (name, pkg) in ML_LIBRARIES.items()
})


@dataclass
class Framework:
    name: str
    package: str
    import_name: str
    version: Optional[str] = None
    kind: str = "library"        # "framework" | "library"
    in_deps: bool = False
    detected_in: list[str] = field(default_factory=list)


def detect_frameworks(
    project_path: str,
    installed_packages: dict[str, str] | None = None,
    dep_names: set[str] | None = None,
) -> list[Framework]:
    """Scan project for ML frameworks and libraries.

    installed_packages: {pip_name: version} from pip freeze / pkg_map
    dep_names:          set of pip package names already in the dependencies table
    """
    inst = installed_packages or {}
    dep_norm = {d.lower().replace("-", "_") for d in (dep_names or set())}

    # Dedup by pip package name so aliases (tf/tensorflow) collapse to one entry
    found: dict[str, Framework] = {}
    found_in: dict[str, set[str]] = {}

    def _ver(pkg: str, imp: str) -> Optional[str]:
        return (
            inst.get(pkg)
            or inst.get(pkg.replace("-", "_"))
            or inst.get(pkg.replace("_", "-"))
            or inst.get(imp)
        )

    def _process_imports(imports: list[str], rel_path: str) -> None:
        for imp in imports:
            top = imp.split(".")[0]
            entry = _IMPORT_MAP.get(top) or _IMPORT_MAP.get(imp)
            if not entry:
                continue
            display_name, pkg, kind = entry
            if pkg in found:
                found_in[pkg].add(rel_path)
            else:
                found[pkg] = Framework(
                    name=display_name,
                    package=pkg,
                    import_name=top,
                    version=_ver(pkg, top),
                    kind=kind,
                )
                found_in[pkg] = {rel_path}

    root = Path(project_path)
    py_files_found = False
    for py_file in root.rglob("*.py"):
        py_files_found = True
        try:
            source = py_file.read_text(errors="ignore")
        except (OSError, PermissionError):
            continue
        _process_imports(_extract_imports(source), str(py_file.relative_to(root)))

    for nb_file in root.rglob("*.ipynb"):
        py_files_found = True
        imports = _extract_notebook_imports(nb_file)
        if imports:
            _process_imports(imports, str(nb_file.relative_to(root)))

    for pkg, paths in found_in.items():
        found[pkg].detected_in = sorted(paths)

    # Add installed-but-not-imported entries (once per pip package)
    _not_imported_sentinel = "(installed, not imported)" if py_files_found else "(no source files scanned)"
    for imp, (display_name, pkg, kind) in _IMPORT_MAP.items():
        if pkg in found:
            continue
        ver = _ver(pkg, imp)
        if ver:
            found[pkg] = Framework(
                name=display_name,
                package=pkg,
                import_name=imp,
                version=ver,
                kind=kind,
                detected_in=[_not_imported_sentinel],
            )

    # Flag entries already present in the pip dependencies table
    for fw in found.values():
        fw.in_deps = fw.package.lower().replace("-", "_") in dep_norm

    return list(found.values())


def _extract_notebook_imports(nb_path: Path) -> list[str]:
    try:
        data = json.loads(nb_path.read_text(errors="ignore"))
        imports = []
        for cell in data.get("cells", []):
            if cell.get("cell_type") == "code":
                source = "".join(cell.get("source", []))
                imports.extend(_extract_imports(source))
        return imports
    except Exception:
        return []


def _extract_imports(source: str) -> list[str]:
    imports = []
    try:
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module)
    except SyntaxError:
        for match in re.finditer(r"^\s*(?:import|from)\s+([\w.]+)", source, re.MULTILINE):
            imports.append(match.group(1))
    return imports
