import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .model_inspector import ModelInspection, inspect_model_dir

MODEL_EXTENSIONS = {
    ".pt", ".pth", ".bin", ".ckpt", ".safetensors",
    ".h5", ".pb", ".onnx", ".tflite", ".pkl", ".joblib",
    ".mlmodel", ".engine", ".plan",
}

TRAINING_SCRIPT_PATTERNS = {
    "train.py", "train_*.py", "finetune.py", "finetune_*.py",
    "pretrain.py", "run_training.py", "main.py",
}

HF_SOURCE_FILES = {"config.json", "tokenizer.json", "tokenizer_config.json", "model_card.md"}

KNOWN_CHECKPOINT_DIRS = {
    "checkpoints", "checkpoint", "ckpts", "saved_models",
    "weights", "models", "model", "artifacts",
}


@dataclass
class ModelFile:
    name: str
    path: str
    size_bytes: int
    source: str = "unknown"
    source_id: Optional[str] = None
    license: Optional[str] = None
    version: Optional[str] = None
    sha256: Optional[str] = None
    expected_hash: Optional[str] = None
    tamper_detected: Optional[bool] = None
    is_checkpoint: bool = False
    is_training_script: bool = False
    inspection: Optional[ModelInspection] = None
    detection_method: str = "file"


def scan_models(
    project_path: str,
    config_models: list[dict] | None = None,
    code_refs: list | None = None,
    hf_cache_models: list | None = None,
) -> list[ModelFile]:
    # Build expected-hash lookup from config (by name or source_id)
    _expected: dict[str, str] = {}
    for entry in (config_models or []):
        eh = entry.get("expected_hash") or entry.get("hash")
        if eh:
            _expected[entry.get("name", "").lower()] = eh
            if entry.get("source_id"):
                _expected[entry["source_id"].lower()] = eh
    models: list[ModelFile] = []
    root = Path(project_path)
    inspected_dirs: set[Path] = set()

    root_resolved = root.resolve()
    for item in root.rglob("*"):
        if item.is_symlink() or not item.is_file():
            continue
        if item.suffix.lower() in MODEL_EXTENSIONS:
            entry = _build_model_entry(item, root)
            if item.parent not in inspected_dirs:
                entry.inspection = inspect_model_dir(item.parent)
                inspected_dirs.add(item.parent)
            # Apply tamper detection if config provided expected hash
            _check_key = (entry.source_id or entry.name).lower()
            if _check_key in _expected:
                entry.expected_hash = _expected[_check_key]
                if entry.sha256 is None:
                    entry.sha256 = _sha256(item)
                entry.tamper_detected = entry.sha256 != entry.expected_hash
            models.append(entry)
        elif _is_training_script(item.name):
            models.append(ModelFile(
                name=item.name,
                path=str(item.relative_to(root)),
                size_bytes=item.stat().st_size,
                source="local",
                is_training_script=True,
            ))

    def _seen_keys(m: ModelFile) -> set[str]:
        keys = {m.name.lower()}
        if m.source_id:
            keys.add(m.source_id.lower())
        return keys

    seen: set[str] = set()
    for m in models:
        seen.update(_seen_keys(m))

    # HF cache models supersede file-based entries for the same model ID
    for hf_m in (hf_cache_models or []):
        hf_keys = _seen_keys(hf_m)
        if hf_keys & seen:
            # Replace the weaker file-based entry with the richer cache entry
            models = [m for m in models if not (_seen_keys(m) & hf_keys)]
            seen -= hf_keys
        models.append(hf_m)
        seen.update(hf_keys)

    for ref in (code_refs or []):
        keys = {ref.name.lower()}
        if not keys & seen:
            seen.update(keys)
            models.append(ModelFile(
                name=ref.name,
                path=ref.file,
                size_bytes=0,
                source=ref.source,
                source_id=ref.name,
                detection_method="code",
            ))

    for entry in (config_models or []):
        name = entry.get("name", "unknown")
        if name.lower() not in seen:
            seen.add(name.lower())
            expected = entry.get("expected_hash") or entry.get("hash")
            mf = ModelFile(
                name=name,
                path=entry.get("path", ""),
                size_bytes=0,
                source=entry.get("source", "unknown"),
                source_id=entry.get("source_id"),
                license=entry.get("license"),
                version=entry.get("version"),
                expected_hash=expected,
            )
            # Verify hash if expected and path exists — reject path traversal
            if expected and mf.path:
                p = Path(mf.path)
                try:
                    resolved = (root / p).resolve() if not p.is_absolute() else p.resolve()
                    resolved.relative_to(root_resolved)  # raises ValueError if outside root
                    if resolved.exists() and resolved.is_file() and not resolved.is_symlink():
                        mf.sha256 = _sha256(resolved)
                        mf.tamper_detected = mf.sha256 != expected
                except (ValueError, OSError):
                    pass
            models.append(mf)

    return models


def _build_model_entry(path: Path, root: Path) -> ModelFile:
    stat = path.stat()
    source = _guess_source(path)
    hf_id = _infer_hf_model_id(path) or _guess_hf_id(path)
    is_checkpoint = any(p.lower() in KNOWN_CHECKPOINT_DIRS for p in path.parts)

    return ModelFile(
        name=hf_id or path.name,
        path=str(path.relative_to(root)),
        size_bytes=stat.st_size,
        source=source,
        source_id=hf_id,
        is_checkpoint=is_checkpoint,
        sha256=_sha256(path) if stat.st_size < 500 * 1024 * 1024 else None,
    )


def _is_training_script(name: str) -> bool:
    name_lower = name.lower()
    return (
        name_lower.startswith("train")
        or name_lower.startswith("finetune")
        or name_lower == "pretrain.py"
        or name_lower == "run_training.py"
    ) and name_lower.endswith(".py")


def _guess_source(path: Path) -> str:
    siblings = {f.name for f in path.parent.iterdir() if f.is_file()}
    if HF_SOURCE_FILES & siblings:
        return "huggingface"
    name_lower = path.name.lower()
    if "torch" in name_lower or path.suffix in {".pt", ".pth"}:
        return "pytorch"
    if path.suffix in {".h5", ".pb", ".tflite"}:
        return "tensorflow"
    if path.suffix == ".onnx":
        return "onnx"
    return "local"


def _infer_hf_model_id(path: Path) -> Optional[str]:
    """Walk up the path looking for a models--org--name directory."""
    for parent in path.parents:
        if parent.name.startswith("models--"):
            parts = parent.name[len("models--"):].split("--")
            return "/".join(parts)
    return None


def _guess_hf_id(path: Path) -> Optional[str]:
    """Fall back: read _name_or_path from config.json (may be a local path, not an HF ID)."""
    config = path.parent / "config.json"
    if config.exists():
        try:
            import json
            data = json.loads(config.read_text())
            val = data.get("_name_or_path", "")
            # Only use it if it looks like an HF model ID (org/name), not a local path
            if val and "/" in val and not val.startswith("/") and not val.startswith("."):
                return val
        except Exception:
            pass
    return None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
