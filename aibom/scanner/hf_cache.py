"""
Scan the local HuggingFace cache (~/.cache/huggingface/hub/) for downloaded models.
Cache layout: models--{org}--{name}/snapshots/{commit_hash}/
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Optional

from .model_inspector import inspect_model_dir
from .models import ModelFile, _sha256

_DEFAULT_CACHE = Path.home() / ".cache" / "huggingface" / "hub"
_WEIGHT_SUFFIXES = {".safetensors", ".bin", ".pt", ".pth", ".ckpt", ".onnx", ".h5"}


def _env_cache() -> Optional[Path]:
    p = os.environ.get("HF_HOME") or os.environ.get("HUGGINGFACE_HUB_CACHE")
    return Path(p) if p else None


def scan_single_model_dir(path: Path) -> Optional[ModelFile]:
    """Treat a single directory as a model snapshot and return one ModelFile."""
    weight_files = [f for f in path.iterdir() if f.is_file() and f.suffix in _WEIGHT_SUFFIXES]
    if not weight_files and not (path / "config.json").exists():
        return None
    total_size = sum(f.stat().st_size for f in weight_files)
    insp = inspect_model_dir(path)
    model_id = _infer_model_id(path)
    sha = _dir_sha256(path)
    return ModelFile(
        name=model_id or path.name,
        path=str(path),
        size_bytes=total_size,
        source="huggingface" if (path / "config.json").exists() else "local",
        source_id=model_id,
        version=path.name[:8],
        sha256=sha,
        inspection=insp,
        detection_method="direct-path",
    )


def scan_hf_cache(
    cache_dir: Optional[str] = None,
    filter_ids: Optional[set[str]] = None,
) -> list[ModelFile]:
    """Return ModelFile entries from the HF cache.

    filter_ids: if given, only return models whose ID is in this set.
    """
    root = (Path(cache_dir).expanduser().resolve() if cache_dir
            else (_env_cache() or _DEFAULT_CACHE))
    if not root.exists():
        return []

    models: list[ModelFile] = []
    for entry in root.iterdir():
        if not entry.is_dir() or not entry.name.startswith("models--"):
            continue
        model_id = _dir_to_model_id(entry.name)
        if filter_ids is not None and model_id.lower() not in {f.lower() for f in filter_ids}:
            continue
        snapshots_dir = entry / "snapshots"
        if not snapshots_dir.exists():
            continue
        for snapshot in sorted(snapshots_dir.iterdir(), reverse=True):   # newest first
            if not snapshot.is_dir():
                continue
            weight_files = [f for f in snapshot.iterdir() if f.is_file() and f.suffix in _WEIGHT_SUFFIXES]
            if not weight_files:
                continue
            total_size = sum(f.stat().st_size for f in weight_files)
            insp = inspect_model_dir(snapshot)
            sha = _dir_sha256(snapshot)
            models.append(ModelFile(
                name=model_id,
                path=str(snapshot),
                size_bytes=total_size,
                source="huggingface",
                source_id=model_id,
                version=snapshot.name[:8],
                sha256=sha,
                inspection=insp,
                detection_method="hf-cache",
            ))
            break   # only latest snapshot per model

    return models


def _dir_sha256(path: Path) -> Optional[str]:
    """Compute a deterministic SHA256 fingerprint for a model directory.

    Hashes config.json + each weight file (if < 200 MB individually; larger
    files contribute filename:size instead to stay fast).  Returns the hex
    digest of the combined manifest.
    """
    h = hashlib.sha256()
    parts: list[str] = []

    config = path / "config.json"
    if config.exists():
        parts.append(f"config:{_sha256(config)}")

    for f in sorted(path.iterdir()):
        if not f.is_file() or f.suffix not in _WEIGHT_SUFFIXES:
            continue
        sz = f.stat().st_size
        if sz < 200 * 1024 * 1024:
            parts.append(f"{f.name}:{_sha256(f)}")
        else:
            parts.append(f"{f.name}:size={sz}")

    if not parts:
        return None
    h.update("\n".join(parts).encode())
    return h.hexdigest()


def _dir_to_model_id(dir_name: str) -> str:
    return "/".join(dir_name[len("models--"):].split("--"))


def _infer_model_id(path: Path) -> Optional[str]:
    """Walk up the path to find a models--org--name parent and reconstruct the ID."""
    for parent in path.parents:
        if parent.name.startswith("models--"):
            return _dir_to_model_id(parent.name)
    return None


def resolve_hf_model_snapshot(path: Path) -> Optional[Path]:
    """If path is a models--org--name cache dir, return its latest snapshot dir."""
    if not path.is_dir() or not path.name.startswith("models--"):
        return None
    snapshots = path / "snapshots"
    if not snapshots.exists():
        return None
    candidates = sorted(
        (s for s in snapshots.iterdir() if s.is_dir()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for snap in candidates:
        has_weights = any(f.suffix in _WEIGHT_SUFFIXES for f in snap.iterdir() if f.is_file())
        has_config  = (snap / "config.json").exists()
        if has_weights or has_config:
            return snap
    return None
