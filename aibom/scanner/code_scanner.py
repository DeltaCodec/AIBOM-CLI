"""
Scan Python source files and Jupyter notebooks for model and dataset references.
Detects from_pretrained(), load_dataset(), and common dataset constructor calls.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

# from_pretrained("org/model-name") or ("model-name")
_FROM_PRETRAINED = re.compile(
    r"""from_pretrained\s*\(\s*['"]([a-zA-Z0-9_.\-/]+)['"]"""
)
# load_dataset("name") or load_dataset("name", "config")
_LOAD_DATASET = re.compile(
    r"""load_dataset\s*\(\s*['"]([a-zA-Z0-9_.\-/]+)['"]"""
)
# hf_hub_download(repo_id="...")  or  snapshot_download("...")
_HF_HUB_DOWNLOAD = re.compile(
    r"""(?:hf_hub_download|snapshot_download)\s*\([^)]*?['"]([a-zA-Z0-9_.\-/]+)['"]"""
)
# torchvision / torchaudio / torchtext dataset constructors
_TORCH_DATASET = re.compile(
    r"""(?:torchvision|torchaudio|torchtext)\.datasets\.(\w+)\s*\("""
)
# tensorflow_datasets.load("name")
_TFDS = re.compile(
    r"""tfds\.load\s*\(\s*['"]([a-zA-Z0-9_.\-/]+)['"]"""
)
# datasets.load_from_disk("path") — local dataset
_LOAD_FROM_DISK = re.compile(
    r"""load_from_disk\s*\(\s*['"]([^'"]+)['"]"""
)
# pandas file reads: pd.read_csv/parquet/json/excel/feather("path")
_PANDAS_READ = re.compile(
    r"""pd\.read_(?:csv|parquet|json|excel|feather|table|orc|sas|spss|stata)\s*\(\s*['"]([^'"]+)['"]"""
)
# sklearn built-in datasets: sklearn.datasets.load_iris() / fetch_20newsgroups() etc.
_SKLEARN_DATASET = re.compile(
    r"""(?:sklearn\.datasets|datasets)\.(load_\w+|fetch_\w+|make_\w+)\s*\("""
)
# keras.datasets.mnist.load_data() etc.
_KERAS_DATASET = re.compile(
    r"""keras\.datasets\.(\w+)\.load_data\s*\("""
)
# torch.utils.data.DataLoader(SomeDataset(...)) — capture class name
_TORCH_DATALOADER = re.compile(
    r"""DataLoader\s*\(\s*([A-Z]\w+)\s*\("""
)
# open("file.csv") / open("file.jsonl") for raw file reads
_OPEN_DATA_FILE = re.compile(
    r"""open\s*\(\s*['"]([^'"]+\.(?:csv|jsonl|tsv|parquet|json))['"]\s*[,)]"""
)


@dataclass
class CodeRef:
    kind: str           # "model" | "dataset"
    name: str
    source: str         # "huggingface" | "torchvision" | "tfds" | "local" | "unknown"
    file: str
    line: int


def scan_code_refs(project_path: str) -> tuple[list[CodeRef], list[CodeRef]]:
    """Return (model_refs, dataset_refs) found in .py and .ipynb files."""
    root = Path(project_path)
    model_refs: list[CodeRef] = []
    dataset_refs: list[CodeRef] = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix == ".py":
            lines = _read_py(path)
        elif path.suffix == ".ipynb":
            lines = _read_notebook(path)
        else:
            continue

        rel = str(path.relative_to(root))
        for i, line in enumerate(lines, 1):
            for m in _FROM_PRETRAINED.finditer(line):
                model_refs.append(CodeRef("model", m.group(1), "huggingface", rel, i))
            for m in _HF_HUB_DOWNLOAD.finditer(line):
                model_refs.append(CodeRef("model", m.group(1), "huggingface", rel, i))
            for m in _LOAD_DATASET.finditer(line):
                dataset_refs.append(CodeRef("dataset", m.group(1), "huggingface", rel, i))
            for m in _TORCH_DATASET.finditer(line):
                dataset_refs.append(CodeRef("dataset", m.group(1), "torchvision", rel, i))
            for m in _TFDS.finditer(line):
                dataset_refs.append(CodeRef("dataset", m.group(1), "tfds", rel, i))
            for m in _LOAD_FROM_DISK.finditer(line):
                dataset_refs.append(CodeRef("dataset", Path(m.group(1)).name, "local", rel, i))
            for m in _PANDAS_READ.finditer(line):
                name = Path(m.group(1)).name
                dataset_refs.append(CodeRef("dataset", name, "local", rel, i))
            for m in _SKLEARN_DATASET.finditer(line):
                dataset_refs.append(CodeRef("dataset", m.group(1), "sklearn", rel, i))
            for m in _KERAS_DATASET.finditer(line):
                dataset_refs.append(CodeRef("dataset", m.group(1), "keras", rel, i))
            for m in _TORCH_DATALOADER.finditer(line):
                dataset_refs.append(CodeRef("dataset", m.group(1), "pytorch", rel, i))
            for m in _OPEN_DATA_FILE.finditer(line):
                name = Path(m.group(1)).name
                dataset_refs.append(CodeRef("dataset", name, "local", rel, i))

    return _dedupe(model_refs), _dedupe(dataset_refs)


def _read_py(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []


def _read_notebook(path: Path) -> list[str]:
    lines: list[str] = []
    try:
        nb = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        for cell in nb.get("cells", []):
            if cell.get("cell_type") in ("code", "markdown"):
                src = cell.get("source", [])
                if isinstance(src, list):
                    lines.extend(src)
                else:
                    lines.extend(src.splitlines())
    except Exception:
        pass
    return lines


def _dedupe(refs: list[CodeRef]) -> list[CodeRef]:
    seen: set[tuple[str, str]] = set()
    out: list[CodeRef] = []
    for r in refs:
        key = (r.kind, r.name.lower())
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out
