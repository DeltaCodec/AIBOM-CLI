"""Cross-reference installed packages against known requirements for a model family."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# ── required packages per model family ───────────────────────────────────────
# Each entry: pip_package → minimum reason / label shown in the warning

_TRANSFORMERS_BASE = {
    "transformers": "HuggingFace model runtime",
    "torch":        "tensor backend",
}

_TRANSFORMERS_FULL = {
    **_TRANSFORMERS_BASE,
    "accelerate":   "device/memory management",
    "tokenizers":   "fast tokenizer backend",
}

_SENTENCE_TRANSFORMERS = {
    "sentence-transformers": "embedding model runtime",
    "transformers":          "backbone",
    "torch":                 "tensor backend",
}

_DIFFUSION = {
    "diffusers":    "diffusion pipeline runtime",
    "transformers": "text encoder",
    "torch":        "tensor backend",
    "accelerate":   "device/memory management",
}

_ONNX = {
    "onnxruntime":  "ONNX inference runtime",
}

_ONNX_GPU = {
    "onnxruntime-gpu": "ONNX GPU inference runtime",
}

# model_type / architecture fragment  →  required packages dict
_FAMILY_RULES: list[tuple[str, dict[str, str]]] = [
    # Sentence-transformers models
    ("sentence-transformers",       _SENTENCE_TRANSFORMERS),
    ("sentence_transformers",       _SENTENCE_TRANSFORMERS),
    # Diffusion
    ("unet",                        _DIFFUSION),
    ("diffusion",                   _DIFFUSION),
    ("vae",                         _DIFFUSION),
    # ONNX
    ("onnx",                        _ONNX),
    # LLMs that benefit from accelerate
    ("llama",                       _TRANSFORMERS_FULL),
    ("mistral",                     _TRANSFORMERS_FULL),
    ("mixtral",                     _TRANSFORMERS_FULL),
    ("qwen",                        _TRANSFORMERS_FULL),
    ("falcon",                      _TRANSFORMERS_FULL),
    ("mpt",                         _TRANSFORMERS_FULL),
    ("bloom",                       _TRANSFORMERS_FULL),
    ("opt",                         _TRANSFORMERS_FULL),
    ("gpt-j",                       _TRANSFORMERS_FULL),
    ("gptj",                        _TRANSFORMERS_FULL),
    ("gpt_neox",                    _TRANSFORMERS_FULL),
    ("phi",                         _TRANSFORMERS_FULL),
    ("gemma",                       _TRANSFORMERS_FULL),
    ("starcoder",                   _TRANSFORMERS_FULL),
    ("deepseek",                    _TRANSFORMERS_FULL),
    ("granite",                     _TRANSFORMERS_FULL),
    ("internlm",                    _TRANSFORMERS_FULL),
    ("yi",                          _TRANSFORMERS_FULL),
    ("baichuan",                    _TRANSFORMERS_FULL),
    # BERT-family / encoders (lighter)
    ("bert",                        _TRANSFORMERS_BASE),
    ("roberta",                     _TRANSFORMERS_BASE),
    ("deberta",                     _TRANSFORMERS_BASE),
    ("electra",                     _TRANSFORMERS_BASE),
    ("albert",                      _TRANSFORMERS_BASE),
    ("modernbert",                  _TRANSFORMERS_BASE),
    ("xlm",                         _TRANSFORMERS_BASE),
    ("distilbert",                  _TRANSFORMERS_BASE),
    ("camembert",                   _TRANSFORMERS_BASE),
    # Encoder-decoder
    ("t5",                          _TRANSFORMERS_FULL),
    ("bart",                        _TRANSFORMERS_FULL),
    ("pegasus",                     _TRANSFORMERS_FULL),
    ("mbart",                       _TRANSFORMERS_FULL),
    ("mt5",                         _TRANSFORMERS_FULL),
    # Vision
    ("vit",                         _TRANSFORMERS_BASE),
    ("deit",                        _TRANSFORMERS_BASE),
    ("clip",                        _TRANSFORMERS_BASE),
    ("blip",                        _TRANSFORMERS_FULL),
    ("sam",                         _TRANSFORMERS_FULL),
    # Generic HuggingFace catch-all (architecture ends with common suffixes)
    ("forcausallm",                 _TRANSFORMERS_FULL),
    ("forsequenceclassification",   _TRANSFORMERS_BASE),
    ("formaskedlm",                 _TRANSFORMERS_BASE),
    ("fortokenclassification",      _TRANSFORMERS_BASE),
    ("forquestionanswering",        _TRANSFORMERS_BASE),
    ("forseq2seqlm",                _TRANSFORMERS_FULL),
    ("model",                       _TRANSFORMERS_BASE),  # BertModel, ModernBertModel, etc.
]


@dataclass
class MissingDepResult:
    model_name: str
    family:     str
    required:   dict[str, str]        # pkg → reason
    missing:    dict[str, str]        # pkg → reason  (subset of required)
    installed:  dict[str, str] = field(default_factory=dict)  # pkg → version


def _normalise(pkg: str) -> str:
    return pkg.lower().replace("-", "_")


def _resolve_family(model_type: Optional[str], architecture: Optional[str],
                    library_name: Optional[str], model_name: str) -> tuple[str, dict[str, str]]:
    """Return (family_label, required_packages) for a model."""
    candidates = [
        (model_type or "").lower(),
        (architecture or "").lower(),
        (library_name or "").lower(),
        model_name.lower().split("/")[-1],   # last path component
    ]

    for fragment, reqs in _FAMILY_RULES:
        for candidate in candidates:
            if fragment in candidate:
                return fragment, reqs

    # no match — still need transformers if there's an architecture
    if architecture or model_type:
        return model_type or "unknown", _TRANSFORMERS_BASE

    return "unknown", {}


def check_missing_deps(
    models: list[dict],
    installed_packages: dict[str, str],
) -> list[MissingDepResult]:
    """
    models:             list of element dicts with type=="ai_model"
    installed_packages: {pip_name: version} — from pkg_map built during scan

    Returns one MissingDepResult per model that has at least one missing package.
    """
    inst_norm = {_normalise(k): v for k, v in installed_packages.items()}
    results: list[MissingDepResult] = []

    for m in models:
        # support both dataclass objects and plain dicts (BOM elements)
        if isinstance(m, dict):
            if m.get("isTrainingScript"):
                continue
            insp_raw     = m.get("inspection") or {}
            insp         = insp_raw if isinstance(insp_raw, dict) else {}
            model_type   = insp.get("modelType")  or m.get("modelType")
            architecture = insp.get("architecture")
            library_name = insp.get("libraryName") or m.get("hubMetadata", {}).get("library_name")
            model_name   = m.get("name", "unknown")
        else:
            if getattr(m, "is_training_script", False):
                continue
            insp_obj     = getattr(m, "inspection", None)
            model_type   = getattr(insp_obj, "model_type", None) if insp_obj else None
            architecture = getattr(insp_obj, "architecture", None) if insp_obj else None
            library_name = getattr(insp_obj, "library_name", None) if insp_obj else None
            model_name   = getattr(m, "source_id", None) or getattr(m, "name", "unknown")

        family, required = _resolve_family(model_type, architecture, library_name, model_name)
        if not required:
            continue

        missing = {
            pkg: reason
            for pkg, reason in required.items()
            if _normalise(pkg) not in inst_norm
               and _normalise(pkg.replace("-", "_")) not in inst_norm
               and _normalise(pkg.replace("_", "-")) not in inst_norm
        }
        if missing:
            inst_subset = {
                pkg: inst_norm.get(_normalise(pkg), "")
                for pkg in required
                if _normalise(pkg) in inst_norm
            }
            results.append(MissingDepResult(
                model_name=model_name,
                family=family,
                required=required,
                missing=missing,
                installed=inst_subset,
            ))

    return results
