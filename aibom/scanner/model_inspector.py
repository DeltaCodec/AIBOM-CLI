"""
Local model inspection: architecture metadata, param estimation,
pickle safety scanning, safetensors header validation, EU AI Act classification.
"""
from __future__ import annotations

import json
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Pickle opcodes that reference external globals
_PICKLE_GLOBAL_OPCODE = b"c"       # protocol 0-2 GLOBAL: module\nname\n
_PICKLE_STACK_GLOBAL = b"\x93"     # protocol 4+ STACK_GLOBAL

_DANGEROUS_PATTERNS = [
    b"os\nsystem", b"os\npopen", b"os\ngetenv",
    b"subprocess\nPopen", b"subprocess\ncall", b"subprocess\ncheck_output",
    b"builtins\neval", b"builtins\nexec", b"builtins\n__import__",
    b"__builtin__\neval", b"__builtin__\nexec",
    b"commands\ngetoutput", b"posix\nsystem",
    b"nt\nsystem", b"importlib\nimport_module",
]

_EU_HIGH_RISK_PIPELINE = {
    "image-segmentation", "object-detection", "image-classification",
    "video-classification", "zero-shot-image-classification",
    "face-detection", "face-recognition",
}
_EU_HIGH_RISK_TAGS = {
    "biometric", "surveillance", "facial-recognition", "emotion-recognition",
    "law-enforcement", "credit-scoring", "recruitment", "education",
    "critical-infrastructure",
}
_EU_LIMITED_RISK_PIPELINE = {
    "text-generation", "conversational", "text2text-generation",
    "question-answering", "summarization",
}
_EU_LIMITED_RISK_TAGS = {
    "chatbot", "deepfake", "synthetic-media", "sentiment-analysis",
    "emotion-detection",
}

# Infer pipeline tag from HuggingFace architecture class name suffixes
_ARCH_TO_PIPELINE: dict[str, str] = {
    "ForCausalLM": "text-generation",
    "LMHeadModel": "text-generation",
    "ForSeq2SeqLM": "text2text-generation",
    "ForConditionalGeneration": "text2text-generation",
    "ForSequenceClassification": "text-classification",
    "ForTokenClassification": "token-classification",
    "ForQuestionAnswering": "question-answering",
    "ForMaskedLM": "fill-mask",
    "ForImageClassification": "image-classification",
    "ForObjectDetection": "object-detection",
    "ForImageSegmentation": "image-segmentation",
    "ForAudioClassification": "audio-classification",
    "ForSpeechSeq2Seq": "automatic-speech-recognition",
    "ForCTC": "automatic-speech-recognition",
}


@dataclass
class ModelInspection:
    architecture: Optional[str] = None
    model_type: Optional[str] = None
    param_count_estimate: Optional[int] = None
    context_length: Optional[int] = None
    hidden_size: Optional[int] = None
    num_layers: Optional[int] = None
    num_attention_heads: Optional[int] = None
    num_kv_heads: Optional[int] = None
    vocab_size: Optional[int] = None
    torch_dtype: Optional[str] = None
    library_name: Optional[str] = None
    tokenizer_type: Optional[str] = None
    pickle_safe: Optional[str] = None      # "safe" | "unsafe" | "skipped"
    pickle_threats: list[str] = field(default_factory=list)
    safetensors_valid: Optional[bool] = None
    eu_ai_act_risk: Optional[str] = None   # "high" | "limited" | "minimal" | "unknown"
    eu_ai_act_reasons: list[str] = field(default_factory=list)


def inspect_model_dir(directory: Path) -> Optional[ModelInspection]:
    """Inspect a model directory. Returns None if no recognisable model artifacts found."""
    config_path = directory / "config.json"
    if not config_path.exists():
        return None

    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    insp = ModelInspection()
    _extract_config_metadata(config, insp)
    _extract_tokenizer_type(directory, insp)

    for f in directory.iterdir():
        if not f.is_file():
            continue
        if f.suffix in (".pkl", ".pt", ".pth", ".ckpt"):
            safe, threats = _scan_pickle(f)
            insp.pickle_safe = safe
            insp.pickle_threats.extend(threats)
        elif f.suffix == ".safetensors":
            valid = _validate_safetensors(f)
            insp.safetensors_valid = valid if insp.safetensors_valid is None else (insp.safetensors_valid and valid)

    # No pickle files found but safetensors present — explicit security positive
    if insp.pickle_safe is None and insp.safetensors_valid is not None:
        insp.pickle_safe = "safetensors"

    return insp


def infer_pipeline_from_architecture(architecture: Optional[str]) -> Optional[str]:
    """Map HuggingFace architecture class name to a pipeline tag."""
    if not architecture:
        return None
    for suffix, pipeline in _ARCH_TO_PIPELINE.items():
        if architecture.endswith(suffix):
            return pipeline
    return None


def classify_eu_ai_act(
    pipeline_tag: Optional[str],
    tags: list[str],
    architecture: Optional[str] = None,
) -> tuple[str, list[str]]:
    """Return (risk_level, reasons).

    Falls back to inferring the pipeline from the architecture class name
    when no hub pipeline_tag is available.
    """
    reasons: list[str] = []
    tag_set = {t.lower() for t in tags}

    pipe = (pipeline_tag or "").lower()
    if not pipe and architecture:
        inferred = infer_pipeline_from_architecture(architecture)
        if inferred:
            pipe = inferred
            reasons_prefix = f"inferred from architecture '{architecture}'"
        else:
            reasons_prefix = None
    else:
        reasons_prefix = None

    if pipe in _EU_HIGH_RISK_PIPELINE:
        label = f"inferred pipeline '{pipe}'" if reasons_prefix else f"pipeline '{pipe}'"
        reasons.append(f"{label} listed in EU AI Act Annex III")
    matched_high = _EU_HIGH_RISK_TAGS & tag_set
    if matched_high:
        reasons.append(f"high-risk tags: {', '.join(sorted(matched_high))}")

    if reasons:
        return "high", reasons

    if pipe in _EU_LIMITED_RISK_PIPELINE:
        label = f"inferred pipeline '{pipe}'" if reasons_prefix else f"pipeline '{pipe}'"
        reasons.append(f"{label} requires transparency disclosure (Art. 52)")
    matched_limited = _EU_LIMITED_RISK_TAGS & tag_set
    if matched_limited:
        reasons.append(f"limited-risk tags: {', '.join(sorted(matched_limited))}")

    if reasons:
        return "limited", reasons

    if pipe or tags:
        return "minimal", ["no high/limited-risk indicators detected"]
    return "unknown", ["insufficient metadata to classify"]


# ── private helpers ────────────────────────────────────────────────────────────

def _extract_config_metadata(config: dict, insp: ModelInspection) -> None:
    archs = config.get("architectures") or []
    insp.architecture = archs[0] if archs else None
    insp.model_type = config.get("model_type")
    insp.hidden_size = config.get("hidden_size") or config.get("d_model") or config.get("n_embd")
    insp.num_layers = (
        config.get("num_hidden_layers")
        or config.get("n_layer")
        or config.get("num_layers")
        or config.get("num_decoder_layers")
    )
    insp.num_attention_heads = config.get("num_attention_heads") or config.get("n_head")
    insp.num_kv_heads = config.get("num_key_value_heads") or insp.num_attention_heads
    insp.vocab_size = config.get("vocab_size")
    insp.torch_dtype = config.get("torch_dtype")
    insp.library_name = config.get("library_name")
    insp.context_length = (
        config.get("max_position_embeddings")
        or config.get("max_sequence_length")
        or config.get("n_positions")
        or config.get("seq_length")
    )
    insp.param_count_estimate = _estimate_params(config)


def _estimate_params(config: dict) -> Optional[int]:
    hidden = config.get("hidden_size") or config.get("d_model") or config.get("n_embd")
    layers = (
        config.get("num_hidden_layers")
        or config.get("n_layer")
        or config.get("num_layers")
    )
    if not (hidden and layers):
        return None

    intermediate = (
        config.get("intermediate_size")
        or config.get("ffn_dim")
        or hidden * 4
    )
    vocab = config.get("vocab_size") or 0
    num_heads = config.get("num_attention_heads") or config.get("n_head") or 1
    num_kv_heads = config.get("num_key_value_heads") or num_heads
    tie_embeddings = config.get("tie_word_embeddings", False)
    hidden_act = config.get("hidden_act", "")

    kv_ratio = num_kv_heads / num_heads
    # Q + O projections (full hidden) + K + V (scaled by GQA ratio)
    attn_params = hidden * hidden * (2 + 2 * kv_ratio)

    # SwiGLU / SiLU use 3 weight matrices (up, gate, down); others use 2
    ffn_matrices = 3 if hidden_act in ("silu", "swiglu", "gelu_new") else 2
    ffn_params = ffn_matrices * hidden * intermediate

    # Layer norms (weight + bias, 2 per layer)
    ln_params = hidden * 4

    total = layers * (attn_params + ffn_params + ln_params)

    if vocab:
        embed = vocab * hidden
        total += embed if tie_embeddings else embed * 2

    return int(total)


def _extract_tokenizer_type(directory: Path, insp: ModelInspection) -> None:
    tc = directory / "tokenizer_config.json"
    if tc.exists():
        try:
            data = json.loads(tc.read_text(encoding="utf-8"))
            insp.tokenizer_type = data.get("tokenizer_class") or data.get("model_type")
        except Exception:
            pass


def _scan_pickle(path: Path) -> tuple[str, list[str]]:
    """Scan a file for dangerous pickle globals without executing it."""
    try:
        if path.suffix in (".pt", ".pth", ".ckpt"):
            raw = _extract_pytorch_pickle(path)
        else:
            raw = path.read_bytes()

        if raw is None:
            return "skipped", []

        threats: list[str] = []
        for pattern in _DANGEROUS_PATTERNS:
            if pattern in raw:
                threats.append(pattern.decode("utf-8", errors="replace").replace("\n", "."))

        return ("unsafe" if threats else "safe"), threats
    except Exception:
        return "skipped", []


def _extract_pytorch_pickle(path: Path) -> Optional[bytes]:
    """PyTorch saves are ZIP archives containing archive/data.pkl."""
    try:
        with zipfile.ZipFile(path, "r") as zf:
            pkl_names = [n for n in zf.namelist() if n.endswith("data.pkl")]
            if pkl_names:
                return zf.read(pkl_names[0])
    except (zipfile.BadZipFile, Exception):
        pass
    # Fallback: might be a raw pickle
    try:
        return path.read_bytes()
    except Exception:
        return None


def _validate_safetensors(path: Path) -> bool:
    """Validate safetensors header: first 8 bytes are header length (uint64 LE)."""
    try:
        with path.open("rb") as f:
            size_bytes = f.read(8)
            if len(size_bytes) < 8:
                return False
            header_size = struct.unpack("<Q", size_bytes)[0]
            if header_size > 100 * 1024 * 1024:  # sanity: header > 100 MB is invalid
                return False
            header_bytes = f.read(header_size)
            if len(header_bytes) < header_size:
                return False
            json.loads(header_bytes)  # must be valid JSON
        return True
    except Exception:
        return False
