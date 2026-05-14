from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

DATASET_DIRS = {
    "data", "dataset", "datasets", "raw_data", "processed_data",
    "train", "test", "val", "validation", "inputs", "outputs",
    "corpus", "samples", "annotations", "labels", "splits",
    "benchmark", "eval", "finetune", "pretrain", "training_data",
}

DATA_EXTENSIONS = {
    ".csv", ".json", ".jsonl", ".parquet", ".h5", ".hdf5",
    ".tfrecord", ".pkl", ".pickle", ".npy", ".npz", ".arrow",
    ".tsv", ".txt", ".xml", ".avro", ".feather", ".lance",
}

CONFIG_EXTENSIONS = {".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".env"}

DATASET_CONFIG_KEYS = re.compile(
    r"(?i)(dataset[_\-]?(?:name|path|dir|id|repo)?|"
    r"train[_\-](?:file|data|path|dir)|"
    r"(?:eval|test|val)[_\-](?:file|data|path|dir)|"
    r"data[_\-](?:path|dir|root|file)|"
    r"input[_\-](?:file|path|dir)|"
    r"corpus[_\-]?(?:path|dir)?)"
    r"\s*[=:]\s*(.+)"
)

KNOWN_SOURCES: dict[str, str] = {
    "common_crawl":      "https://commoncrawl.org",
    "huggingface":       "https://huggingface.co/datasets",
    "imagenet":          "https://image-net.org",
    "coco":              "https://cocodataset.org",
    "openimages":        "https://storage.googleapis.com/openimages",
    "wikipedia":         "https://dumps.wikimedia.org",
    "reddit":            "https://pushshift.io",
    "pile":              "https://pile.eleuther.ai",
    "laion":             "https://laion.ai",
    "ms_marco":          "https://microsoft.com/en-us/research/project/ms-marco",
    "squad":             "https://rajpurkar.github.io/SQuAD-explorer",
    "glue":              "https://gluebenchmark.com",
    "superglue":         "https://super.gluebenchmark.com",
    "mmlu":              "https://huggingface.co/datasets/cais/mmlu",
    "alpaca":            "https://huggingface.co/datasets/tatsu-lab/alpaca",
    "dolly":             "https://huggingface.co/datasets/databricks/databricks-dolly-15k",
    "openwebtext":       "https://huggingface.co/datasets/Skylion007/openwebtext",
    "c4":                "https://huggingface.co/datasets/allenai/c4",
    "bookcorpus":        "https://huggingface.co/datasets/bookcorpus",
    "wikitext":          "https://huggingface.co/datasets/wikitext",
}

# Metadata for well-known datasets: source_type, sensitivity, privacy flags, gdpr_risk
_KNOWN_DATASET_META: dict[str, dict] = {
    "common_crawl":        {"source_type": "web_scrape",  "sensitivity": "PUBLIC",  "gdpr_relevant": True,  "lgpd_relevant": True,  "gdpr_risk": "HIGH"},
    "c4":                  {"source_type": "web_scrape",  "sensitivity": "PUBLIC",  "gdpr_relevant": True,  "lgpd_relevant": True,  "gdpr_risk": "HIGH"},
    "openwebtext":         {"source_type": "web_scrape",  "sensitivity": "PUBLIC",  "gdpr_relevant": True,  "lgpd_relevant": False, "gdpr_risk": "HIGH"},
    "the_pile":            {"source_type": "web_scrape",  "sensitivity": "PUBLIC",  "gdpr_relevant": True,  "lgpd_relevant": False, "gdpr_risk": "HIGH"},
    "pile":                {"source_type": "web_scrape",  "sensitivity": "PUBLIC",  "gdpr_relevant": True,  "lgpd_relevant": False, "gdpr_risk": "HIGH"},
    "redpajama":           {"source_type": "web_scrape",  "sensitivity": "PUBLIC",  "gdpr_relevant": True,  "lgpd_relevant": False, "gdpr_risk": "HIGH"},
    "dolmino":             {"source_type": "web_scrape",  "sensitivity": "PUBLIC",  "gdpr_relevant": True,  "lgpd_relevant": False, "gdpr_risk": "HIGH"},
    "laion":               {"source_type": "web_scrape",  "sensitivity": "PUBLIC",  "gdpr_relevant": True,  "lgpd_relevant": False, "gdpr_risk": "HIGH"},
    "laion_400m":          {"source_type": "web_scrape",  "sensitivity": "PUBLIC",  "gdpr_relevant": True,  "lgpd_relevant": False, "gdpr_risk": "HIGH"},
    "laion_5b":            {"source_type": "web_scrape",  "sensitivity": "PUBLIC",  "gdpr_relevant": True,  "lgpd_relevant": False, "gdpr_risk": "HIGH"},
    "wikipedia":           {"source_type": "licensed",    "sensitivity": "PUBLIC",  "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
    "wikitext":            {"source_type": "licensed",    "sensitivity": "PUBLIC",  "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
    "bookcorpus":          {"source_type": "licensed",    "sensitivity": "PUBLIC",  "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
    "books3":              {"source_type": "licensed",    "sensitivity": "PUBLIC",  "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
    "gutenberg":           {"source_type": "licensed",    "sensitivity": "PUBLIC",  "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
    "stack_exchange":      {"source_type": "licensed",    "sensitivity": "PUBLIC",  "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
    "stackoverflow":       {"source_type": "licensed",    "sensitivity": "PUBLIC",  "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
    "github":              {"source_type": "licensed",    "sensitivity": "PUBLIC",  "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
    "the_stack":           {"source_type": "licensed",    "sensitivity": "PUBLIC",  "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
    "starcoder":           {"source_type": "licensed",    "sensitivity": "PUBLIC",  "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
    "imagenet":            {"source_type": "licensed",    "sensitivity": "PUBLIC",  "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
    "coco":                {"source_type": "licensed",    "sensitivity": "PUBLIC",  "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
    "openimages":          {"source_type": "licensed",    "sensitivity": "PUBLIC",  "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
    "squad":               {"source_type": "licensed",    "sensitivity": "PUBLIC",  "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
    "glue":                {"source_type": "licensed",    "sensitivity": "PUBLIC",  "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
    "superglue":           {"source_type": "licensed",    "sensitivity": "PUBLIC",  "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
    "mmlu":                {"source_type": "licensed",    "sensitivity": "PUBLIC",  "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
    "alpaca":              {"source_type": "synthetic",   "sensitivity": "PUBLIC",  "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
    "dolly":               {"source_type": "synthetic",   "sensitivity": "PUBLIC",  "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
    "flan":                {"source_type": "synthetic",   "sensitivity": "PUBLIC",  "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
    "open_assistant":      {"source_type": "synthetic",   "sensitivity": "PUBLIC",  "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
    "ms_marco":            {"source_type": "web_scrape",  "sensitivity": "PUBLIC",  "gdpr_relevant": True,  "lgpd_relevant": False, "gdpr_risk": "MEDIUM"},
    "reddit":              {"source_type": "web_scrape",  "sensitivity": "PUBLIC",  "gdpr_relevant": True,  "lgpd_relevant": False, "gdpr_risk": "HIGH"},
    "pushshift":           {"source_type": "web_scrape",  "sensitivity": "PUBLIC",  "gdpr_relevant": True,  "lgpd_relevant": False, "gdpr_risk": "HIGH"},
    "refinedweb":          {"source_type": "web_scrape",  "sensitivity": "PUBLIC",  "gdpr_relevant": True,  "lgpd_relevant": True,  "gdpr_risk": "HIGH"},
    "webtext":             {"source_type": "web_scrape",  "sensitivity": "PUBLIC",  "gdpr_relevant": True,  "lgpd_relevant": False, "gdpr_risk": "HIGH"},
    "slimpajama":          {"source_type": "web_scrape",  "sensitivity": "PUBLIC",  "gdpr_relevant": True,  "lgpd_relevant": False, "gdpr_risk": "HIGH"},
    "roots":               {"source_type": "licensed",    "sensitivity": "PUBLIC",  "gdpr_relevant": True,  "lgpd_relevant": False, "gdpr_risk": "MEDIUM"},
}

# Known model family → documented training datasets
_KNOWN_LINEAGE: dict[str, list[dict]] = {
    "llama": [
        {"name": "CommonCrawl",    "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": True,  "gdpr_risk": "HIGH", "notes": "~67% of LLaMA pre-training mix"},
        {"name": "C4",             "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": False, "notes": "~15% of LLaMA pre-training mix"},
        {"name": "Wikipedia",      "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False, "notes": "20 languages"},
        {"name": "Books3",         "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False},
        {"name": "ArXiv",          "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False},
        {"name": "Stack Exchange", "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False},
        {"name": "GitHub",         "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False},
    ],
    "mistral": [
        {"name": "CommonCrawl",    "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": True,  "gdpr_risk": "HIGH"},
        {"name": "Wikipedia",      "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False},
        {"name": "The Stack",      "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False, "notes": "Undisclosed mix — sources inferred from public statements"},
    ],
    "bert": [
        {"name": "BooksCorpus",    "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False, "notes": "800M words"},
        {"name": "Wikipedia",      "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False, "notes": "English Wikipedia, 2.5B words"},
    ],
    "roberta": [
        {"name": "BooksCorpus",    "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False},
        {"name": "Wikipedia",      "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False},
        {"name": "CC-News",        "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": False},
        {"name": "OpenWebText",    "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": False},
        {"name": "Stories",        "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False},
    ],
    "gpt2": [
        {"name": "WebText",        "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": False, "notes": "Reddit outbound links with 3+ karma, ~40GB"},
    ],
    "gpt-j": [
        {"name": "The Pile",       "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": False, "notes": "825GB diverse text corpus"},
    ],
    "gpt-neox": [
        {"name": "The Pile",       "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": False},
    ],
    "t5": [
        {"name": "C4",             "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": False, "notes": "Colossal Cleaned Crawled Corpus"},
    ],
    "falcon": [
        {"name": "RefinedWeb",     "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": True,  "notes": "5T tokens from CommonCrawl, deduplicated"},
        {"name": "CommonCrawl",    "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": True,  "gdpr_risk": "HIGH"},
    ],
    "phi": [
        {"name": "The Stack",      "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False},
        {"name": "StackOverflow",  "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False},
        {"name": "Wikipedia",      "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False},
        {"name": "Synthetic (GPT-3.5)", "source_type": "synthetic", "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False, "notes": "Phi-1: textbook quality synthetic data"},
    ],
    "gemma": [
        {"name": "Web Documents",  "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": False, "notes": "6T tokens, mix undisclosed by Google"},
        {"name": "Mathematics",    "source_type": "synthetic",  "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False},
        {"name": "Code",           "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False},
    ],
    "qwen": [
        {"name": "CommonCrawl",    "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": True,  "gdpr_risk": "HIGH"},
        {"name": "Wikipedia",      "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False},
        {"name": "GitHub",         "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False},
        {"name": "Books",          "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False, "notes": "Qwen: 3T tokens, Chinese+English mix"},
    ],
    "bloom": [
        {"name": "ROOTS",          "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": False, "notes": "1.6TB in 46 languages, 59 datasets via BigScience"},
    ],
    "opt": [
        {"name": "The Pile",       "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": False},
        {"name": "PushShift Reddit", "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True, "lgpd_relevant": False},
        {"name": "CommonCrawl",    "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": True,  "gdpr_risk": "HIGH"},
    ],
    "mpt": [
        {"name": "RedPajama",      "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": False, "notes": "1T token subset"},
        {"name": "C4",             "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": False},
        {"name": "The Stack",      "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False},
    ],
    "deepseek": [
        {"name": "CommonCrawl",    "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": True,  "gdpr_risk": "HIGH"},
        {"name": "GitHub",         "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False},
        {"name": "Wikipedia",      "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False},
        {"name": "ArXiv",          "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False, "notes": "DeepSeek: 2T tokens, Chinese+English+Code"},
    ],
    "ernie": [
        {"name": "Baidu Corpus",   "source_type": "internal",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False, "notes": "Baidu internal web corpus + Wikipedia"},
        {"name": "Wikipedia",      "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False},
        {"name": "CommonCrawl",    "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": True,  "gdpr_risk": "HIGH"},
    ],
    "chatglm": [
        {"name": "GLM Corpus",     "source_type": "internal",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False, "notes": "THUDM internal corpus; Chinese+English"},
        {"name": "Wikipedia",      "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False},
    ],
    "internlm": [
        {"name": "SlimPajama",     "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": False},
        {"name": "The Stack",      "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False},
        {"name": "Wikipedia",      "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False, "notes": "InternLM: ~1.6T tokens"},
    ],
    "yi": [
        {"name": "CommonCrawl",    "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": True,  "gdpr_risk": "HIGH"},
        {"name": "Wikipedia",      "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False, "notes": "01.AI Yi: 3T tokens, proprietary mix"},
    ],
    "baichuan": [
        {"name": "CommonCrawl",    "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": True,  "gdpr_risk": "HIGH"},
        {"name": "Wikipedia",      "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False, "notes": "Baichuan: 1.2T tokens, Chinese+English"},
    ],
    "starcoder": [
        {"name": "The Stack",      "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False, "notes": "6.4TB source code in 358 languages"},
    ],
    "codegen": [
        {"name": "The Pile",       "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": False},
        {"name": "BigQuery",       "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False, "notes": "Salesforce CodeGen: multi-turn program synthesis"},
    ],
    "clip": [
        {"name": "LAION-400M",     "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": False, "notes": "Image-text pairs scraped from the web"},
        {"name": "LAION-2B",       "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": False},
    ],
    "stable-diffusion": [
        {"name": "LAION-5B",       "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": False, "notes": "5.85B image-text pairs"},
        {"name": "LAION-Aesthetics", "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True, "lgpd_relevant": False},
    ],
    "whisper": [
        {"name": "Web Crawl Audio","source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": False, "notes": "680k hours of multilingual audio from the web"},
    ],
    "granite": [
        {"name": "RedPajama",      "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": False, "gdpr_risk": "HIGH",   "notes": "IBM Granite: primary web-crawl pretraining corpus"},
        {"name": "CommonCrawl",    "source_type": "web_scrape", "sensitivity": "PUBLIC", "gdpr_relevant": True,  "lgpd_relevant": True,  "gdpr_risk": "HIGH"},
        {"name": "Wikipedia",      "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
        {"name": "GitHub",         "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW",    "notes": "Code data for Granite code models"},
        {"name": "ArXiv",          "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
        {"name": "Stack Exchange", "source_type": "licensed",   "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW"},
        {"name": "Flan Collection","source_type": "synthetic",  "sensitivity": "PUBLIC", "gdpr_relevant": False, "lgpd_relevant": False, "gdpr_risk": "LOW",    "notes": "Instruction-tuning data for Granite instruct variants"},
    ],
}

_DEFAULT_HF_DATASETS_CACHE = Path.home() / ".cache" / "huggingface" / "datasets"


@dataclass
class Dataset:
    name: str
    source: str
    version: Optional[str] = None
    license: Optional[str] = None
    hash: Optional[str] = None
    gdpr_relevant: bool = False
    lgpd_relevant: bool = False
    confidential: bool = False
    detection_method: str = "auto"
    path: Optional[str] = None
    num_rows: Optional[int] = None
    size_bytes: Optional[int] = None
    # Provenance fields
    confidence: str = "UNKNOWN"            # CONFIRMED | INFERRED | UNKNOWN
    source_type: str = "unknown"           # web_scrape | licensed | synthetic | internal | unknown
    sensitivity: str = "PUBLIC"            # PUBLIC | CONFIDENTIAL | RESTRICTED
    gdpr_risk: Optional[str] = None        # HIGH | MEDIUM | LOW — overrides keyword detection
    detected_in: list[str] = field(default_factory=list)
    notes: str = ""
    review_required: bool = False          # set True for internal sources by default


def scan_datasets(
    project_path: str,
    config_datasets: list[dict] | None = None,
    code_refs: list | None = None,
) -> list[Dataset]:
    datasets: list[Dataset] = []
    seen: set[str] = set()

    def _add(ds: Dataset) -> None:
        key = ds.name.lower()
        if key not in seen:
            seen.add(key)
            datasets.append(ds)

    for d in _scan_directories(project_path):
        _add(d)
    for d in _scan_configs(project_path):
        _add(d)
    for d in _scan_hf_dataset_cache():
        _add(d)
    for d in _scan_dataset_cards(project_path):
        _add(d)

    for ref in (code_refs or []):
        source = ref.source if ref.source not in ("local", "pytorch", "sklearn", "keras", "tfds") else {
            "torchvision": "https://pytorch.org/vision",
            "pytorch": "local",
            "sklearn": "https://scikit-learn.org/stable/datasets",
            "keras": "https://keras.io/api/datasets",
            "tfds": "https://www.tensorflow.org/datasets",
            "local": "local",
            "huggingface": "https://huggingface.co/datasets",
        }.get(ref.source, ref.source)
        meta = _lookup_dataset_meta(ref.name)
        st = meta.get("source_type", "unknown")
        _add(Dataset(
            name=ref.name,
            source=source,
            gdpr_relevant=meta.get("gdpr_relevant", _is_privacy_relevant(ref.name, "gdpr")),
            lgpd_relevant=meta.get("lgpd_relevant", _is_privacy_relevant(ref.name, "lgpd")),
            detection_method=f"code:{ref.file}:{ref.line}",
            confidence="CONFIRMED",
            source_type=st,
            sensitivity=meta.get("sensitivity", "PUBLIC"),
            detected_in=["code"],
            **_dataset_kwargs(meta, st),
        ))

    for entry in (config_datasets or []):
        name = entry.get("name", "unknown")
        meta = _lookup_dataset_meta(name)
        st = entry.get("source_type", meta.get("source_type", "unknown"))
        _add(Dataset(
            name=name,
            source=entry.get("source", "unknown"),
            version=entry.get("version"),
            license=entry.get("license"),
            hash=entry.get("hash"),
            gdpr_relevant=entry.get("gdpr_relevant", meta.get("gdpr_relevant", False)),
            lgpd_relevant=entry.get("lgpd_relevant", meta.get("lgpd_relevant", False)),
            confidential=entry.get("confidential", False),
            detection_method="config",
            confidence="CONFIRMED",
            source_type=st,
            sensitivity=entry.get("sensitivity", meta.get("sensitivity", "PUBLIC")),
            detected_in=["config"],
            **_dataset_kwargs(meta, st),
        ))

    return datasets


def enrich_datasets_from_model_cards(
    datasets: list[Dataset],
    models: list,
    hub_cards: dict,
) -> list[Dataset]:
    """Add Dataset entries from HuggingFace model card `datasets:` fields.

    Returns new Dataset objects (caller should merge/dedup with existing list).
    """
    seen_existing = {ds.name.lower() for ds in datasets}
    new_datasets: list[Dataset] = []
    seen_new: set[str] = set()

    for model in models:
        card = hub_cards.get(getattr(model, "source_id", None))
        if not card or not card.training_datasets:
            continue
        for ds_name in card.training_datasets:
            key = ds_name.lower()
            if key in seen_existing or key in seen_new:
                continue
            seen_new.add(key)
            meta = _lookup_dataset_meta(ds_name)
            st = meta.get("source_type", "unknown")
            source = _guess_source(ds_name)
            new_datasets.append(Dataset(
                name=ds_name,
                source=source,
                gdpr_relevant=meta.get("gdpr_relevant", _is_privacy_relevant(ds_name, "gdpr")),
                lgpd_relevant=meta.get("lgpd_relevant", _is_privacy_relevant(ds_name, "lgpd")),
                detection_method=f"model-card:{card.model_id}",
                confidence="CONFIRMED",
                source_type=st,
                sensitivity=meta.get("sensitivity", "PUBLIC"),
                detected_in=["model_card"],
                notes=f"Listed in {card.model_id} model card",
                **_dataset_kwargs(meta, st),
            ))

    return new_datasets


def infer_from_model_lineage(
    models: list,
    hub_cards: dict,
    existing_datasets: list[Dataset],
) -> list[Dataset]:
    """Infer datasets from known model family training data.

    Only adds entries with confidence=INFERRED when not already present.
    """
    seen_names = {ds.name.lower() for ds in existing_datasets}
    inferred: list[Dataset] = []
    seen_inferred: set[str] = set()

    for model in models:
        name_lower = (getattr(model, "name", "") or "").lower()
        source_id_lower = (getattr(model, "source_id", "") or "").lower()

        # Also check architecture from inspection
        arch = ""
        insp = getattr(model, "inspection", None)
        if insp:
            arch = (getattr(insp, "architecture", "") or "").lower()

        matched_family: str | None = None
        for family_key in _KNOWN_LINEAGE:
            if (
                _matches_family(name_lower, family_key)
                or _matches_family(source_id_lower, family_key)
                or (arch and _matches_family(arch, family_key))
            ):
                matched_family = family_key
                break

        if not matched_family:
            # Try hub card tags/pipeline for additional signals
            card = hub_cards.get(getattr(model, "source_id", None))
            if card:
                tag_text = " ".join(card.tags or []).lower()
                pipeline_text = (card.pipeline_tag or "").lower()
                for family_key in _KNOWN_LINEAGE:
                    if _matches_family(tag_text, family_key) or _matches_family(pipeline_text, family_key):
                        matched_family = family_key
                        break

        if not matched_family:
            continue

        for ds_spec in _KNOWN_LINEAGE[matched_family]:
            key = ds_spec["name"].lower()
            if key in seen_names or key in seen_inferred:
                continue
            seen_inferred.add(key)
            meta = _lookup_dataset_meta(ds_spec["name"])
            st = ds_spec.get("source_type", meta.get("source_type", "unknown"))
            inferred.append(Dataset(
                name=ds_spec["name"],
                source=_guess_source(ds_spec["name"]),
                gdpr_relevant=ds_spec.get("gdpr_relevant", meta.get("gdpr_relevant", False)),
                lgpd_relevant=ds_spec.get("lgpd_relevant", meta.get("lgpd_relevant", False)),
                detection_method=f"lineage:{matched_family}",
                confidence="INFERRED",
                source_type=st,
                sensitivity=ds_spec.get("sensitivity", meta.get("sensitivity", "PUBLIC")),
                detected_in=["lineage_lookup"],
                notes=ds_spec.get("notes", f"Detected via {matched_family} model lineage"),
                gdpr_risk=ds_spec.get("gdpr_risk", meta.get("gdpr_risk")),
                review_required=(st == "internal"),
            ))

    return inferred


def get_provenance_gaps(models: list, datasets: list[Dataset]) -> list[str]:
    """Return names of models that have no associated dataset entries."""
    model_names_with_data: set[str] = set()

    # A model has data if any dataset was detected via its model card or lineage
    # or if it appears in trainingDatasets
    dataset_model_refs: set[str] = set()
    for ds in datasets:
        dm = ds.detection_method or ""
        if dm.startswith("model-card:") or dm.startswith("lineage:"):
            # These are attributed to the whole scan, not a specific model
            pass

    # Simpler heuristic: if we have any CONFIRMED or INFERRED datasets, the scan
    # found something. Gap = model with source=huggingface but zero card datasets AND
    # no lineage match.
    confirmed_or_inferred = {
        ds.name.lower() for ds in datasets
        if ds.confidence in ("CONFIRMED", "INFERRED")
    }

    gaps: list[str] = []
    for model in models:
        source_id = (getattr(model, "source_id", "") or "").lower()
        name = (getattr(model, "name", "") or "").lower()
        if not source_id:
            continue
        # Check if any lineage/card dataset came from this model
        has_data = any(
            ds.detection_method and (
                source_id in ds.detection_method or
                any(fam in name for fam in _KNOWN_LINEAGE)
            )
            for ds in datasets
            if ds.confidence in ("CONFIRMED", "INFERRED")
        )
        if not has_data:
            gaps.append(getattr(model, "name", source_id) or source_id)

    return gaps


# ── scanners ─────────────────────────────────────────────────────────────────

def _scan_directories(project_path: str) -> list[Dataset]:
    datasets = []
    root = Path(project_path)
    for item in root.rglob("*"):
        if not item.is_dir() or item.name.lower() not in DATASET_DIRS:
            continue
        data_files = [f for f in item.iterdir() if f.is_file() and f.suffix.lower() in DATA_EXTENSIONS]
        if not data_files:
            continue
        size = sum(f.stat().st_size for f in data_files)
        datasets.append(Dataset(
            name=item.name,
            source=_guess_source(item.name),
            gdpr_relevant=_is_privacy_relevant(item.name, "gdpr"),
            lgpd_relevant=_is_privacy_relevant(item.name, "lgpd"),
            detection_method="directory",
            path=str(item.relative_to(root)),
            size_bytes=size,
            confidence="CONFIRMED",
            source_type="internal",
            detected_in=["directory"],
            review_required=True,
        ))
    return datasets


def _scan_configs(project_path: str) -> list[Dataset]:
    datasets = []
    root = Path(project_path)
    for item in root.rglob("*"):
        if not item.is_file() or item.suffix.lower() not in CONFIG_EXTENSIONS:
            continue
        try:
            text = item.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            continue
        for match in DATASET_CONFIG_KEYS.finditer(text):
            value = match.group(2).strip().strip("\"'").split()[0]
            if not value or value.startswith("#"):
                continue
            name = Path(value).name or value
            meta = _lookup_dataset_meta(name)
            st = meta.get("source_type", "unknown")
            datasets.append(Dataset(
                name=name,
                source=_guess_source(value),
                gdpr_relevant=meta.get("gdpr_relevant", _is_privacy_relevant(value, "gdpr")),
                lgpd_relevant=meta.get("lgpd_relevant", _is_privacy_relevant(value, "lgpd")),
                detection_method=f"config:{item.name}",
                path=str(item.relative_to(root)),
                confidence="INFERRED",
                source_type=st,
                sensitivity=meta.get("sensitivity", "PUBLIC"),
                detected_in=["config"],
                **_dataset_kwargs(meta, st),
            ))
    return datasets


def _scan_hf_dataset_cache() -> list[Dataset]:
    """Scan ~/.cache/huggingface/datasets/ for downloaded datasets."""
    datasets = []
    cache_root = Path(os.environ.get("HF_DATASETS_CACHE", "") or _DEFAULT_HF_DATASETS_CACHE)
    if not cache_root.exists():
        return []
    for entry in cache_root.iterdir():
        if not entry.is_dir():
            continue
        raw_name = entry.name
        dataset_id = raw_name.replace("___", "/")
        size = sum(f.stat().st_size for f in entry.rglob("*") if f.is_file())
        info = _read_hf_dataset_info(entry)
        meta = _lookup_dataset_meta(dataset_id)
        st = meta.get("source_type", "unknown")
        datasets.append(Dataset(
            name=dataset_id,
            source="https://huggingface.co/datasets",
            version=info.get("version"),
            license=info.get("license"),
            gdpr_relevant=meta.get("gdpr_relevant", _is_privacy_relevant(dataset_id, "gdpr")),
            lgpd_relevant=meta.get("lgpd_relevant", _is_privacy_relevant(dataset_id, "lgpd")),
            detection_method="hf-dataset-cache",
            path=str(entry),
            num_rows=info.get("num_rows"),
            size_bytes=size if size else None,
            confidence="CONFIRMED",
            source_type=st,
            sensitivity=meta.get("sensitivity", "PUBLIC"),
            detected_in=["hf_cache"],
            **_dataset_kwargs(meta, st),
        ))
    return datasets


def _scan_dataset_cards(project_path: str) -> list[Dataset]:
    """Parse dataset_card.yaml / README.md YAML frontmatter in dataset directories."""
    datasets = []
    root = Path(project_path)
    for card_file in list(root.rglob("dataset_card.yaml")) + list(root.rglob("README.md")):
        try:
            text = card_file.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            continue
        meta = _extract_yaml_frontmatter(text)
        if not meta:
            continue
        # Must have an explicit dataset identifier — model READMEs have license too
        # but lack dataset_name/dataset_type; skip to avoid hash-named false positives
        name = meta.get("dataset_name") or meta.get("name")
        tags = meta.get("tags") or []
        has_dataset_tag = any("dataset" in str(t).lower() for t in tags)
        if not name and not meta.get("dataset_type") and not has_dataset_tag:
            continue
        if not name:
            name = card_file.parent.name
        ds_meta = _lookup_dataset_meta(name)
        st = ds_meta.get("source_type", "unknown")
        datasets.append(Dataset(
            name=name,
            source="https://huggingface.co/datasets",
            version=str(meta.get("dataset_version", "")) or None,
            license=meta.get("license"),
            gdpr_relevant=ds_meta.get("gdpr_relevant", _is_privacy_relevant(name, "gdpr")),
            lgpd_relevant=ds_meta.get("lgpd_relevant", _is_privacy_relevant(name, "lgpd")),
            detection_method=f"dataset-card:{card_file.name}",
            path=str(card_file.relative_to(root)),
            confidence="CONFIRMED",
            source_type=st,
            sensitivity=ds_meta.get("sensitivity", "PUBLIC"),
            detected_in=["dataset_card"],
            **_dataset_kwargs(ds_meta, st),
        ))
    return datasets


# ── helpers ───────────────────────────────────────────────────────────────────

def _dataset_kwargs(meta: dict, source_type: str | None = None) -> dict:
    """Return extra Dataset fields derived from meta + source_type."""
    st = source_type or meta.get("source_type", "unknown")
    return {
        "gdpr_risk": meta.get("gdpr_risk"),
        "review_required": st == "internal",
    }


def _lookup_dataset_meta(name: str) -> dict:
    """Return known metadata for a dataset name, or empty dict."""
    key = _norm_name(name)
    # Exact match first
    if key in _KNOWN_DATASET_META:
        return _KNOWN_DATASET_META[key]
    # Token-level containment: "allenai/c4" → key contains "c4"
    for known_key, meta in _KNOWN_DATASET_META.items():
        # Only match if the known_key appears as a full token in key, not a substring
        if re.search(r'(?:^|[_/])' + re.escape(known_key) + r'(?:[_/]|$)', key):
            return meta
    return {}


def _read_hf_dataset_info(cache_dir: Path) -> dict:
    for info_file in cache_dir.rglob("dataset_info.json"):
        try:
            data = json.loads(info_file.read_text())
            return {
                "version": data.get("version"),
                "license": data.get("license"),
                "num_rows": data.get("splits", {}).get("train", {}).get("num_examples"),
            }
        except Exception:
            pass
    return {}


def _extract_yaml_frontmatter(text: str) -> dict:
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    try:
        import yaml
        return yaml.safe_load(text[3:end]) or {}
    except Exception:
        return {}


_GDPR_KEYWORDS = {
    "user", "customer", "patient", "person", "personal", "private",
    "pii", "gdpr", "eu_data", "europe", "european", "clinical", "medical",
    "health", "biometric", "financial", "credit", "ssn", "email",
    "phone", "address", "location", "ip_address", "passport",
}

_LGPD_KEYWORDS = {
    "cpf", "cnpj", "rg", "cnh", "sus", "titulo_eleitor",
    "lgpd", "brazil", "brasil", "brasileiro", "dadospessoais",
    "dados_pessoais", "saude", "financeiro", "banco", "pis", "pasep",
}

# Datasets known to be privacy-safe — suppress false positives from keyword matching.
# "credit" in "creditcard" would hit the GDPR pattern without this guard.
_SAFE_DATASETS: frozenset[str] = frozenset({
    "wikipedia", "wikitext", "wikidata", "wikicorpus",
    "gutenberg", "project_gutenberg",
    "arxiv",
    "bookcorpus", "books_corpus", "books3",
    "the_stack", "thestack",
    "imagenet",
    "coco",
    "cifar", "cifar10", "cifar_10", "cifar100", "cifar_100",
    "mnist",
    "squad", "squad2", "squad_v2",
    "glue", "superglue",
    "mmlu",
    "mathematics", "math",
    "github",
    "stackoverflow", "stack_overflow", "stack_exchange",
    "openimages", "open_images",
    "alpaca", "dolly", "flan",
})

def _norm_name(name: str) -> str:
    return name.lower().replace("-", "_").replace(" ", "_")


def _name_tokens(name: str) -> set[str]:
    """Split a dataset name on [-_/\\s.] separators and return lowercase tokens.

    "user_data"   → {"user", "data"}      → matches "user"
    "username"    → {"username"}           → does NOT match "user"
    "credit_score"→ {"credit", "score"}   → matches "credit"
    "creditcard"  → {"creditcard"}         → does NOT match "credit"
    """
    return set(re.split(r'[-_/\s.]+', name.lower()))


def _matches_family(text: str, family: str) -> bool:
    """True if family appears as a whole token in text.

    Splits on [-_/\\s.] so "llama-2" and "llama3" both match "llama",
    but "llamaindex" does not.
    """
    family_lower = family.lower()
    tokens = re.split(r'[-_/\s.]+', text.lower())
    return any(
        tok == family_lower or bool(re.fullmatch(re.escape(family_lower) + r'\d+[\w.]*', tok))
        for tok in tokens
    )


def _is_privacy_relevant(name: str, regulation: str) -> bool:
    if _norm_name(name) in _SAFE_DATASETS:
        return False
    tokens = _name_tokens(name)
    if regulation == "gdpr":
        return bool(tokens & _GDPR_KEYWORDS)
    if regulation == "lgpd":
        return bool(tokens & _LGPD_KEYWORDS)
    return False


def _guess_source(name: str) -> str:
    name_lower = name.lower()
    for key, url in KNOWN_SOURCES.items():
        if key in name_lower:
            return url
    if "hugging" in name_lower or "hf_" in name_lower or "/" in name_lower:
        return KNOWN_SOURCES["huggingface"]
    return "unknown"
