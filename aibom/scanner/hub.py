"""
Fetch model metadata from HuggingFace Hub API.
Enriches ModelFile entries with base model lineage, training datasets, and license.
"""
import re
import time
from dataclasses import dataclass, field
from typing import Optional

import requests

HF_API_BASE = "https://huggingface.co/api/models"
_REQUEST_TIMEOUT = 10
_RATE_LIMIT_DELAY = 0.5  # seconds between requests

# Only allow model IDs matching HF's own naming rules: optional org/name or just name
_MODEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]*(/[A-Za-z0-9][A-Za-z0-9._\-]*)?$")


def _validate_model_id(model_id: str) -> bool:
    """Return True only for safe HF model IDs — rejects path traversal and injections."""
    return (
        isinstance(model_id, str)
        and 1 <= len(model_id) <= 200
        and ".." not in model_id
        and bool(_MODEL_ID_RE.match(model_id))
    )


@dataclass
class HFModelCard:
    model_id: str
    license: Optional[str] = None
    base_model: Optional[str] = None
    base_model_relation: Optional[str] = None  # "finetune", "quantization", "merge", etc.
    training_datasets: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    pipeline_tag: Optional[str] = None
    library_name: Optional[str] = None
    downloads: Optional[int] = None
    likes: Optional[int] = None
    private: bool = False
    raw: dict = field(default_factory=dict)


def enrich_models(models: list, quiet: bool = False) -> dict[str, HFModelCard]:
    """
    For each ModelFile with source='huggingface' and a source_id,
    fetch metadata from the HF Hub API.
    Returns a dict mapping source_id -> HFModelCard.
    """
    cards: dict[str, HFModelCard] = {}
    hf_models = [m for m in models if m.source == "huggingface" and m.source_id]

    for i, model in enumerate(hf_models):
        model_id = model.source_id
        if model_id in cards:
            continue
        if i > 0:
            time.sleep(_RATE_LIMIT_DELAY)
        card = _fetch_model_card(model_id)
        if card:
            cards[model_id] = card

    return cards


def _fetch_model_card(model_id: str) -> Optional[HFModelCard]:
    if not _validate_model_id(model_id):
        return None
    try:
        resp = requests.get(
            f"{HF_API_BASE}/{model_id}",
            timeout=_REQUEST_TIMEOUT,
            headers={"User-Agent": "ai-bom/0.1.0"},
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException:
        return None

    card_data = data.get("cardData") or {}
    tags = data.get("tags") or []

    base_model = card_data.get("base_model")
    base_model_relation = None
    if isinstance(base_model, list):
        # newer card format: list of {name, relation}
        if base_model and isinstance(base_model[0], dict):
            base_model_relation = base_model[0].get("relation")
            base_model = base_model[0].get("name")
        else:
            base_model = base_model[0] if base_model else None

    datasets = card_data.get("datasets") or []
    if isinstance(datasets, str):
        datasets = [datasets]

    license_val = card_data.get("license") or data.get("license")

    return HFModelCard(
        model_id=model_id,
        license=license_val,
        base_model=base_model,
        base_model_relation=base_model_relation,
        training_datasets=datasets,
        tags=tags,
        pipeline_tag=data.get("pipeline_tag"),
        library_name=data.get("library_name"),
        downloads=data.get("downloads"),
        likes=data.get("likes"),
        private=data.get("private", False),
        raw=data,
    )


def resolve_lineage(model_id: str, depth: int = 3) -> list[HFModelCard]:
    """
    Walk base_model chain up to `depth` hops.
    Returns list ordered from the queried model to its root ancestor.
    """
    lineage: list[HFModelCard] = []
    seen: set[str] = set()
    current_id = model_id

    for _ in range(depth):
        if current_id in seen:
            break
        seen.add(current_id)
        card = _fetch_model_card(current_id)
        if not card:
            break
        lineage.append(card)
        if not card.base_model or card.base_model == current_id:
            break
        if not _validate_model_id(card.base_model):
            break
        current_id = card.base_model
        time.sleep(_RATE_LIMIT_DELAY)

    return lineage
