"""
Vendor model-identifier resolver.

Parses a model-id string (found in code, config, or IaC) into
{model_provider, hosting_provider, family, snapshot, floating_alias}.

Pure string/regex parsing — no network calls, no vendor SDK or API key
required. Every pattern here is derived from each vendor's own public
naming convention (see docs/vendor-disclosure-scanner-design.md).
"""
import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class ResolvedIdentifier:
    raw: str
    model_provider: Optional[str] = None     # who trains/owns the model, e.g. "Anthropic"
    hosting_provider: Optional[str] = None   # who you legally contract with for this call
    family: Optional[str] = None             # e.g. "claude-3-5-sonnet"
    snapshot: Optional[str] = None           # pinned date/version suffix, if present
    floating_alias: bool = False             # True if the id can silently resolve to a new model
    resolved: bool = True                    # False if the shape isn't recognized at all
    note: str = ""


_KNOWN_MODEL_PROVIDERS = {
    "anthropic": "Anthropic",
    "openai": "OpenAI",
    "google": "Google",
    "mistralai": "Mistral AI",
    "cohere": "Cohere",
}

_DIRECT_PREFIXES = {
    "claude-": "Anthropic",
    "gpt-": "OpenAI",
    "o1-": "OpenAI",
    "o3-": "OpenAI",
    "o4-": "OpenAI",
    "gemini-": "Google",
}

_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}|\d{8}")  # 2024-08-06 or 20241022
_AT_DATE_RE = re.compile(r"@(\d{8})$")        # Vertex "...@20241022"
_NUMERIC_SNAPSHOT_RE = re.compile(r"-(\d{3})$")  # gemini-1.5-pro-002
_BEDROCK_RE = re.compile(r"^([a-z]{2}(?:-gov)?)\.([a-z0-9]+)\.(.+?)(?::(\d+))?$")
_VERTEX_RE = re.compile(r"^publishers/([a-z0-9\-]+)/models/(.+)$")
_ORG_MODEL_RE = re.compile(r"^([A-Za-z0-9_\-]+)/([A-Za-z0-9._\-]+)$")

_FLOATING_NOTE = (
    "No snapshot/date in identifier — this alias can silently resolve to a "
    "different model version without your code changing."
)


def _split_direct(s: str) -> tuple[str, Optional[str], bool]:
    """Split a direct-vendor id into (family, snapshot, floating_alias)."""
    if s.endswith("-latest"):
        return s[: -len("-latest")], None, True
    date_m = _DATE_RE.search(s)
    if date_m:
        date_raw = date_m.group(0)
        family = (s[: date_m.start()] + s[date_m.end():]).rstrip("-")
        return family, date_raw.replace("-", ""), False
    snap_m = _NUMERIC_SNAPSHOT_RE.search(s)
    if snap_m:
        return _NUMERIC_SNAPSHOT_RE.sub("", s), snap_m.group(1), False
    return s, None, True


def resolve_model_id(raw: str) -> ResolvedIdentifier:
    """Resolve a single model-id string. Never raises; unrecognized shapes
    come back with resolved=False rather than an exception."""
    s = raw.strip()
    if not s:
        return ResolvedIdentifier(raw=raw, resolved=False, note="Empty identifier.")

    # Bedrock inference-profile form: "us.anthropic.claude-3-5-sonnet-20241022-v2:0"
    m = _BEDROCK_RE.match(s)
    if m and m.group(2) in _KNOWN_MODEL_PROVIDERS:
        _region, provider_key, rest, _ver = m.groups()
        family, snapshot, floating = _split_direct(rest)
        return ResolvedIdentifier(
            raw=raw,
            model_provider=_KNOWN_MODEL_PROVIDERS[provider_key],
            hosting_provider="AWS (Bedrock)",
            family=family,
            snapshot=snapshot,
            floating_alias=floating,
            note="Region-prefixed Bedrock inference profile — governed by AWS's DPA/terms, "
                 "not the model provider's directly." + (f" {_FLOATING_NOTE}" if floating else ""),
        )

    # Vertex publisher path: "publishers/anthropic/models/claude-3-5-sonnet-v2@20241022"
    m = _VERTEX_RE.match(s)
    if m:
        provider_key, rest = m.groups()
        date_m = _AT_DATE_RE.search(rest)
        family = _AT_DATE_RE.sub("", rest)
        floating = date_m is None
        note = "Vertex-hosted — governed by Google Cloud's terms, not the model provider's directly."
        if floating:
            note += f" {_FLOATING_NOTE}"
        return ResolvedIdentifier(
            raw=raw,
            model_provider=_KNOWN_MODEL_PROVIDERS.get(provider_key, provider_key),
            hosting_provider="Google (Vertex AI)",
            family=family,
            snapshot=date_m.group(1) if date_m else None,
            floating_alias=floating,
            note=note,
        )

    # Google AI SDK legacy prefix: "models/gemini-1.5-pro"
    if s.startswith("models/"):
        s = s[len("models/"):]

    # Direct-vendor forms: claude-*, gpt-*, o1-/o3-/o4-*, gemini-*
    for prefix, provider in _DIRECT_PREFIXES.items():
        if s.startswith(prefix):
            family, snapshot, floating = _split_direct(s)
            return ResolvedIdentifier(
                raw=raw,
                model_provider=provider,
                hosting_provider=provider,
                family=family,
                snapshot=snapshot,
                floating_alias=floating,
                note=_FLOATING_NOTE if floating else "",
            )

    # "provider/model" shape — OpenRouter for a known provider key, otherwise
    # treated as an open-weight HF org/name reference.
    m = _ORG_MODEL_RE.match(s)
    if m:
        org, rest = m.groups()
        if org in _KNOWN_MODEL_PROVIDERS:
            family, snapshot, floating = _split_direct(rest)
            note = "Routed via OpenRouter — governed by OpenRouter's terms in addition to the model provider's."
            if floating:
                note += f" {_FLOATING_NOTE}"
            return ResolvedIdentifier(
                raw=raw,
                model_provider=_KNOWN_MODEL_PROVIDERS[org],
                hosting_provider="OpenRouter",
                family=family,
                snapshot=snapshot,
                floating_alias=floating,
                note=note,
            )
        return ResolvedIdentifier(
            raw=raw,
            model_provider=org,
            hosting_provider="self-hosted / Hugging Face (open-weight)",
            family=rest,
            snapshot=None,
            floating_alias=False,
            note="Open-weight model — governed by its license/AUP, not an inference vendor's terms of service.",
        )

    # Unrecognized shape — e.g. a user-chosen Azure OpenAI deployment name
    # ("my-gpt4-prod"): the base model isn't encoded in the string at all.
    return ResolvedIdentifier(
        raw=raw,
        resolved=False,
        note="Identifier does not match any known vendor pattern — likely a custom deployment "
             "name (e.g. Azure OpenAI) where the base model is not encoded in the string. "
             "Source selection unverified.",
    )
