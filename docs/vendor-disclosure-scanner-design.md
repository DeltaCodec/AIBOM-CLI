# ai-bom — Vendor Model Identifier Resolver (design)

Status: **v1 scope locked and implemented, 2026-09-05** — `ai-bom resolve` shipped
(`aibom/scanner/vendor_resolver.py`, `aibom/cli.py`, `tests/test_vendor_resolver.py`).
The original "vendor disclosure scanner" concept (registry, 21-field schema, gap
report) was scoped down after a grill-with-docs session — see "CUT from v1" below.
Owner: Moacir. Separate feature track from `docs/perf-enhancement-plan.md`.

## What shipped in v1

`ai-bom resolve <model-id> [...]` — parses a model-id string found in code/config
into `{model_provider, hosting_provider, family, snapshot, floating_alias}`.
Pure string/regex parsing, no network call, no vendor SDK or API key required.
Surfaces two findings: **floating alias** (id has no pinned snapshot — can
silently resolve to a different model) and **hosting indirection** (the entity
you legally contract with differs from the model's trainer, e.g. Bedrock → AWS
governs, not Anthropic). Exits nonzero on either finding (CI-gate friendly).

This is a genuine BOM feature, not a bolt-on: it extends the tool's existing
detection-then-enrich pattern (`enrich_models`, `hub.py`) to a class of
component the scanner currently misses entirely — `scan_code_refs`
(aibom/scanner/code_scanner.py) only matches HuggingFace patterns
(`from_pretrained`, `hf_hub_download`), so an app calling `claude-sonnet-4-6`
directly via the Anthropic SDK produces **zero** entries in today's BOM.

### Still open — not yet built
- **Detection layer**: matching vendor-API SDK call sites (Anthropic/OpenAI/
  Bedrock/Vertex) to extract the model-id string automatically from a scanned
  project, the way `scan_code_refs` does for HF calls. `resolve` today takes
  the id as a CLI argument; it doesn't yet find ids in your code itself.
  Note: do **not** reuse `frameworks.py`'s `_IMPORT_MAP`/`Framework` — its
  `kind` field is rendered as a binary framework/library split in the
  "ML LIBRARIES & FRAMEWORKS" table (aibom/cli.py:790-808); a vendor-API SDK
  import needs its own detection path and output section, not that one.
- **New SPDX element type** (`ai_service` or similar) in `aibom/output/spdx.py`
  to emit resolved vendor components into the BOM itself, alongside the
  existing `software_package`/`dataset`/`ai_model` element types.
- **Compliance-summary integration**: `classify_eu_ai_act` works off HF
  pipeline tag/architecture, which a resolved API component has none of — the
  pass/fail compliance verdict won't evaluate these components without
  dedicated work.
- **Dashboard**: `aibom/dashboard/` renders BOM elements by type; a new
  element type needs matching chart/layout support or it silently won't show.

## CUT from v1 (documented, not built)

Everything below was the original design — full public-disclosure gap
scanning (registry, 21-field schema, extraction pipeline, CI gate on
undisclosed fields, `--contribute` PR flow). Cut for three reasons surfaced
during the grill session:

1. **Maintenance burden** — ~30 models × legal prose that changes on vendor
   timelines, "verbatim quote, never paraphrase," is paralegal-adjacent labor
   indefinitely, for a solo maintainer.
2. **Low marginal signal** — most of the 21 fields (training-data provenance,
   GPAI Art. 53 summaries) are undisclosed by *every* vendor, so the gap
   report converges to near-identical boilerplate across models. The
   resolver's two findings (floating alias, hosting indirection) are the
   actually novel, differentiated signal — see below.
3. **Legal exposure** — publishing "Vendor X has NOT disclosed Y" is a factual
   claim about a company; a missed doc makes it a wrong public claim, for a
   side project, indefinitely.

If ever revisited, the correct framing is **not** "BOM fragment" — a BOM
inventories components, it doesn't render a verdict on a third party's
disclosure completeness. The correct shape is a **VEX-style companion
document**: per-field status (disclosed/NOT_DISCLOSED/NOT_ASSESSED) +
justification (verbatim quote) + source (URL, as-of date) — same pattern as
CycloneDX/SPDX VEX's per-CVE `analysis` block, referencing the model
component by id rather than extending the component record itself. This
resolves the old "BOM element type" question (registry/schema section below)
without inventing a new component type for disclosure data.

---

## The identifier problem (resolver design — CURRENT, implemented)

This section is still live: it's the resolver's design spec and doubles as
the test matrix in `tests/test_vendor_resolver.py`.

Model id strings are non-standard across surfaces. Resolver must parse into
`{model_provider, hosting_provider, family, snapshot, floating_alias?}`.

| Surface | Example string |
|---|---|
| Anthropic API | `claude-sonnet-4-6`, `claude-3-5-sonnet-20241022`, `claude-3-5-sonnet-latest` |
| OpenAI | `gpt-4o`, `gpt-4o-2024-08-06`, `o3-mini` |
| Google AI | `gemini-1.5-pro`, `gemini-1.5-pro-002`, `models/gemini-1.5-pro` |
| Bedrock | `us.anthropic.claude-3-5-sonnet-20241022-v2:0` (region prefix + inference profile) |
| Azure OpenAI | `my-gpt4-prod` — user-chosen deployment name, base model NOT in the string |
| Vertex | `publishers/anthropic/models/claude-3-5-sonnet-v2@20241022` |
| OpenRouter | `anthropic/claude-3.5-sonnet` |
| Open weight | `meta-llama/Llama-3.1-70B-Instruct` (HF-card path, license/AUP not inference-vendor) |

- A **floating alias is itself a finding** ("version not under your control").
- Same model, multiple hosting providers -> different governing docs (Bedrock => AWS DPA/retention/region, not Anthropic's).

Uncovered-model degradation (implemented as `resolved=False`, never raises):
1. Resolver identifies provider from the id string pattern (`claude-*` -> Anthropic) — no per-model data needed.
2. Unrecognized shape (e.g. an Azure deployment name) -> flagged "source selection unverified," not a crash or dead end.

---

## Historical: original full-scope design (context only, not built)

Everything from here down describes the pre-grill-session vision in full —
kept for context on *why* the schema/registry looked the way it did, not as
a build plan. See "CUT from v1" above for the current decision and reasoning.

## Purpose

Operational readiness to answer risk / disposition questions about a given AI model.
"If a regulator or our own risk committee asks about `claude-sonnet-4-6`, can we answer?"

The tool produces the **vendor-neutral public artifact**: what the vendor has publicly
disclosed about a model, what it has NOT, as of a date, with citations. What an enterprise
does with that (map to their contracts, industry regs, approved-vendor list) is out of
bounds by design — that lives in their TPRM/GRC system, and no two are alike. Interface
between the two = the BOM file.

---

## Decisions locked

| # | Decision |
|---|---|
| Q1 | Vendor scanner = **new dedicated subcommand** (working name `ai-bom vendors`), NOT folded into `ai-bom scan`. |
| Q2a | Input: **both** — explicit model-id string(s) on CLI, *and* a path (discovers ids in code/config/IaC). `ai-bom scan` also emits discovered ids so `vendors` can consume them. |
| Q2b | Fetch model: **hosted/curated registry preferred, direct vendor fetch as `--live` fallback.** (Partially revisited — see registry section; not fully closed on hosted-service-vs-bundled.) |
| Q2c | **Online command.** Offline = degraded: bundled snapshot prints with staleness warning. User accepts offline is largely out of scope. |
| Layer 2 | **CUT from v1 and from docs.** Contract-/tier-specific facts (zero-retention agreements, BAAs, negotiated residency, who's cleared for what) are org-private, un-generalizable, and belong in the company's existing third-party-contract system. Not a feature. If ever built = separate repo consuming this tool's output. |
| Layer 2 caveat | Schema MUST still mark contract-dependent fields and emit them as `NOT_ASSESSED` — never silently present the public default as the answer. No "enterprise layer" concept in docs; just a per-field flag. |
| Q4 | **Registry needed, but split in two:** (1) *pointer registry* — MANDATORY, light: `model-id -> {provider, authoritative doc URLs, note on which doc holds which fact}`, ~15 lines/model, ~30 models = ~95% coverage. Ships WITH the tool, maintained by project + community PRs, refreshed by CI. End user never writes or sees it. (2) *fact cache* — OPTIONAL, derived: the filled schema, regenerable by re-extraction against the pointer list. v1 can ship zero pre-extracted facts and extract at runtime. |
| Q4 UX | "Just pick the model and it works" REQUIRES a registry with model-id keys (rules out a no-registry design). Registry key set = the autocomplete candidate list. |

## Uncovered-model behaviour (no dead end)

1. Resolver identifies provider from the id string (`claude-*` -> Anthropic) — pattern rules, no per-model data.
2. Fall back to bundled **provider-level doc roots** (~5 entries, one per provider).
3. Best-effort discovery + extraction, output flagged **"source selection unverified — model not in registry."**
4. Optional: `ai-bom vendors --contribute <id>` opens a PR template.

## Registry's three jobs

1. **Completion candidates** — user types `claude` -> match registry keys -> offer concrete ids.
2. **Resolve target** — chosen id -> provider, hosting options, authoritative doc URLs, per-fact location note.
3. **Extraction plan** — the note ("retention -> ToS §4", "risk tier -> RSP §3") points the extractor at the right section.

## Output shape (illustrative — values NOT verified facts)

Per-model **disclosure inventory + gap list**, emitted as human table AND BOM fragment
(CycloneDX/SPDX component).

Field states: `value (+ sourceUrl + verbatim quote + as-of date)` | `NOT_DISCLOSED` |
`NOT_ASSESSED (contract-dependent)` | `NOT_APPLICABLE`.

Groups: Identity · Model Card · Safety · Data-Inference · Data-Training · Legal · Compliance · Residency.

```
GAP REPORT (what you cannot answer from public disclosure)
  • knowledge cutoff
  • model deprecation / sunset date
  • machine-readable red-team summary
  • training data provenance
  • GPAI Art. 53 training-data summary
  • EU AI Act GPAI technical documentation
  -> 6 of 21 governance fields undisclosed
  -> identifier is a floating alias: version not under your control
```

Headline = the gap report (operational-readiness signal). Full inventory = the evidence.

Aligns with EU AI Act Art. 53 / GPAI Code of Practice (which forces providers toward
standardized published docs) — tool doubles as "did this GPAI provider meet its disclosure
obligation."

---

## Old open questions (superseded)

Everything that used to live here (gap-first vs. inventory-first default,
registry format, extraction floor, disclosure schema, CI gate on undisclosed
fields, `--contribute` flow) belonged to the cut full-scope design and is
moot for v1. The only items still genuinely open are listed under
"Still open — not yet built" near the top of this doc — those are about
*detecting* model-ids in a real project and wiring the resolver's output into
the BOM/dashboard/compliance-summary, not about disclosure scanning.
