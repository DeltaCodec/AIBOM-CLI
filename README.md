# ai-bom

[![CI](https://github.com/DeltaCodec/AIBOM-CLI/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/DeltaCodec/AIBOM-CLI/actions/workflows/ci.yml)
[![CodeQL](https://github.com/DeltaCodec/AIBOM-CLI/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/DeltaCodec/AIBOM-CLI/actions/workflows/codeql.yml)
[![PyPI version](https://img.shields.io/pypi/v/ai-bom.svg)](https://pypi.org/project/ai-bom/)
[![Python versions](https://img.shields.io/pypi/pyversions/ai-bom.svg)](https://pypi.org/project/ai-bom/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![SPDX 3.0](https://img.shields.io/badge/output-SPDX_3.0-teal.svg)](https://spdx.github.io/spdx-spec/v3.0/)

**AI Bill of Materials generator for ML projects.**

`ai-bom` scans your machine learning project and produces a structured, auditable inventory of everything it contains: Python dependencies with CVE exposure, HuggingFace models with integrity hashes and EU AI Act risk classification, training datasets with LGPD/GDPR privacy flags, and ML frameworks. Output is SPDX 3.0 JSON — the emerging standard for AI system transparency — plus a rich terminal summary designed for quick compliance review.

---

## Features

| Category | What it detects |
|---|---|
| **Dependencies** | All pip packages, versions, SPDX licenses, copyleft flags, CVE exposure via OSV |
| **CVE enrichment** | OSV batch API → GHSA severity → NVD CVSS score, fix versions, no-fix warnings |
| **Model inspection** | Architecture, parameter count, context length, dtype, pickle safety, safetensors validation |
| **Integrity** | SHA-256 fingerprint per model; tamper detection against expected hashes |
| **EU AI Act** | Risk classification (HIGH / LIMITED / MINIMAL) from pipeline tag, tags, architecture |
| **Dataset provenance** | Auto-detected from code imports, HF cache, model cards, and known family lineage |
| **Privacy compliance** | LGPD / GDPR flagging with HIGH / MEDIUM / LOW risk levels; safe-list suppression |
| **ML frameworks** | Distinguishes orchestration frameworks (Ray, DeepSpeed, vLLM) from ML libraries (PyTorch, JAX…) |
| **SPDX 3.0 output** | Full element graph: packages, datasets, models, CVEs, audit trail, provenance gaps |
| **Compliance summary** | Pass/fail verdict across Licenses, Vulnerabilities, Privacy, Datasets, Models |

---

## Installation

```bash
pip install ai-bom
```

From source:

```bash
git clone https://github.com/DeltaCodec/AIBOM-CLI.git
cd AIBOM-CLI
pip install -e .
```

For the Dash dashboard:

```bash
pip install "ai-bom[dashboard]"
```

---

## Quick start

```bash
# Scan the current project
ai-bom scan .

# Scan a specific directory, write output to a fixed path
ai-bom scan ./my-ml-project --output bom.json

# Scan without hitting external APIs (offline mode)
ai-bom scan . --no-hub --no-cve --no-pypi

# Launch the interactive dashboard
ai-bom dashboard bom.json
```

---

## CLI reference

### `ai-bom scan [PROJECT_PATH]`

| Flag | Default | Description |
|---|---|---|
| `--config / -c` | `aibom.yaml` | Config file path |
| `--output / -o` | auto-named | Output JSON path |
| `--output-dir` | `.` | Directory for auto-named output |
| `--allowlist` | — | Extra SPDX IDs to allow (repeatable) |
| `--no-audit` | off | Skip writing the audit trail |
| `--no-pypi` | off | Skip PyPI license lookups |
| `--no-hub` | off | Skip HuggingFace Hub API enrichment |
| `--no-cache` | off | Skip HuggingFace local cache scan |
| `--no-cve` | off | Skip OSV CVE enrichment |
| `--quiet / -q` | off | Suppress all terminal output |

### `ai-bom resolve MODEL_ID [MODEL_ID ...]`

Resolves one or more vendor model-id strings (as found in code, config, or
IaC) into their model provider, hosting provider, and whether the id is a
floating alias that can silently resolve to a different model version. Pure
string parsing — no network access, no vendor SDK or API key required. Exits
non-zero if any id is a floating alias, has hosting indirection (governed by
a different entity than its trainer, e.g. Bedrock -> AWS), or is unresolvable.

```bash
ai-bom resolve claude-3-5-sonnet-latest us.anthropic.claude-3-5-sonnet-20241022-v2:0
```

### `ai-bom dashboard [BOM_FILE]`

| Flag | Default | Description |
|---|---|---|
| `--host` | `127.0.0.1` | Host to bind |
| `--port` | `8050` | Port to bind |
| `--debug` | off | Enable Dash debug mode |

---

## `aibom.yaml` config reference

```yaml
# aibom.yaml — place in your project root or pass with -c

project:
  name: my-ml-project        # defaults to directory name
  version: "1.0.0"

output:
  path: null                  # null = auto-named aibom-<name>-<timestamp>.json

# Manual model entries — supplement auto-detection
models:
  - name: bert-base-uncased
    source: huggingface
    source_id: google-bert/bert-base-uncased
    license: Apache-2.0
    version: "1.0"
    path: models/bert/pytorch_model.bin
    expected_hash: <sha256-hex>   # triggers tamper detection

# Manual dataset entries — supplement auto-detection
datasets:
  - name: squad
    source: https://huggingface.co/datasets/rajpurkar/squad
    version: "1.1"
    license: CC-BY-4.0
    gdpr_relevant: false
    lgpd_relevant: false
    confidential: false

# Extra SPDX license IDs to allow beyond the default permissive list
license_allowlist:
  - LicenseRef-custom-internal
  - CC-BY-4.0

# Extra keywords that trigger GDPR/LGPD flagging
gdpr_sources:
  - internal-survey-responses
  - customer-clickstream

# Override the default ~/.cache/huggingface/hub location
hf_cache_dir: null
```

---

## Output format

`ai-bom` produces **SPDX 3.0 JSON** containing:

- `elements` — one entry per dependency, dataset, and model
- `cvesByPackage` — full CVE detail with CVSS scores and fix suggestions
- `gdprFlags` — per-dataset privacy flags with risk level and regulation
- `provenanceGaps` — models with no traceable dataset origin
- `summary` — aggregate counts for quick dashboard consumption
- `auditTrail` — timestamped record of every scan step

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

To report a vulnerability, follow the process in [SECURITY.md](SECURITY.md). Please **do not** open public issues for security problems.

## License

MIT — see [LICENSE](LICENSE).
