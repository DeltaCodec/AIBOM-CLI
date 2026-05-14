# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-09

### Added

- Dependency scanning via `pip freeze` with requirements.txt / pyproject.toml / setup.cfg support
- CVE enrichment via OSV batch API with GHSA and NVD CVSS fallback
- Fix version suggestions and "no fix available" warnings per CVE
- HuggingFace model inspection: architecture, parameter count, context length, dtype, tokenizer type
- Pickle safety scanning: 14 dangerous opcode patterns detected without executing the file
- Safetensors header validation
- SHA-256 integrity fingerprinting per model with tamper detection against expected hashes
- EU AI Act risk classification (HIGH / LIMITED / MINIMAL / UNKNOWN) from pipeline tag, model tags, and architecture inference
- HuggingFace Hub API enrichment: license, base model lineage, training datasets, pipeline tag
- HuggingFace local cache scanning (`~/.cache/huggingface/hub/`)
- Dataset provenance detection: code imports, config files, model card `training_datasets`, known family lineage
- 21 model family lineage patterns (LLaMA, Mistral, Falcon, Gemma, Phi, Qwen, Granite, and more)
- LGPD / GDPR privacy flagging with HIGH / MEDIUM / LOW risk levels and safe-list suppression
- ML framework detection split into orchestration frameworks (Ray, DeepSpeed, vLLM, MLflow, W&B…) and ML libraries (PyTorch, TensorFlow, JAX, Transformers…)
- Confidence-graded dataset provenance: CONFIRMED (from model card), INFERRED (from lineage), UNKNOWN
- Provenance gap detection for models with no traceable dataset origin
- SPDX 3.0 JSON output with full element graph, CVE detail, GDPR flags, audit trail
- Rich terminal output: summary panel, dependency table, CVE table, model inspection table, dataset table, ML libraries & frameworks table, privacy flags panel, compliance summary
- Compliance summary with five categories (Licenses, Vulnerabilities, Privacy, Datasets, Models) and overall pass/fail verdict
- Disk cache for PyPI, OSV, and NVD responses with configurable TTL
- `aibom.yaml` config file support for manual model/dataset entries, license allowlist, GDPR keywords
- Atomic cache writes to prevent file corruption under concurrent scans
- `ai-bom dashboard` command launching a Dash web UI
- Scan duration and output path printed after every scan

[Unreleased]: https://github.com/DeltaCodec/AIBOM-CLI/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/DeltaCodec/AIBOM-CLI/releases/tag/v0.1.0
