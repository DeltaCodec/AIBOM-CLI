# Security Policy

## Supported versions

Only the latest minor release receives security fixes during the `0.x` series.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a vulnerability

**Do not open a public GitHub issue for security reports.**

Use one of the following private channels:

- **GitHub Security Advisories** — https://github.com/DeltaCodec/AIBOM-CLI/security/advisories/new (preferred)
- **Email** — moacir.js.filho@gmail.com with subject prefix `[ai-bom security]`

Please include:

- A description of the issue and its impact
- Reproduction steps, a proof-of-concept, or affected commit/version
- Any suggested mitigation if you have one

### Response timeline

- Acknowledgement of receipt: within **3 business days**
- Initial triage and severity assessment: within **7 business days**
- Coordinated disclosure: we aim to ship a fix and publish an advisory within **90 days** of confirmation, sooner for critical issues

We will credit reporters in the advisory unless anonymity is requested.

## Scope

In scope:

- The `ai-bom` Python package on PyPI
- Code in this repository, including the Dash dashboard
- GitHub Actions workflows in `.github/workflows/`

Out of scope:

- Vulnerabilities in third-party dependencies — please report those upstream; we will pick up fixed versions as they are released
- Findings that require modifying the local filesystem the user already controls
- Social engineering, physical attacks, or DoS against `pypi.org` / `osv.dev` / `huggingface.co`

## Threat model notes

`ai-bom` is a defensive supply-chain tool. It deliberately inspects untrusted artifacts (pickle files, safetensors headers, YAML configs, model cards). The tool **never executes** the artifacts it inspects — pickle files are scanned at the opcode level, not deserialized. If you find a code path that loads an untrusted artifact via `pickle.load`, `torch.load`, `joblib.load`, `eval`, `exec`, or `yaml.load` (unsafe), please report it.
