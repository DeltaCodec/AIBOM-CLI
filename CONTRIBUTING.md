# Contributing to ai-bom

Thanks for your interest in contributing. Here's how to get set up.

## Development environment

```bash
git clone https://github.com/yourname/ai-bom
cd ai-bom
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Running tests

```bash
pytest
pytest -v                    # verbose
pytest tests/test_gdpr.py    # single file
```

## Linting

```bash
ruff check .
ruff check --fix .           # auto-fix safe issues
```

The project targets Python 3.10+ and enforces a line length of 100.

## How to add a new ML framework or library

Open `aibom/scanner/frameworks.py`.

- **Framework** (orchestration, MLOps, serving): add an entry to `FRAMEWORKS`
- **Library** (core ML, training, inference): add an entry to `ML_LIBRARIES`

Both dicts map `import_name → (display_name, pip_package_name)`. Use the top-level
import name (e.g. `"sklearn"` for `scikit-learn`):

```python
ML_LIBRARIES: dict[str, tuple[str, str]] = {
    ...
    "my_lib": ("My Library", "my-lib-package"),
}
```

If a library has multiple import aliases that resolve to the same pip package, add all
of them — deduplication is handled automatically by the scanner.

## How to add a new model family to lineage

Open `aibom/scanner/datasets.py` and find `_KNOWN_LINEAGE`.

Each entry is `family_pattern → list[dataset_spec]`:

```python
"myfamily": [
    {"name": "CommonCrawl", "source_type": "web_scrape", "gdpr_risk": "HIGH",
     "confidence": "INFERRED", "sensitivity": "PUBLIC"},
    {"name": "Wikipedia",   "source_type": "licensed",   "gdpr_risk": "LOW",
     "confidence": "INFERRED", "sensitivity": "PUBLIC"},
],
```

The family pattern is matched against model names using whole-token boundaries
(split on `-`, `_`, `/`, spaces, dots). Confirm the training data using the model's
original paper or model card before adding.

## Submitting a pull request

1. Fork the repo and create a branch from `main`
2. Make your changes with tests
3. Run `pytest` and `ruff check .` — both must pass
4. Open a PR with the provided template

## Code of conduct

Be constructive and respectful. No harassment, discrimination, or personal attacks.
