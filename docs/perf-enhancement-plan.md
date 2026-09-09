# ai-bom — Processing Performance Enhancement Plan

Status: **draft for review** · Target: v0.2.0 · Scope: processing/perf only (output-format
and coverage work tracked separately).

## Baseline (measured 2026-09-03)

Machine: Windows 11, Python 3.12. Test corpus = the `ai-bom` repo itself (429 tree entries,
~15 first-party deps).

| Operation | Measured | Notes |
|---|---|---|
| `Path.rglob("*")` once | 0.14 s | 429 entries |
| `rglob("*")` ×7 | 0.88 s | current scan does ~7 independent full walks |
| `pip freeze --all` subprocess | 3.27 s | run once, sometimes twice |
| `importlib.metadata.distributions()` | 0.34 s | same data, in-process |
| offline scan (`--no-hub --no-cve --no-pypi --no-cache`) | ~2 s | dominated by walks + hashing |
| scan with PyPI + CVE (network) | 30.7 s | serial-ish HTTP, no session reuse |
| test suite (`pytest -q`) | 84 s | hits live OSV/PyPI/NVD/HF |

Projection: the ×7-walk and no-exclude behaviour is ~1 s here but scales linearly with tree
size. A repo with a checked-in `.venv` or `node_modules` (50k–200k entries) turns that into
30–120 s of pure `os.stat` churn plus SHA-256 over the whole venv.

## Guiding constraints

- No behavioural change to the BOM contents except where explicitly called out (walk
  exclusions change which files are seen — that is intended and must be documented + flag-gated).
- Every slice ships with a benchmark number (before/after) and unit tests that do **not**
  hit the network.
- Keep the `--no-*` offline flags working.

---

## Slice 1 — Single project tree walk (`FileIndex`)

**Problem.** `scan_code_refs`, `scan_models`, `scan_datasets._scan_directories`,
`_scan_configs`, `_scan_dataset_cards` (×2), `detect_frameworks` (×2) each call
`root.rglob("*")` from scratch. ~7 recursive walks, each re-`stat`-ing every entry.

**Change.** Add `aibom/scanner/fileindex.py`:

```python
@dataclass
class FileIndex:
    root: Path
    files: list[Path]              # all non-excluded files, one walk
    by_suffix: dict[str, list[Path]]   # ".py" -> [...], ".json" -> [...]
    by_name: dict[str, list[Path]]     # "config.json" -> [...], "README.md" -> [...]
    dirs_by_name: dict[str, list[Path]]  # "data" -> [...], lowercased
```

Build it once in `cli.scan` with a single `os.walk` (faster than `rglob` — lets us prune
dirs in-place). Pass the index into every scanner; delete their internal walks.

**Files.** New `fileindex.py`; edit `code_scanner.py`, `models.py`, `datasets.py`,
`frameworks.py`, `cli.py`.

**Acceptance.** One walk per scan (assert via a counter/monkeypatch in tests). Offline scan
time on a synthetic 20k-file tree drops ≥60%. BOM output byte-identical to baseline on the
test corpus (before exclusions land — see Slice 2).

**Effort.** M (touches every scanner signature; mechanical once `FileIndex` exists).

---

## Slice 2 — Directory exclusions + `.gitignore` awareness

**Problem.** No skip list. `_scan_configs` reads every `.json`/`.yaml`/`.toml` in the tree;
`_scan_dataset_cards` reads every `README.md`; `scan_models` hashes every weight-suffixed
file including those inside a vendored venv.

**Change.**
- Default prune set: `.git`, `.hg`, `.svn`, `.venv`, `venv`, `env`, `node_modules`,
  `site-packages`, `__pycache__`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `.tox`,
  `.idea`, `.vscode`, `dist`, `build`, `.eggs`, `*.egg-info`.
- `--include-hidden` / `--no-default-excludes` escape hatches.
- `--exclude PATTERN` (repeatable, glob).
- Optional `.gitignore` respect via a tiny matcher (vendored, ~40 lines) or `pathspec` as an
  extra dep — **decision needed** (see Open Questions).
- `aibom.yaml`: `scan.exclude: [...]`, `scan.respect_gitignore: true`.

**Files.** `fileindex.py` (prune logic), `cli.py` (flags), `README.md`, config example.

**Acceptance.** Scanning a repo with a 10k-file `.venv` inside is within 10% of scanning it
without. Documented note in CHANGELOG: "scans no longer descend into common vendor/build
dirs by default; use `--no-default-excludes` for old behaviour."

**Effort.** S–M (M if `.gitignore` matching is in scope).

---

## Slice 3 — Content-addressed hash cache

**Problem.** `_sha256` (per model file) and `_dir_sha256` (config + weights) run every scan,
single-threaded. `scan_hf_cache` with no `filter_ids` hashes **every** model in
`~/.cache/huggingface/hub`. Nothing is memoised between runs.

**Change.**
- New `hash_cache` namespace in `cache.py` (no TTL — keyed by identity, not freshness).
- Key = `f"{path}:{mtime_ns}:{size}"` → value = hex digest. Cheap `stat` guards the
  expensive read.
- Route `_sha256`, `_dir_sha256` through it.
- `--no-hash-cache` to force recompute.

**Files.** `cache.py`, `scanner/models.py`, `scanner/hf_cache.py`.

**Acceptance.** Second scan of an unchanged tree/cache does zero file-content reads for
hashing (assert via monkeypatched `_sha256`). Cold vs warm scan of a dir with a 1–2 GB model
shows the warm run saving ≥95% of hash time.

**Effort.** S.

---

## Slice 4 — Parallelise hashing + inspection

**Problem.** Model discovery/hash/inspect loop in `scan_models` and `scan_hf_cache` is
serial. On multi-model trees this is wall-clock bound on one core.

**Change.** `ThreadPoolExecutor` (I/O-bound: SHA-256 releases the GIL in `hashlib`, file
reads release it) for per-file/per-dir hashing and `inspect_model_dir`. Worker count from
new `--jobs N` (default `min(8, os.cpu_count())`), threaded through to `enrich_cves` too
(already parallel there — just unify the knob).

**Files.** `scanner/models.py`, `scanner/hf_cache.py`, `compliance/cve.py`, `cli.py`.

**Acceptance.** Scanning a fixture with 8 small model dirs is ≥3× faster at `--jobs 8` than
`--jobs 1`. Output order-independent (sort before emit).

**Effort.** S–M.

---

## Slice 5 — Drop `pip freeze` subprocess

**Problem.** `_pip_freeze()` shells out to `pip freeze --all` (3.3 s here), and
`_infer_snapshot_deps` can trigger it again plus an `importlib.metadata` fallback loop.

**Change.** Replace with `importlib.metadata.distributions()` (0.34 s), building
`{canonical_name: version}` with `packaging.utils.canonicalize_name`. Keep a `pip freeze`
fallback only if `distributions()` yields nothing (exotic environments). Memoise per process.

**Files.** `scanner/deps.py`, `cli.py`.

**Acceptance.** `scan_dependencies` returns the same package set as before (diff-tested
against `pip freeze` output in CI on a known env), ~3 s faster, no subprocess spawned
(assert `subprocess.run` not called).

**Effort.** S.

---

## Slice 6 — Shared HTTP session with retry/backoff

**Problem.** Every OSV/PyPI/NVD/HF call is a fresh `requests.get` — new TCP + TLS
handshake each time, no connection pooling, no retry on transient 5xx/429.

**Change.** `aibom/http.py` exposing a module-level `session()` returning a singleton
`requests.Session` with `HTTPAdapter(max_retries=Retry(total=3, backoff_factor=0.5,
status_forcelist=[429,500,502,503,504], respect_retry_after_header=True))` and a default
`User-Agent`. Replace all `requests.get/post` call sites.

**Files.** New `http.py`; edit `compliance/cve.py`, `scanner/hub.py`, `cli.py`
(`_pypi_latest_version`, `_fetch_requires_dist`).

**Acceptance.** CVE+PyPI scan of the test corpus drops measurably (target ≥25% off the
30.7 s baseline). Retry path unit-tested with a mock returning 503-then-200.

**Effort.** S.

---

## Slice 7 — Disk-cache HuggingFace model cards

**Problem.** `_fetch_model_card` has **no** disk cache (only a per-run in-memory dict).
Every scan re-hits `huggingface.co/api/models/...` with a 0.5 s sleep between each.

**Change.** New `hf_cache` (cards) namespace in `cache.py`, TTL 7 days (model metadata is
near-static). Cache the parsed `HFModelCard` (as `asdict`). Replace the fixed
`time.sleep(0.5)` serial loop with a small threadpool (`--jobs`) gated by the shared session;
only sleep/backoff on an actual 429.

**Files.** `cache.py`, `scanner/hub.py`.

**Acceptance.** Second scan referencing the same models makes zero HF API calls (assert via
mocked session). First scan of N models is ~N×0.5 s faster from losing the mandatory sleeps.

**Effort.** S.

---

## Slice 8 — Deterministic BOM identity

**Problem.** `generate_spdx` uses `uuid.uuid4()` for `documentNamespace` and the doc id, and
`datetime.now()` for `createdAt`. Two scans of identical input produce noisy diffs — defeats
CI drift gating and makes `aibom-history.jsonl` hard to use.

**Change.**
- Derive the document id / namespace from a content hash of the normalised element list
  (sorted, minus timestamps).
- Keep the wall-clock `createdAt`, but add `contentHash` (sha256 of the canonical BOM with
  `createdAt`/`auditTrail` excluded) to `summary`.
- `--reproducible` flag: zero out `createdAt` and `auditTrail` timestamps for byte-stable
  output.

**Files.** `output/spdx.py`, `output/audit.py`, `cli.py`.

**Acceptance.** `aibom scan X --reproducible` twice → byte-identical files. `contentHash`
stable across runs when inputs unchanged, changes when a dep/model/dataset changes.

**Effort.** S–M.

---

## Slice 9 — Non-network test suite

**Problem.** 84 s suite, flaky offline, NVD path sleeps 7 s. CI depends on third-party
uptime.

**Change.** Add `responses` (or `respx`/`vcr`) as a dev dep; record fixtures for the OSV
batch, OSV vuln, GHSA, NVD, PyPI, and HF endpoints. Mark any genuinely-live test
`@pytest.mark.network` and exclude from default `pytest` (`addopts = -m "not network"`).
Inject the HTTP session (Slice 6) so tests can pass a mock.

**Files.** `pyproject.toml`, `tests/conftest.py`, new `tests/fixtures/http/*.json`, most
`tests/test_*.py`.

**Acceptance.** `pytest` runs with the network unplugged in < 10 s. Coverage not lower than
today.

**Effort.** M.

---

## Suggested order

1. Slice 5 (pip freeze) — smallest, instant 3 s win, no dependents.
2. Slice 6 (HTTP session) — unblocks 7 and 9.
3. Slice 1 (FileIndex) — biggest structural win; do before 2/3/4.
4. Slice 2 (exclusions) — rides on FileIndex.
5. Slice 3 (hash cache) → Slice 4 (parallel hashing).
6. Slice 7 (HF card cache).
7. Slice 8 (determinism).
8. Slice 9 (test suite) — last, once sessions are injectable.

Slices 1–7 are independently shippable and individually benchmarkable.

## Open questions

1. **`.gitignore` support** in Slice 2 — vendor a ~40-line matcher, take a `pathspec`
   dependency, or defer entirely to a follow-up? Default exclude list alone covers ~90% of
   the pain.
2. **`--jobs` default** — `min(8, cpu_count())` or a flat `4`? HF/NVD rate limits mean the
   network paths can't use the full count anyway.
3. **`--reproducible` vs. always content-addressed** — is anyone relying on the current
   random `documentNamespace`? (Almost certainly not; it's `aibom.local/...`.)
4. **Cache size** — `_MAX_ENTRY_BYTES` is 10 MB; hash-cache entries are tiny but numerous.
   Add an entry-count cap / LRU eviction to `DiskCache`, or leave it?
