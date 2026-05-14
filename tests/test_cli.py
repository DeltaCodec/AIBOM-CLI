"""Smoke tests for the CLI."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def run_scan(path: str, extra_args: list[str] | None = None) -> tuple[int, str, Path]:
    """Run `ai-bom scan` and return (exit_code, stdout, output_path)."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "bom.json"
        cmd = [
            sys.executable, "-m", "aibom.cli", "scan", path,
            "--output", str(out),
            "--no-hub", "--no-cve", "--no-pypi", "--quiet",
        ] + (extra_args or [])
        result = subprocess.run(cmd, capture_output=True, text=True)
        content = out.read_text() if out.exists() else ""
        return result.returncode, result.stderr, out if out.exists() else None, content


class TestScanSmoke:
    def test_scan_project_root_exits_zero(self):
        """Scanning the ai-bom source itself should succeed."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "bom.json"
            result = subprocess.run(
                [sys.executable, "-m", "aibom.cli", "scan", ".",
                 "--output", str(out),
                 "--no-hub", "--no-cve", "--no-pypi", "--quiet"],
                capture_output=True, text=True,
            )
            assert result.returncode == 0, f"stderr: {result.stderr}"

    def test_scan_produces_valid_spdx_json(self):
        """Output must be parseable JSON with spdxVersion field."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "bom.json"
            subprocess.run(
                [sys.executable, "-m", "aibom.cli", "scan", ".",
                 "--output", str(out),
                 "--no-hub", "--no-cve", "--no-pypi", "--quiet"],
                check=True, capture_output=True,
            )
            bom = json.loads(out.read_text())
            assert bom.get("spdxVersion") == "SPDX-3.0"
            assert "summary" in bom
            assert "elements" in bom

    def test_scan_summary_has_expected_keys(self):
        """BOM summary should contain all required count keys."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "bom.json"
            subprocess.run(
                [sys.executable, "-m", "aibom.cli", "scan", ".",
                 "--output", str(out),
                 "--no-hub", "--no-cve", "--no-pypi", "--quiet"],
                check=True, capture_output=True,
            )
            bom = json.loads(out.read_text())
            s = bom["summary"]
            for key in ("totalDependencies", "totalDatasets", "totalModels", "totalFrameworks"):
                assert key in s, f"Missing summary key: {key}"

    def test_scan_nonexistent_path_fails(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmp:
            gone = Path(tmp) / "deleted_subdir"
        # tmp is deleted here; gone definitely doesn't exist
        result = subprocess.run(
            [sys.executable, "-m", "aibom.cli", "scan", str(gone),
             "--quiet"],
            capture_output=True, text=True,
        )
        assert result.returncode != 0
