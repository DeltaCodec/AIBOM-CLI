"""Simple JSON disk cache with per-entry TTL."""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

_ROOT = Path.home() / ".cache" / "aibom"
_MAX_ENTRY_BYTES = 10 * 1024 * 1024  # 10 MB — refuse to read/write larger entries


class DiskCache:
    def __init__(self, namespace: str, ttl_seconds: int):
        self._dir = _ROOT / namespace
        self._dir.mkdir(parents=True, exist_ok=True)
        self._ttl = ttl_seconds

    def _path(self, key: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9._-]", "_", key)
        # Long or collision-prone keys get hashed to prevent truncation collisions
        if len(safe) > 80:
            safe = hashlib.sha256(key.encode()).hexdigest()[:48]
        return self._dir / f"{safe}.json"

    def get(self, key: str) -> Optional[Any]:
        p = self._path(key)
        if not p.exists():
            return None
        try:
            if p.stat().st_size > _MAX_ENTRY_BYTES:
                return None
            data = json.loads(p.read_text(encoding="utf-8"))
            if time.time() - data["ts"] > self._ttl:
                return None
            return data["value"]
        except Exception:
            return None

    def set(self, key: str, value: Any) -> None:
        target = self._path(key)
        try:
            payload = json.dumps({"ts": time.time(), "value": value}, ensure_ascii=False)
            if len(payload.encode()) > _MAX_ENTRY_BYTES:
                return
            # Atomic write: temp file in same dir → os.replace (atomic on POSIX and Windows)
            fd, tmp = tempfile.mkstemp(dir=self._dir, suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(payload)
                os.replace(tmp, str(target))
            except Exception:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        except Exception:
            pass


# Shared instances
# PyPI package metadata (requires_dist) — version-pinned, immutable → 7 days
pypi_cache = DiskCache("pypi", ttl_seconds=7 * 24 * 3600)

# OSV batch vulnerability results — new CVEs disclosed daily → 24 h
osv_cache = DiskCache("osv", ttl_seconds=24 * 3600)

# OSV/GHSA/NVD individual vuln enrichment → 24 h
vuln_cache = DiskCache("vulns", ttl_seconds=24 * 3600)
