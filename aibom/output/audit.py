import collections
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_MAX_HISTORY_BYTES = 50 * 1024 * 1024   # 50 MB — stream tail if larger
_TAIL_LINES = 10_000                      # lines to keep from a huge history file


@dataclass
class AuditEntry:
    timestamp: str
    action: str
    actor: str
    details: dict = field(default_factory=dict)


class AuditTrail:
    def __init__(self, history_path: Optional[str] = None):
        self._entries: list[AuditEntry] = []
        self._history_path = Path(history_path) if history_path else None
        self._scan_id = uuid.uuid4().hex[:12]

    def record(self, action: str, actor: str = "ai-bom", **details):
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            action=action,
            actor=actor,
            details=details,
        )
        self._entries.append(entry)

    def to_list(self) -> list[dict]:
        return [
            {
                "timestamp": e.timestamp,
                "action": e.action,
                "actor": e.actor,
                "details": e.details,
            }
            for e in self._entries
        ]

    def flush_to_history(self, bom_output_path: str) -> None:
        """Append this scan's entries as one record to the persistent history JSONL."""
        target = self._history_path
        if target is None:
            target = Path(bom_output_path).parent / "aibom-history.jsonl"
        target.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "scan_id": self._scan_id,
            "bom_file": Path(bom_output_path).name,
            "entries": self.to_list(),
        }
        with target.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")

    @staticmethod
    def load_history(history_path: str) -> list[dict]:
        """Read past scan records from the JSONL history file.

        Streams the tail of large files to avoid loading GBs into memory.
        """
        p = Path(history_path)
        if not p.exists():
            return []
        try:
            size = p.stat().st_size
            if size > _MAX_HISTORY_BYTES:
                with p.open("r", encoding="utf-8", errors="ignore") as fh:
                    lines: list[str] = list(collections.deque(fh, maxlen=_TAIL_LINES))
            else:
                lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return []
        records = []
        for line in lines:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except Exception:
                    pass
        return records
