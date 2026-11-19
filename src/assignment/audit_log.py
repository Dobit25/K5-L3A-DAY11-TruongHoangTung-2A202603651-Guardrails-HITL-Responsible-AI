"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Record input and start timestamp keyed by request_id/user_id."""
        import time
        rid = request_id or f"{user_id}_{time.time()}"
        self._open[rid] = time.time()
        self.logs.append({
            "type": "input",
            "user_id": user_id,
            "text": self._sanitize(text),
            "request_id": rid,
            "timestamp": utc_now_iso(),
        })

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Record output, layer decision, latency; append to self.logs."""
        import time
        rid = request_id or f"{user_id}_out"
        start = self._open.pop(rid, None)
        if start is None:
            for k in list(self._open):
                if k.startswith(user_id):
                    start = self._open.pop(k)
                    break
        latency = (time.time() - start) if start else None
        self.logs.append({
            "type": "output",
            "user_id": user_id,
            "text": self._sanitize(text)[:500] if text else "",
            "blocked": blocked,
            "layer": layer,
            "request_id": rid,
            "latency_ms": round(latency * 1000, 1) if latency else None,
            "timestamp": utc_now_iso(),
        })

    @staticmethod
    def _sanitize(text):
        from guardrails.output_guardrails import content_filter
        return content_filter(text or "")["redacted"]

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
