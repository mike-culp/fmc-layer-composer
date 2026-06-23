from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class DiagnosticsLogger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def event(
        self,
        *,
        stage: str,
        severity: str = "info",
        csv_order: int | None = None,
        rule_name: str | None = None,
        source_acp_name: str | None = None,
        status: str | None = None,
        decision: str | None = None,
        reason_code: str | None = None,
        details: dict[str, Any] | None = None,
        api_method: str | None = None,
        api_path: str | None = None,
        api_status: int | None = None,
        api_response: Any = None,
    ) -> None:
        record = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stage": stage,
            "severity": severity,
            "csv_order": csv_order,
            "rule_name": rule_name,
            "source_acp_name": source_acp_name,
            "status": status,
            "decision": decision,
            "reason_code": reason_code,
            "details": details or {},
            "api_method": api_method,
            "api_path": api_path,
            "api_status": api_status,
            "api_response": api_response,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, default=str) + "\n")
