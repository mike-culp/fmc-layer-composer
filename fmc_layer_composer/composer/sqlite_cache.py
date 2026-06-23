from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class LayerComposerCache:
    def __init__(self, path: str | Path = "fmc_layer_composer.sqlite"):
        self.path = Path(path)
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS source_acp_snapshot(
                  snapshot_id TEXT,
                  timestamp TEXT,
                  fmc_host TEXT,
                  domain_uuid TEXT,
                  acp_id TEXT,
                  acp_name TEXT,
                  priority INTEGER,
                  raw_json TEXT
                );
                CREATE TABLE IF NOT EXISTS source_rule_snapshot(
                  snapshot_id TEXT,
                  timestamp TEXT,
                  domain_uuid TEXT,
                  acp_id TEXT,
                  acp_name TEXT,
                  rule_id TEXT,
                  rule_name TEXT,
                  raw_json TEXT,
                  signature_json TEXT
                );
                CREATE TABLE IF NOT EXISTS analysis_plan(
                  plan_id TEXT,
                  timestamp TEXT,
                  target_acp_name TEXT,
                  csv_filename TEXT,
                  plan_json TEXT
                );
                CREATE TABLE IF NOT EXISTS commit_result(
                  result_id TEXT,
                  timestamp TEXT,
                  target_acp_id TEXT,
                  target_acp_name TEXT,
                  result_json TEXT
                );
                """
            )

    def save_source_rule_snapshot(self, rows: list[dict[str, Any]]) -> None:
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO source_rule_snapshot(
                  snapshot_id,timestamp,domain_uuid,acp_id,acp_name,rule_id,rule_name,raw_json,signature_json
                ) VALUES(:snapshot_id,:timestamp,:domain_uuid,:acp_id,:acp_name,:rule_id,:rule_name,:raw_json,:signature_json)
                """,
                rows,
            )

    def save_plan(self, plan_id: str, timestamp: str, target_acp_name: str, csv_filename: str, plan: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO analysis_plan(plan_id,timestamp,target_acp_name,csv_filename,plan_json) VALUES(?,?,?,?,?)",
                (plan_id, timestamp, target_acp_name, csv_filename, json.dumps(plan, default=str)),
            )

    def save_result(self, result_id: str, timestamp: str, target_acp_id: str | None, target_acp_name: str, result: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO commit_result(result_id,timestamp,target_acp_id,target_acp_name,result_json) VALUES(?,?,?,?,?)",
                (result_id, timestamp, target_acp_id, target_acp_name, json.dumps(result, default=str)),
            )
