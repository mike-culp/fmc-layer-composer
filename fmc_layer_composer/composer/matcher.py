from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .models import MatchMode, SourceAcpRef, SourceRuleCandidate
from .signatures import build_rule_signature


def normalize_rule_name(name: str, mode: MatchMode) -> str:
    value = (name or "").strip()
    if mode == MatchMode.CASE_INSENSITIVE:
        return value.casefold()
    if mode == MatchMode.NORMALIZED_WHITESPACE:
        return re.sub(r"\s+", " ", value).strip().casefold()
    return value


def build_source_rule_index(
    source_rules_by_acp: dict[str, list[dict[str, Any]]],
    source_acps: list[SourceAcpRef],
    mode: MatchMode,
) -> dict[str, list[SourceRuleCandidate]]:
    acp_by_id = {acp.id: acp for acp in source_acps}
    index: dict[str, list[SourceRuleCandidate]] = defaultdict(list)
    for acp_id, rules in source_rules_by_acp.items():
        acp = acp_by_id[acp_id]
        for rule in rules:
            name = str(rule.get("name", "")).strip()
            if not name:
                continue
            candidate = SourceRuleCandidate(
                source_acp_id=acp.id,
                source_acp_name=acp.name,
                source_priority=acp.priority,
                rule_id=str(rule.get("id", "")),
                rule_name=name,
                rule=rule,
                signature=build_rule_signature(rule),
            )
            index[normalize_rule_name(name, mode)].append(candidate)
    for candidates in index.values():
        candidates.sort(key=lambda candidate: candidate.source_priority)
    return dict(index)
