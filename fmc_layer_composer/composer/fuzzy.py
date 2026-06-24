from __future__ import annotations

import difflib
import re

from .models import FuzzyMatchOptions, FuzzyRuleCandidate, SourceRuleCandidate


ARTIFACT_SUFFIX_RE = re.compile(r"(?i)(?:_\d+)+$|-\d+$|\s+\(\d+\)$|\s+copy$")


def find_fuzzy_rule_candidates(
    csv_rule_name: str,
    source_rules: list[SourceRuleCandidate],
    options: FuzzyMatchOptions,
) -> list[FuzzyRuleCandidate]:
    if not options.enabled:
        return []
    threshold = getattr(options, "min_score", None) or options.threshold
    candidates: list[FuzzyRuleCandidate] = []
    normalized_csv = normalize_fuzzy_name(csv_rule_name)
    artifact_csv = artifact_base_name(csv_rule_name)
    for source_rule in source_rules:
        fuzzy = _score_candidate(csv_rule_name, normalized_csv, artifact_csv, source_rule, threshold, options)
        if fuzzy:
            candidates.append(fuzzy)
    return sorted(
        candidates,
        key=lambda item: (
            _source_priority(source_rules, item),
            _tier_rank(item.match_tier),
            -item.score,
            _rule_index(source_rules, item),
            item.candidate_rule_name.casefold(),
        ),
    )


def normalize_fuzzy_name(name: str) -> str:
    value = " ".join(str(name).strip().split()).casefold()
    value = re.sub(r"\s*[-_]\s*", "-", value)
    return value


def artifact_base_name(name: str) -> str:
    return normalize_fuzzy_name(ARTIFACT_SUFFIX_RE.sub("", str(name).strip()))


def _score_candidate(
    csv_rule_name: str,
    normalized_csv: str,
    artifact_csv: str,
    source_rule: SourceRuleCandidate,
    threshold: float,
    options: FuzzyMatchOptions,
) -> FuzzyRuleCandidate | None:
    candidate_name = source_rule.rule_name
    normalized_candidate = normalize_fuzzy_name(candidate_name)
    artifact_candidate = artifact_base_name(candidate_name)
    reasons: list[str] = []
    tier = ""
    score = 0.0

    if options.include_artifact_suffix_matches and artifact_csv == artifact_candidate and normalized_csv != normalized_candidate:
        tier = "ARTIFACT_SUFFIX"
        score = 0.97
        reasons.extend(_artifact_reasons(candidate_name))
    elif options.include_case_whitespace_matches and normalized_csv == normalized_candidate:
        tier = "NORMALIZED_EXACT"
        score = _normalized_exact_score(csv_rule_name, candidate_name, reasons)
    elif options.include_prefix_suffix_matches and (normalized_candidate.startswith(normalized_csv) or normalized_csv.startswith(normalized_candidate)):
        tier = "TOKEN_PREFIX_SUFFIX"
        score = 0.88
        reasons.append("PREFIX_MATCH")
    elif options.include_prefix_suffix_matches and (normalized_candidate.endswith(normalized_csv) or normalized_csv.endswith(normalized_candidate)):
        tier = "TOKEN_PREFIX_SUFFIX"
        score = 0.86
        reasons.append("SUFFIX_MATCH")
    elif options.include_prefix_suffix_matches and (normalized_csv in normalized_candidate or normalized_candidate in normalized_csv):
        tier = "TOKEN_PREFIX_SUFFIX"
        score = 0.84
        reasons.append("CONTAINS_MATCH")
    elif options.include_token_similarity_matches and _tokens(normalized_csv) == _tokens(normalized_candidate):
        tier = "TOKEN_PREFIX_SUFFIX"
        score = 0.80
        reasons.append("TOKEN_SET_MATCH")
    else:
        if not options.include_difflib_similarity_matches:
            return None
        score = difflib.SequenceMatcher(None, normalized_csv, normalized_candidate).ratio()
        if score < threshold:
            return None
        tier = "STRING_SIMILARITY"
        reasons.append("STRING_SIMILARITY_MATCH")

    return FuzzyRuleCandidate(
        csv_rule_name=csv_rule_name,
        candidate_rule_name=candidate_name,
        source_acp_id=source_rule.source_acp_id,
        source_acp_name=source_rule.source_acp_name,
        source_rule_id=source_rule.rule_id,
        score=round(score, 4),
        match_tier=tier,
        match_reasons=reasons,
        normalized_csv_name=normalized_csv,
        normalized_candidate_name=normalized_candidate,
        artifact_base_csv_name=artifact_csv,
        artifact_base_candidate_name=artifact_candidate,
        semantic_summary={
            "action": source_rule.signature.get("action"),
            "enabled": source_rule.signature.get("enabled"),
        },
        blocking_candidate_deltas=[],
        informational_candidate_deltas=[],
    )


def _artifact_reasons(name: str) -> list[str]:
    stripped = str(name).strip().casefold()
    reasons: list[str] = []
    if re.search(r"(?:_\d+)+$", stripped) or re.search(r"-\d+$", stripped) or re.search(r"\s+\(\d+\)$", stripped):
        reasons.append("ARTIFACT_SUFFIX_MATCH")
        reasons.append("DUPLICATE_SUFFIX_MATCH")
    if re.search(r"\s+copy$", stripped):
        reasons.append("COPY_SUFFIX_MATCH")
    return reasons or ["ARTIFACT_SUFFIX_MATCH"]


def _normalized_exact_score(csv_rule_name: str, candidate_name: str, reasons: list[str]) -> float:
    if csv_rule_name.strip() != candidate_name.strip() and csv_rule_name.strip().casefold() == candidate_name.strip().casefold():
        reasons.append("CASE_ONLY_MATCH")
        return 0.96
    if " ".join(csv_rule_name.split()) == " ".join(candidate_name.split()):
        reasons.append("WHITESPACE_ONLY_MATCH")
        return 0.95
    reasons.append("NORMALIZED_EXACT_MATCH")
    return 0.94


def _tokens(value: str) -> set[str]:
    return {token for token in re.split(r"[^a-z0-9]+", value.casefold()) if token}


def _tier_rank(tier: str) -> int:
    return {
        "ARTIFACT_SUFFIX": 1,
        "NORMALIZED_EXACT": 2,
        "TOKEN_PREFIX_SUFFIX": 3,
        "STRING_SIMILARITY": 4,
    }.get(tier, 99)


def _source_priority(source_rules: list[SourceRuleCandidate], fuzzy: FuzzyRuleCandidate) -> int:
    for rule in source_rules:
        if rule.rule_id == fuzzy.source_rule_id and rule.source_acp_id == fuzzy.source_acp_id:
            return rule.source_priority
    return 999999


def _rule_index(source_rules: list[SourceRuleCandidate], fuzzy: FuzzyRuleCandidate) -> int:
    for rule in source_rules:
        if rule.rule_id == fuzzy.source_rule_id and rule.source_acp_id == fuzzy.source_acp_id:
            metadata = rule.rule.get("metadata") or {}
            return int(metadata.get("ruleIndex") or 999999)
    return 999999
