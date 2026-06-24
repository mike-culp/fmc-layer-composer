from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MatchMode(str, Enum):
    EXACT = "exact"
    CASE_INSENSITIVE = "case_insensitive"
    NORMALIZED_WHITESPACE = "normalized_whitespace"


class RuleMatchStatus(str, Enum):
    READY_TO_COPY = "READY_TO_COPY"
    MATCHED_ONE = "MATCHED_ONE"
    MATCHED_IDENTICAL_MULTIPLE = "MATCHED_IDENTICAL_MULTIPLE"
    MATCHED_MULTIPLE_WITH_DELTA = "MATCHED_MULTIPLE_WITH_DELTA"
    MISSING = "MISSING"
    CSV_DUPLICATE_RULE_NAME = "CSV_DUPLICATE_RULE_NAME"
    CSV_TO_FMC_DELTA = "CSV_TO_FMC_DELTA"
    OBJECT_NAME_ARTIFACT_DELTA = "OBJECT_NAME_ARTIFACT_DELTA"
    SOURCE_CANDIDATE_DELTA = "SOURCE_CANDIDATE_DELTA"
    READ_ONLY_OR_LOCKED = "READ_ONLY_OR_LOCKED"
    SKIPPED = "SKIPPED"
    CREATED = "CREATED"
    CREATE_FAILED = "CREATE_FAILED"


@dataclass
class LayerCsvEntry:
    order: int
    raw_name: str
    rule_name: str
    csv_enabled: bool | None
    csv_action: str | None
    csv_source_zones: list[str]
    csv_destination_zones: list[str]
    csv_source_objects: list[str]
    csv_destination_objects: list[str]
    csv_services: list[str]
    csv_applications: list[str]
    csv_urls: list[str]
    csv_description: str | None
    raw_row: dict[str, Any]


@dataclass
class CsvParseResult:
    entries: list[LayerCsvEntry]
    rule_name_column: str
    duplicate_rule_names: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class SourceAcpRef:
    id: str
    name: str
    priority: int


@dataclass
class SourceRuleCandidate:
    source_acp_id: str
    source_acp_name: str
    source_priority: int
    rule_id: str
    rule_name: str
    rule: dict[str, Any]
    signature: dict[str, Any]
    warnings: list[str] = field(default_factory=list)


@dataclass
class CandidateFieldDelta:
    field_path: str
    severity: str
    delta_type: str
    values_by_candidate: dict[str, Any]
    message: str


@dataclass
class SanityDelta:
    code: str
    severity: str
    field: str
    csv_value: Any
    fmc_value: Any
    message: str
    fmc_details: list[dict[str, Any]] = field(default_factory=list)
    blocking: bool = False


@dataclass
class LayerRuleMatch:
    csv_entry: LayerCsvEntry
    status: str
    candidates: list[SourceRuleCandidate]
    selected_candidate: SourceRuleCandidate | None
    candidate_deltas: list[dict[str, Any]]
    candidate_field_deltas: list[CandidateFieldDelta]
    semantic_candidate_delta_count: int
    id_only_delta_count: int
    blocking_candidate_delta_count: int
    sanity_deltas: list[SanityDelta]
    warnings: list[str]
    skip_reason: str | None


@dataclass
class LayerComposerOptions:
    match_mode: MatchMode = MatchMode.EXACT
    skip_missing: bool = False
    use_priority_for_identical_candidates: bool = True
    use_priority_despite_candidate_deltas: bool = False
    honor_csv_disabled: bool = True
    target_acp_name: str = ""
    default_action: str = "BLOCK"
    rule_section: str = "mandatory"
    stop_on_first_failure: bool = True


@dataclass
class LayerComposerPlan:
    timestamp: str
    csv_filename: str
    target_acp_name: str
    source_acps: list[SourceAcpRef]
    options: LayerComposerOptions
    entries: list[LayerCsvEntry]
    matches: list[LayerRuleMatch]
    summary: dict[str, Any]
    commit_allowed: bool
    blockers: list[str]
    warnings: list[str]


@dataclass
class CreatedRuleResult:
    csv_order: int
    rule_name: str
    source_acp_name: str
    source_rule_id: str
    target_rule_id: str | None
    status: str
    error: str | None
    response: dict[str, Any] | None
    placement_strategy: str | None = None


@dataclass
class LayerComposerResult:
    plan: LayerComposerPlan
    target_acp_id: str | None
    target_acp_name: str
    created_rules: list[CreatedRuleResult]
    skipped_rules: list[dict[str, Any]]
    failed_rule: CreatedRuleResult | None
    errors: list[dict[str, Any]]
    report_paths: dict[str, str]
    expected_create_count: int = 0
    api_created_count: int = 0
    verified_target_rule_count: int = 0
    verification_status: str = "VERIFY_FAILED"
    missing_after_commit: list[str] = field(default_factory=list)
    extra_after_commit: list[str] = field(default_factory=list)
