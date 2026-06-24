from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MatchMode(str, Enum):
    EXACT = "exact"
    CASE_INSENSITIVE = "case_insensitive"
    NORMALIZED_WHITESPACE = "normalized_whitespace"


class RuleMatchStatus(str, Enum):
    EXACT_MATCH = "EXACT_MATCH"
    READY_TO_COPY = "READY_TO_COPY"
    MATCHED_ONE = "MATCHED_ONE"
    MATCHED_IDENTICAL_MULTIPLE = "MATCHED_IDENTICAL_MULTIPLE"
    MATCHED_MULTIPLE_WITH_DELTA = "MATCHED_MULTIPLE_WITH_DELTA"
    NO_EXACT_MATCH = "NO_EXACT_MATCH"
    FUZZY_CANDIDATES_FOUND = "FUZZY_CANDIDATES_FOUND"
    FUZZY_SELECTED = "FUZZY_SELECTED"
    FUZZY_SELECTED_RENAMED_TO_CSV = "FUZZY_SELECTED_RENAMED_TO_CSV"
    FMT_SPLIT_CANDIDATES_FOUND = "FMT_SPLIT_CANDIDATES_FOUND"
    MULTI_RULE_OVERRIDE_SELECTED = "MULTI_RULE_OVERRIDE_SELECTED"
    MULTI_RULE_OVERRIDE_READY = "MULTI_RULE_OVERRIDE_READY"
    MULTI_RULE_OVERRIDE_RENAMED = "MULTI_RULE_OVERRIDE_RENAMED"
    MULTI_RULE_OVERRIDE_PRESERVE_SOURCE_NAMES = "MULTI_RULE_OVERRIDE_PRESERVE_SOURCE_NAMES"
    MULTI_RULE_OVERRIDE_CREATED = "MULTI_RULE_OVERRIDE_CREATED"
    MULTI_RULE_OVERRIDE_PART_CREATED = "MULTI_RULE_OVERRIDE_PART_CREATED"
    MULTI_RULE_OVERRIDE_PART_FAILED = "MULTI_RULE_OVERRIDE_PART_FAILED"
    NO_FUZZY_CANDIDATES = "NO_FUZZY_CANDIDATES"
    SKIPPED_NO_CANDIDATE_SELECTED = "SKIPPED_NO_CANDIDATE_SELECTED"
    SKIPPED_BY_USER = "SKIPPED_BY_USER"
    SKIPPED_BY_OPTION = "SKIPPED_BY_OPTION"
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
class FuzzyMatchOptions:
    enabled: bool = True
    threshold: float = 0.72
    min_score: float = 0.72
    include_artifact_suffix_matches: bool = True
    include_case_whitespace_matches: bool = True
    include_prefix_suffix_matches: bool = True
    include_token_similarity_matches: bool = True
    include_difflib_similarity_matches: bool = True
    auto_accept_single_deterministic_artifact: bool = False
    auto_select_single_artifact_match: bool = False


@dataclass
class FuzzyRuleCandidate:
    csv_rule_name: str
    candidate_rule_name: str
    source_acp_id: str
    source_acp_name: str
    source_rule_id: str
    score: float
    match_tier: str
    match_reasons: list[str]
    normalized_csv_name: str
    normalized_candidate_name: str
    artifact_base_csv_name: str
    artifact_base_candidate_name: str
    semantic_summary: dict[str, Any]
    blocking_candidate_deltas: list[dict[str, Any]]
    informational_candidate_deltas: list[dict[str, Any]]


@dataclass
class SplitRuleCandidateGroup:
    csv_order: int
    csv_rule_name: str
    source_acp_name: str
    source_acp_id: str
    candidates: list[FuzzyRuleCandidate]
    group_score: float
    group_reasons: list[str]
    blocking_delta_count: int
    informational_delta_count: int


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
class RuleSkipReason:
    csv_order: int
    csv_rule_name: str
    final_status: str
    primary_reason_code: str
    human_reason: str
    match_mode_used: str
    source_acps_searched: list[str]
    exact_candidates_found: list[dict[str, Any]]
    fuzzy_candidates_found: list[dict[str, Any]]
    selected_candidate: dict[str, Any] | None
    user_decision: str
    commit_impact: str
    blockers_or_warnings: list[str]


@dataclass
class LayerRuleMatch:
    csv_entry: LayerCsvEntry
    status: str
    candidates: list[SourceRuleCandidate]
    fuzzy_candidates: list[FuzzyRuleCandidate]
    split_candidate_groups: list[SplitRuleCandidateGroup]
    selected_candidate: SourceRuleCandidate | None
    selected_fuzzy_candidate: FuzzyRuleCandidate | None
    candidate_deltas: list[dict[str, Any]]
    candidate_field_deltas: list[CandidateFieldDelta]
    semantic_candidate_delta_count: int
    id_only_delta_count: int
    blocking_candidate_delta_count: int
    sanity_deltas: list[SanityDelta]
    warnings: list[str]
    skip_reason: str | None
    primary_reason_code: str | None = None
    human_reason: str | None = None
    user_decision: str | None = None
    commit_impact: str | None = None
    target_rule_name: str | None = None
    rename_to_csv_rule_name: bool = False
    skip_reason_detail: RuleSkipReason | None = None


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
    fuzzy: FuzzyMatchOptions = field(default_factory=FuzzyMatchOptions)
    fuzzy_selections: dict[int, str] = field(default_factory=dict)
    fuzzy_skips: set[int] = field(default_factory=set)
    target_rule_name_mode: str = "csv"


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
    plan_signature: str | None = None
    resolution_state: dict[str, Any] = field(default_factory=dict)
    resolved_plan_summary: dict[str, Any] = field(default_factory=dict)


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
    task_order: int | None = None
    target_rule_name: str | None = None
    is_multi_rule_override: bool = False
    multi_rule_part_number: int | None = None
    multi_rule_part_total: int | None = None


@dataclass
class RuleCreateTask:
    csv_order: int
    csv_rule_name: str
    task_order: int
    source_acp_id: str
    source_acp_name: str
    source_rule_id: str
    source_rule_name: str
    target_rule_name: str
    selection_method: str
    is_multi_rule_override: bool
    multi_rule_part_number: int | None
    multi_rule_part_total: int | None
    target_naming_mode: str = "AUTO"
    custom_target_rule_name: str | None = None
    target_rule_name_length: int = 0
    target_rule_name_validation_status: str = "VALID"
    target_rule_name_warning: str | None = None
    target_rule_name_recommended_action: str | None = None


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
    create_tasks: list[RuleCreateTask] = field(default_factory=list)
    expected_create_operations: int = 0


@dataclass
class ResolvedLayerComposerPlan:
    plan: LayerComposerPlan
    summary: dict[str, Any]
    commit_allowed: bool
    blockers: list[str]
    warnings: list[str]
