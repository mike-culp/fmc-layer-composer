from fmc_layer_composer.composer.fuzzy import find_fuzzy_rule_candidates
from fmc_layer_composer.composer.models import FuzzyMatchOptions, SourceRuleCandidate


def candidate(name):
    return SourceRuleCandidate("acp", "MGM Grand", 1, "rule-id-" + name, name, {"name": name}, {"action": "ALLOW"})


def names_for(csv_name, *source_names):
    return find_fuzzy_rule_candidates(csv_name, [candidate(name) for name in source_names], FuzzyMatchOptions())


def test_name_matches_underscore_artifact_suffix():
    matches = names_for("NAME", "NAME_1")
    assert matches[0].match_tier == "ARTIFACT_SUFFIX"
    assert "ARTIFACT_SUFFIX_MATCH" in matches[0].match_reasons


def test_name_matches_nested_underscore_artifact_suffix():
    matches = names_for("NAME", "NAME_1_1")
    assert matches[0].match_tier == "ARTIFACT_SUFFIX"


def test_name_matches_hyphen_artifact_suffix():
    matches = names_for("NAME", "NAME-1")
    assert matches[0].match_tier == "ARTIFACT_SUFFIX"


def test_name_matches_parenthetical_artifact_suffix():
    matches = names_for("NAME", "NAME (1)")
    assert matches[0].match_tier == "ARTIFACT_SUFFIX"


def test_case_only_rule_names_are_normalized_candidates():
    matches = names_for("clients-to-PDQ", "Clients-to-PDQ")
    assert matches[0].match_tier == "NORMALIZED_EXACT"
    assert "CASE_ONLY_MATCH" in matches[0].match_reasons


def test_whitespace_only_rule_names_are_normalized_candidates():
    matches = names_for("Clients to PDQ", "Clients   to   PDQ")
    assert matches[0].match_tier == "NORMALIZED_EXACT"
    assert "WHITESPACE_ONLY_MATCH" in matches[0].match_reasons
