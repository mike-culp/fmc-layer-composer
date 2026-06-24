from __future__ import annotations


FMC_ACCESS_RULE_NAME_MAX_LENGTH = 50


def rule_name_length(name: str) -> int:
    return len(name or "")


def is_valid_fmc_rule_name(name: str) -> bool:
    return bool(name and rule_name_length(name) <= FMC_ACCESS_RULE_NAME_MAX_LENGTH)


def get_rule_name_length_warning(name: str) -> str | None:
    length = rule_name_length(name)
    if not name:
        return "Rule name is empty."
    if length > FMC_ACCESS_RULE_NAME_MAX_LENGTH:
        return f"Rule name is {length} characters. FMC access rule names must be 50 characters or fewer."
    return None
