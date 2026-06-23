# FMC Layer Composer

FMC Layer Composer is a standalone Python/Streamlit tool for composing a new Cisco FMC Access Control Policy from rules that already exist in migrated FMC-native source policies.

It uses one exported Panorama/FMT layer CSV as the authoritative manifest for rule names, rule order, disabled markers, and expected structure. It searches user-selected source ACPs for already-migrated rules with matching names, reports match quality and object/name deltas, then can create one new target ACP and copy selected FMC-native source rules into it in exact CSV order.

## What it does

- Parses one layer CSV and preserves rule order.
- Strips `[Disabled]` from rule names while preserving disabled state.
- Searches selected source ACPs for exact, case-insensitive, or normalized-whitespace rule-name matches.
- Compares duplicate source candidates by rule signature.
- Compares selected FMC rules to CSV expectations by human-readable names.
- Generates self-contained HTML, JSON, and CSV dry-run reports.
- On explicit commit, creates one new target ACP with default action `BLOCK`.
- Copies selected source access rules sequentially into the Mandatory section when supported by the FMC API.
- Re-fetches each source rule immediately before copying.

## What it does not do

- It does not translate PAN XML or CSV rows into FMC rule payloads.
- It does not remap objects, applications, URLs, zones, ports, or policies.
- It does not copy ACP-level settings.
- It does not copy Security Intelligence, identity, prefilter, decryption, device assignment, or deployment settings.
- It does not deploy.
- It does not assign the target ACP to devices.
- It does not delete, replace, append to, or suffix an existing target ACP.

This tool copies access rules only.

## Requirements

- Python 3.11 or newer recommended.
- Cisco FMC API access with permissions to read domains, ACPs, and access rules.
- Cisco FMC API access with permission to create ACPs and access rules for commit mode.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pip install -e .
```

## Running the app

```bash
streamlit run streamlit_app.py
```

Credentials are session-only. Passwords and FMC tokens are not persisted. The FMC host may remain in Streamlit session state during the local app session.

## Workflow

1. Connect to FMC with username/password.
2. Select a domain.
3. Load ACPs and select source ACPs in priority order.
4. Upload one layer CSV.
5. Review the parsed CSV summary and target ACP name.
6. Run `Analyze / Dry Run`.
7. Download and review the dry-run report.
8. Enable explicit commit confirmation only after blockers are resolved or intentionally overridden.
9. Commit to create the target ACP and copy rules.
10. Download the commit report.

## Dry-run behavior

Dry-run fetches source access rules, builds signatures, matches CSV rule names, detects missing rules and candidate conflicts, and generates reports under:

```text
reports/layer_composer/<timestamp>/
```

CSV-to-FMC structure differences are warnings by default. Source candidate signature differences block commit unless the override option is enabled.

## Commit behavior

Commit re-checks that the target ACP does not already exist, creates the target ACP only during commit, and copies rules one at a time in CSV order. Each source rule is re-fetched by ID immediately before copy, sanitized to remove FMC/server-managed fields, annotated with provenance in `newComments`, and posted to the target ACP Mandatory section when supported by the FMC API. The tool does not create custom rule categories or headers in v1.

By default, commit stops on the first create failure. It does not attempt rollback in v1.

## Reports

Dry-run and commit reports are self-contained HTML files with inline CSS and no CDN dependency. JSON and CSV companion files are also written for audit and spreadsheet review.

## SQLite cache

The project includes a simple SQLite cache helper for source snapshots, analysis plans, and commit results. SQLite is standard library based. The Streamlit v1 path keeps cache usage conservative and report-first.

## Diagnostics

`DiagnosticsLogger` writes JSONL diagnostic events with stage, severity, rule context, decision context, and optional API response fields. It never logs passwords or tokens.

## Safety notes

- Target ACP names are blocked if they already exist.
- Missing rules block commit unless `skip missing/unmatched rules` is enabled.
- Candidate signature deltas block commit unless the source-priority override is enabled.
- Duplicate CSV rule names block commit.
- The tool never deploys or assigns devices.

## Known limitations

- Access rules only.
- No batch mode.
- No offline mode.
- No fuzzy matching for commit.
- No per-rule manual conflict resolution beyond skip/priority behavior.
- No ACP-level setting copy in v1.

## Future enhancements

- Richer source inventory caching in the UI.
- Manual per-rule candidate resolution.
- More detailed FMC schema-aware payload validation.
- Optional batch processing once the single-layer workflow is proven.
