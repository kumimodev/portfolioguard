# Changelog

## 0.2.1 (2026-11-01)
- Fixed the pre-push hook to scan commits being pushed, including new remote branches, instead of the usually empty post-commit index.
- Added range and pre-push commit scanning with history path filtering for skipped directories.
- Added OpenAI, Slack, Azure, JSON/compound assignment, and Singapore NRIC/FIN detection. reduced UUID phone-number false positives.
- Added automatic repository or script-adjacent TOML rule loading, with explicit `--rules` override.
- Expanded hook integration and rule tests. updated usage and exit-code documentation.

## 0.2.0 (2026-11-01)
- Added repo-local allowlisting, alternate allowlist paths, and redacted candidate output.
- Added offline staged-scan pre-push hook installation with safe refusal and forced backup.
- Added redacted JSON output and tightened phone-number matching.
- Added MIT licence and expanded usage, safety and version documentation.
- Added tests for allowlist behaviour, JSON redaction and hook installation.

## 0.1.0 (2026-10-24)
- Initial preview with offline working-tree, staged-file, and reachable-history scans.
- Added secret and personal-data patterns and custom TOML rules.
- Findings redact matching values.
- Added unit tests and usage documentation.
