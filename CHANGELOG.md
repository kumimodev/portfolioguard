# Changelog

## 0.3.0, 1 Nov 2026
- Added a GitHub Action workflow that runs unit tests plus working tree and history scans on push and pull requests (covers setups where the pre-push hook never fires).
- Detect Malaysian MyKad numbers in dashed `YYMMDD-PB-####` or 12 digit form, with valid month/day and JPN birthplace codes. Dashless matches need a nearby IC or MyKad style keyword.
- Tightened Slack token matching and added Slack incoming webhooks, Discord bot tokens and webhook URLs, and Stripe secret or restricted keys (live and test).
- Expanded unit tests for the new rules (positives, invalid dates or PB codes, and digits inside longer numbers).
- Documented the Action, how to reuse it, and the new rules.


## 0.2.3, 1 Nov 2026
- Spelled out that skipped folders and over-size files are not scanned and can still go live (e.g. GitHub Pages serving `docs/`, `dist/` or `build/`).
- Optional `skip_dirs` and `max_file_bytes` in `portfolioguard.toml` if you need to scan those paths or raise the size cap. `--max-bytes` on the CLI still wins when you set it.


## 0.2.2, 1 Nov 2026
- Removed Azure protocol-only matches. Azure findings now require an account key or shared access signature fragment, including SAS URL signatures.
- Narrowed NRIC/FIN matching to standalone values and validate standard S/T/F/G/M checksums.
- Shell-quoted interpreter and script paths in installed hooks so paths containing spaces or quotes work.
- Lowered the default scan cap to 1 MB, added `--max-bytes`, and applied skipped-directory, size and binary-file checks across working-tree, staged, history, range and pre-push scans.
- Documented the scan limits and fixes. added focused rule and hook-quoting tests.

## 0.2.1, 1 Nov 2026
- Fixed the pre-push hook to scan commits being pushed, including new remote branches, instead of the usually empty post-commit index.
- Added range and pre-push commit scanning with history path filtering for skipped directories.
- Added OpenAI, Slack, Azure, JSON/compound assignment, and Singapore NRIC/FIN detection. reduced UUID phone-number false positives.
- Added automatic repository or script-adjacent TOML rule loading, with explicit `--rules` override.
- Expanded hook integration and rule tests. updated usage and exit-code documentation.

## 0.2.0, 1 Nov 2026
- Added repo-local allowlisting, alternate allowlist paths, and redacted candidate output.
- Added offline staged-scan pre-push hook installation with safe refusal and forced backup.
- Added redacted JSON output and tightened phone-number matching.
- Added MIT licence and expanded usage, safety and version documentation.
- Added tests for allowlist behaviour, JSON redaction and hook installation.

## 0.1.0, 24 Oct 2026
- Initial preview with offline working-tree, staged-file, and reachable-history scans.
- Added secret and personal-data patterns and custom TOML rules.
- Findings redact matching values.
- Added unit tests and usage documentation.
