# Changelog

## 0.3.1, 1 Nov 2026
1. Ignore SVG coordinate data and LinkedIn activity or share URNs in phone number checks while keeping ordinary phone detection enabled.
2. Added exact, case insensitive `allowed_email_values` for intentional public contact addresses and documented the GitHub Pages visibility of committed allowlists.
3. Strengthened the clean exit guidance for private local allowlists and Pages publishes.
4. In `--history` mode, optional expected commit identities via `[[expected_identities]]` in `portfolioguard.toml` (email, optional name) or repeatable `--expect-email`.
5. Commits whose author or committer email sits outside that list are reported as `unexpected-commit-identity`, with the short hash, field and email in the finding.
6. Existing scans stay unchanged when the list is unset. Added unit tests that build temporary Git repos for matching, odd committer and odd author cases.

## Copy update, 1 Nov 2026

1. Opened up hyphenated wording in the README and older changelog lines.
2. Switched a couple of bullet lists to numbered lists and smoothed a few stiff sentences.

## 0.3.0, 1 Nov 2026
1. Added a GitHub Action workflow that runs unit tests plus working tree and history scans on push and pull requests (covers setups where the pre-push hook never fires).
2. Detect Malaysian MyKad numbers in dashed `YYMMDD-PB-####` or 12 digit form, with valid month/day and JPN birthplace codes. Dashless matches need a nearby IC or MyKad style keyword.
3. Tightened Slack token matching and added Slack incoming webhooks, Discord bot tokens and webhook URLs, and Stripe secret or restricted keys (live and test).
4. Expanded unit tests for the new rules (positives, invalid dates or PB codes, and digits inside longer numbers).
5. Documented the Action, how to reuse it, and the new rules.


## 0.2.3, 1 Nov 2026
1. Spelled out that skipped folders and over size files are not scanned and can still go live (for example GitHub Pages serving `docs/`, `dist/` or `build/`).
2. Optional `skip_dirs` and `max_file_bytes` in `portfolioguard.toml` if you need to scan those paths or raise the size cap. `--max-bytes` on the CLI still wins when you set it.


## 0.2.2, 1 Nov 2026
1. Removed Azure protocol only matches. Azure findings now require an account key or shared access signature fragment, including SAS URL signatures.
2. Narrowed NRIC/FIN matching to standalone values and validate standard S/T/F/G/M checksums.
3. Quoted the shell interpreter and script paths in installed hooks so paths containing spaces or quotes work.
4. Lowered the default scan cap to 1 MB, added `--max-bytes`, and applied skipped directory, size and binary file checks across working tree, staged, history, range and pre-push scans.
5. Documented the scan limits and fixes. Added focused rule and hook quoting tests.

## 0.2.1, 1 Nov 2026
1. Fixed the pre-push hook to scan commits being pushed, including new remote branches, instead of the usually empty post commit index.
2. Added range and pre-push commit scanning with history path filtering for skipped directories.
3. Added OpenAI, Slack, Azure, JSON/compound assignment, and Singapore NRIC/FIN detection. Reduced UUID phone number false positives.
4. Added automatic repository or script adjacent TOML rule loading, with explicit `--rules` override.
5. Expanded hook integration and rule tests. Updated usage and exit code documentation.

## 0.2.0, 1 Nov 2026
1. Added repo local allowlisting, alternate allowlist paths, and redacted candidate output.
2. Added offline staged scan pre-push hook installation with safe refusal and forced backup.
3. Added redacted JSON output and tightened phone number matching.
4. Added MIT licence and expanded usage, safety and version documentation.
5. Added tests for allowlist behaviour, JSON redaction and hook installation.

## 0.1.0, 24 Oct 2026
1. Initial preview with offline working tree, staged file, and reachable history scans.
2. Added secret and personal data patterns and custom TOML rules.
3. Findings redact matching values.
4. Added unit tests and usage documentation.
