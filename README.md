# PortfolioGuard

**Version: 0.2.2**: narrows Azure and NRIC/FIN matches, quotes hook paths safely, and applies configurable scan limits.

PortfolioGuard is an offline Python pre-push scanner for likely secrets and personal data in a Git repository. It scans files locally and reports locations and rule names only. matched text is never included in output. It helps with review but is **not a guarantee** that sensitive data will be found or that a clean scan means a repository is safe. PortfolioGuard is offline only and does not connect to a network.

## Requirements

Python 3.11+ and Git.

## Run a scan

Run the script by its local path from the repository you want to scan:
```sh
python /path/to/PortfolioGuard/portfolioguard.py .            # working tree
python /path/to/PortfolioGuard/portfolioguard.py . --staged    # staged contents
python /path/to/PortfolioGuard/portfolioguard.py . --history   # reachable Git history
python /path/to/PortfolioGuard/portfolioguard.py . --range BASE..HEAD # commits in a range
```

Working-tree mode checks tracked and untracked files not ignored by Git. Staged mode checks staged file contents. History mode checks files in every reachable commit and may take time on large repositories. Directories named `.git`, `node_modules`, `dist`, `build`, `.venv`, `venv`, `__pycache__`, `.idea` and `.vscode` are skipped in every scan mode. Binary files (identified by a null byte near the start) and files larger than 1 MB are also skipped. Set a different cap with `--max-bytes BYTES` (for example, `--max-bytes 2000000`). this applies to working-tree, staged, history, range and pre-push scans.

Exit codes: `0` means no non-allowlisted findings, `1` means one or more findings need review, and `2` means the scan or requested operation could not run.

## Allowlist

By default, `.portfolioguard-allowlist` in the repository root is loaded if present. Use `--allowlist PATH` to choose another file. Blank lines and lines beginning with `#` are ignored. Entries are either:

- Exact finding: `path:line:rule`, for example `src/example.txt:12:email_address`.
- Path glob plus rule: `path-pattern:rule`, for example `docs/*.md:email_address` (matches any line in matching paths).

Paths are relative to the repository root and use `/` separators. Rule names are the labels printed by PortfolioGuard. Review findings locally before adding entries. allowlisted findings do not cause exit code 1. This repository ships a `.portfolioguard-allowlist` that covers the deliberately fake fixtures in `test_portfolioguard.py` so a self-scan stays clean.

Use `--candidates` to print candidate entries from the current scan. This prints paths, line numbers and rule names only, never matched text:
```sh
python /path/to/PortfolioGuard/portfolioguard.py . --candidates
```

## Pre-push hook

From a Git repository, run:
```sh
python /path/to/PortfolioGuard/portfolioguard.py --install-hook
```

The installed hook reads Git's pre-push update records and scans the commits being pushed. For an existing remote ref it scans `remote_sha..local_sha`. for a new ref it scans commits reachable from the local tip that are not already on remote-tracking refs, falling back to the full reachable history if necessary. It stays offline and blocks a push when non-allowlisted findings remain. It does not depend on the staging area, which is normally empty after a commit. Existing hooks are preserved unless `--force` is supplied. `--force` backs up the previous hook beside it as `pre-push.portfolioguard.bak` (with a numeric suffix if needed) before replacement.

## JSON output

Use `--format json` for a JSON array containing `source`, `path`, `line`, `rule` and `allowed` fields. Matched text is never included.
```sh
python /path/to/PortfolioGuard/portfolioguard.py . --format json
```

## Custom rules

`portfolioguard.toml` may contain additive `[[rules]]` entries with `name` and regular-expression `pattern` fields. It is loaded automatically from the repository root, falling back to the directory containing `portfolioguard.py`. `--rules PATH` replaces that auto-selected file. built-in rules remain active in either case. Do not put real credentials or personal data in the config.

Built-in rules cover private keys, AWS and GitHub credentials, OpenAI `sk-` keys, Slack `xox…` and `xapp-` tokens, Azure account keys and shared access signatures, common secret assignments (including quoted JSON keys and compound environment names), email addresses, phone numbers and Singapore-style NRIC/FIN identifiers. Azure protocol-only documentation does not match. NRIC/FIN matches require valid checksums and standalone alphanumeric boundaries.

Version 0.2.2 also quotes interpreter and script paths in installed hooks, including paths containing spaces or quotes.

## Demo

The following uses deliberately fake fixture values:
```text
$ python portfolioguard.py .
working-tree: sample.txt:1 [generic_secret_assignment]
working-tree: sample.txt:2 [email_address]

Found 2 non-allowlisted issue(s) across 2 finding(s). Review locally before sharing.
$ echo $?
1
```

## Version history

See [CHANGELOG.md](CHANGELOG.md).