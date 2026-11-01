"""Offline scanner for likely secrets and personal data in Git repositories."""
import argparse
import json
import os
import re
import shutil
import shlex
import subprocess
import sys
from pathlib import Path

VERSION = "0.2.3"
LIMIT = 1_000_000
SKIP = {'.git', 'node_modules', 'dist', 'build', '.venv', 'venv', '__pycache__', '.idea', '.vscode'}

# Malaysian MyKad birthplace codes (state + overseas). Source: Jabatan Pendaftaran Negara
# state list https://www.jpn.gov.my/en/information/state-code/ and kod-negara for overseas births.
# Ranges kept here: 01-16, 21-59, 60-68, 71-72, 74-79, 82-93, 98, 99.
def _mykad_pb_codes():
    codes = set()
    for lo, hi in ((1, 16), (21, 59), (60, 68), (74, 79), (82, 93)):
        codes.update(f'{n:02d}' for n in range(lo, hi + 1))
    codes.update({'71', '72', '98', '99'})
    return frozenset(codes)


MYKAD_PB_CODES = _mykad_pb_codes()
_MYKAD_CONTEXT = re.compile(r'(?i)\b(?:mykad|nric|ic(?:\s*no(?:\.?|mber)?)?|malaysia(?:n)?\s+ic)\b')

RULES = [
    ('private_key', ('-----' + 'BEGIN' + ' (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----')),
    ('aws_access_key', r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    ('github_token', (r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|' + 'github' + '_pat_' + r'[A-Za-z0-9_]{20,})\b')),
    ('openai_api_key', (r'\b' + 'sk' + r'-(?:proj-)?[A-Za-z0-9_-]{24,}\b')),
    ('slack_token', (r'\b(?:' + 'xo' + 'x[baprs]-' + r'[A-Za-z0-9-]{12,}|' + 'xa' + 'pp-' + r'[A-Za-z0-9-]{12,})\b')),
    ('azure_connection_string', r'(?i)\b(?:AccountKey\s*=\s*[A-Za-z0-9+/=_-]{8,}|SharedAccessSignature\s*=\s*[^\s;]{8,})'),
    ('azure_shared_access_signature', r'(?i)\b(?:SharedAccessSignature\s+[A-Za-z0-9%&=;._+-]{12,}|sig=[A-Za-z0-9%._~-]{8,})'),
    ('generic_secret_assignment', r"""(?i)(?:^|[^A-Za-z0-9])["']?(?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|secret|password|passwd|token|client[_-]?secret)["']?\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{8,})"""),
    ('nric_fin', r'(?<![A-Za-z0-9])[STFGM]\d{7}[A-Z](?![A-Za-z0-9])'),
    ('mykad', r'(?<![A-Za-z0-9])(?:\d{6}-\d{2}-\d{4}|\d{12})(?![A-Za-z0-9])'),
    ('email_address', r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
    ('phone_number', r'(?<![\w-])(?:\+\d[\d .()\-]{8,}\d|\d[\d .()\-]{8,}\d)(?![\w-])'),
]


def valid_nric(value):
    weights = (2, 7, 6, 5, 4, 3, 2)
    prefix, digits, check = value[0], value[1:8], value[8]
    offset = 4 if prefix in 'TG' else 0
    letters = 'JZIHGFEDCBA' if prefix in 'ST' else 'XWUTRQPNMLK'
    return letters[(sum(int(d) * w for d, w in zip(digits, weights)) + offset) % 11] == check


def valid_mykad(value, line):
    """Accept dashed or 12-digit MyKad values with a real date and JPN birthplace code."""
    digits = value.replace('-', '')
    if len(digits) != 12 or not digits.isdigit():
        return False
    mm, dd = int(digits[2:4]), int(digits[4:6])
    pb = digits[6:8]
    if pb not in MYKAD_PB_CODES:
        return False
    if mm < 1 or mm > 12 or dd < 1 or dd > 31:
        return False
    # Reject obvious impossible days for short months without needing a full calendar year.
    if mm in (4, 6, 9, 11) and dd > 30:
        return False
    if mm == 2 and dd > 29:
        return False
    # Dashless form is quieter: need a nearby MyKad / IC context keyword on the line.
    if '-' not in value and not _MYKAD_CONTEXT.search(line):
        return False
    return True


def scan(text, name, rules=RULES, source='working-tree'):
    found = []
    for n, line in enumerate(text.splitlines(), 1):
        for label, pattern in rules:
            match = re.search(pattern, line)
            if not match:
                continue
            value = match.group()
            if label == 'phone_number' and (sum(c.isdigit() for c in value) < 10 or re.fullmatch(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', value)):
                continue
            if label == 'nric_fin' and not valid_nric(value):
                continue
            if label == 'mykad' and not valid_mykad(value, line):
                continue
            found.append((name, n, label, source))
    return found


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def get_root(path):
    r = git(path, 'rev-parse', '--show-toplevel')
    if r.returncode:
        raise ValueError('Git repository not found')
    return Path(os.fsdecode(r.stdout.strip()))


def is_text(data):
    return b'\0' not in data[:8192]


def skipped(name, skip=None):
    dirs = SKIP if skip is None else skip
    return any(part in dirs for part in Path(name).parts)


def working(root, rules, max_bytes=LIMIT, skip=None):
    r = git(root, 'ls-files', '--cached', '--others', '--exclude-standard', '-z')
    if r.returncode:
        raise ValueError('Could not list repository files')
    found = []
    for raw in r.stdout.split(b'\0'):
        if not raw:
            continue
        name = os.fsdecode(raw)
        if skipped(name, skip):
            continue
        p = root / name
        try:
            if p.stat().st_size > max_bytes:
                continue
            data = p.read_bytes()
        except OSError:
            continue
        if is_text(data):
            found += scan(data.decode('utf-8', 'replace'), name, rules)
    return found


def staged(root, rules, max_bytes=LIMIT, skip=None):
    r = git(root, 'diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z')
    if r.returncode:
        raise ValueError('Could not list staged files')
    found = []
    for raw in r.stdout.split(b'\0'):
        if not raw:
            continue
        name = os.fsdecode(raw)
        if skipped(name, skip):
            continue
        b = git(root, 'show', f':{name}')
        if not b.returncode and len(b.stdout) <= max_bytes and is_text(b.stdout):
            found += scan(b.stdout.decode('utf-8', 'replace'), name, rules, 'staged')
    return found


def history(root, rules, max_bytes=LIMIT, skip=None):
    r = git(root, 'rev-list', '--all')
    if r.returncode:
        raise ValueError('Could not read Git history')
    found = []
    for commit in r.stdout.decode('ascii', 'ignore').splitlines():
        tree = git(root, 'ls-tree', '-r', '--name-only', '-z', commit)
        for raw in tree.stdout.split(b'\0'):
            if not raw:
                continue
            name = os.fsdecode(raw)
            if skipped(name, skip):
                continue
            b = git(root, 'show', f'{commit}:{name}')
            if not b.returncode and len(b.stdout) <= max_bytes and is_text(b.stdout):
                found += scan(b.stdout.decode('utf-8', 'replace'), name, rules, f'history:{commit[:8]}')
    return found


def commit_range(root, revisions, rules, max_bytes=LIMIT, skip=None):
    """Scan all blobs in commits selected by a git revision expression."""
    r = git(root, 'rev-list', *revisions)
    if r.returncode:
        raise ValueError('Could not read pushed commit range')
    found = []
    for commit in r.stdout.decode('ascii', 'ignore').splitlines():
        tree = git(root, 'ls-tree', '-r', '--name-only', '-z', commit)
        if tree.returncode:
            continue
        for raw in tree.stdout.split(b'\0'):
            if not raw:
                continue
            name = os.fsdecode(raw)
            if skipped(name, skip):
                continue
            b = git(root, 'show', f'{commit}:{name}')
            if not b.returncode and len(b.stdout) <= max_bytes and is_text(b.stdout):
                found += scan(b.stdout.decode('utf-8', 'replace'), name, rules, f'push:{commit[:8]}')
    return found


def pre_push(root, rules, stream=None, max_bytes=LIMIT, skip=None):
    zeros = '0' * 40
    found = []
    for raw in (stream or sys.stdin).read().splitlines():
        fields = raw.split()
        if len(fields) != 4:
            continue
        _local_ref, local_sha, _remote_ref, remote_sha = fields
        if local_sha == zeros:
            continue
        if remote_sha != zeros:
            found += commit_range(root, [f'{remote_sha}..{local_sha}'], rules, max_bytes, skip)
        else:
            r = git(root, 'rev-list', local_sha, '--not', '--remotes')
            commits = r.stdout.decode('ascii', 'ignore').splitlines() if not r.returncode else []
            if not commits:
                found += commit_range(root, [local_sha], rules, max_bytes, skip)
            else:
                found += commit_range(root, [local_sha, '--not', '--remotes'], rules, max_bytes, skip)
    return found


def load_allowlist(path):
    """Read exact path:line:rule entries or glob-path:rule entries."""
    entries = []
    if not path.exists():
        return entries
    for number, raw in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        item = raw.strip()
        if not item or item.startswith('#'):
            continue
        parts = item.rsplit(':', 2)
        if len(parts) == 3 and parts[1].isdigit():
            entries.append(('exact', parts[0], int(parts[1]), parts[2]))
        else:
            parts = item.rsplit(':', 1)
            if len(parts) != 2 or not parts[0] or not parts[1]:
                raise ValueError(f'Invalid allowlist entry on line {number}')
            entries.append(('glob', parts[0], None, parts[1]))
    return entries


def is_allowed(finding, entries):
    name, line, rule, _source = finding
    return any((kind == 'exact' and name == path and line == ln and rule == label)
               or (kind == 'glob' and Path(name).match(path) and rule == label)
               for kind, path, ln, label in entries)


def install_hook(root, force=False):
    hooks = git(root, 'rev-parse', '--git-path', 'hooks/pre-push')
    if hooks.returncode:
        raise ValueError('Could not locate Git hooks directory')
    hook = Path(os.fsdecode(hooks.stdout.strip()))
    if not hook.is_absolute():
        hook = root / hook
    if hook.exists() and not force:
        raise ValueError('pre-push hook already exists; use --force to back it up and replace it')
    hook.parent.mkdir(parents=True, exist_ok=True)
    if hook.exists():
        backup = hook.with_name(hook.name + '.portfolioguard.bak')
        suffix = 1
        while backup.exists():
            backup = hook.with_name(hook.name + f'.portfolioguard.bak.{suffix}')
            suffix += 1
        shutil.copy2(hook, backup)
    script = Path(__file__).resolve()
    content = '#!/bin/sh\nexec ' + shlex.quote(str(sys.executable)) + ' ' + shlex.quote(str(script)) + ' --pre-push\n'
    hook.write_text(content, encoding='utf-8')
    hook.chmod(0o755)
    return hook


def main(argv=None):
    p = argparse.ArgumentParser(description='Offline scan for likely secrets and personal data.')
    p.add_argument('path', nargs='?', default='.')
    m = p.add_mutually_exclusive_group()
    m.add_argument('--staged', action='store_true')
    m.add_argument('--history', action='store_true')
    m.add_argument('--pre-push', action='store_true', help='Scan commits described on pre-push hook stdin')
    m.add_argument('--range', dest='revision_range', help='Scan commits in a Git revision range')
    p.add_argument('--rules', help='TOML additions: [[rules]] name/pattern')
    p.add_argument('--allowlist', help='Allowlist path (default: .portfolioguard-allowlist at repository root)')
    p.add_argument('--candidates', action='store_true', help='Print allowlist candidate lines (locations and rules only)')
    p.add_argument('--format', choices=('text', 'json'), default='text')
    p.add_argument('--install-hook', action='store_true', help='Install an offline commit-scan pre-push hook')
    p.add_argument('--force', action='store_true', help='Back up and replace an existing pre-push hook')
    p.add_argument('--max-bytes', type=int, default=None, help=f'Maximum file size to scan (default: {LIMIT} bytes, or max_file_bytes from portfolioguard.toml)')
    a = p.parse_args(argv)
    try:
        root = get_root(Path(a.path).resolve())
        if a.install_hook:
            hook = install_hook(root, a.force)
            print(f'Installed PortfolioGuard pre-push hook: {hook}')
            return 0
        rules = [(n, re.compile(x)) for n, x in RULES]
        config = Path(a.rules).resolve() if a.rules else (root / 'portfolioguard.toml' if (root / 'portfolioguard.toml').is_file() else Path(__file__).resolve().parent / 'portfolioguard.toml')
        if a.rules and not config.is_file():
            raise ValueError(f'Rules file not found: {config}')
        skip = None
        max_bytes = LIMIT
        if config.is_file():
            import tomllib
            with open(config, 'rb') as f:
                data = tomllib.load(f)
            rules += [(x['name'], re.compile(x['pattern'])) for x in data.get('rules', [])]
            if 'skip_dirs' in data:
                if not isinstance(data['skip_dirs'], list) or not all(isinstance(x, str) for x in data['skip_dirs']):
                    raise ValueError('skip_dirs must be a list of directory name strings')
                skip = set(data['skip_dirs'])
            if 'max_file_bytes' in data:
                max_bytes = int(data['max_file_bytes'])
        if a.max_bytes is not None:
            max_bytes = a.max_bytes
        if max_bytes < 0:
            raise ValueError('--max-bytes / max_file_bytes must be non-negative')
        found = pre_push(root, rules, max_bytes=max_bytes, skip=skip) if a.pre_push else commit_range(root, [a.revision_range], rules, max_bytes, skip) if a.revision_range else staged(root, rules, max_bytes, skip) if a.staged else history(root, rules, max_bytes, skip) if a.history else working(root, rules, max_bytes, skip)
        allow_path = Path(a.allowlist).resolve() if a.allowlist else root / '.portfolioguard-allowlist'
        allow_entries = load_allowlist(allow_path)
    except (OSError, ValueError, KeyError, re.error) as e:
        print(f'PortfolioGuard: {e}', file=sys.stderr)
        return 2
    allowed = [is_allowed(x, allow_entries) for x in found]
    if a.candidates:
        for name, line, rule, _source in found:
            print(f'{name}:{line}:{rule}')
    elif a.format == 'json':
        print(json.dumps([{'source': s, 'path': n, 'line': ln, 'rule': rule, 'allowed': ok}
                          for (n, ln, rule, s), ok in zip(found, allowed)], indent=2))
    else:
        for (name, line, rule, source), ok in zip(found, allowed):
            suffix = ' [allowed]' if ok else ''
            print(f'{source}: {name}:{line} [{rule}]{suffix}')
        if found:
            print(f'\nFound {sum(not x for x in allowed)} non-allowlisted issue(s) across {len(found)} finding(s). Review locally before sharing.')
        else:
            print('No configured patterns matched.')
    return 1 if any(not x for x in allowed) else 0


if __name__ == '__main__':
    raise SystemExit(main())
