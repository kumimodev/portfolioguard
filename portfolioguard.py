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

VERSION = "0.3.1"
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
    ('slack_webhook', (r'(?i)\b(?:https?://)?' + 'hooks.' + 'slack' + '.com/' + 'services/' + r'T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+\b')),
    ('discord_bot_token', r'(?<![A-Za-z0-9_-])[MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}(?![A-Za-z0-9_-])'),
    ('discord_webhook', (r'(?i)\b(?:https?://)?(?:' + 'discord' + r'(?:app)?\.com/api/webhooks/)\d{5,}/[A-Za-z0-9_-]{20,}\b')),
    ('stripe_secret_key', (r'\b(?:' + 'sk' + '_' + 'live' + '_|' + 'sk' + '_' + 'test' + '_|' + 'rk' + '_' + 'live' + '_|' + 'rk' + '_' + 'test' + r'_)[A-Za-z0-9]{16,}\b')),
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
            if label == 'phone_number':
                before = line[:match.start()]
                if re.search(r'(?i)urn:li:(?:activity|share):$', before):
                    continue
                if ('viewBox' in line and re.search(r'(?i)viewBox\s*=\s*["\'][^"\']*$', before)):
                    continue
                if re.search(r'(?i)\bd\s*=\s*["\'][^"\']*\b[MLHVCSQTAZ][^"\']*$', before):
                    continue
                if re.fullmatch(r'\s*[-+]?\d+(?:\.\d+)?(?:\s+[-+]?\d+(?:\.\d+)?){1,}', line.strip()):
                    continue
            if label == 'nric_fin' and not valid_nric(value):
                continue
            if label == 'mykad' and not valid_mykad(value, line):
                continue
            found.append((name, n, label, source))
    return found


def display_name(path):
    return os.path.normpath(str(path)).replace(os.sep, '/')


def skip_note(name, reason):
    print(f'PortfolioGuard: skipped {name} ({reason})', file=sys.stderr)


def read_text_file(path, name, max_bytes):
    """Return decoded text for an explicitly named file, or None after a stderr note."""
    try:
        if path.stat().st_size > max_bytes:
            skip_note(name, 'over size limit')
            return None
        data = path.read_bytes()
    except OSError:
        skip_note(name, 'unreadable')
        return None
    if not is_text(data):
        skip_note(name, 'binary')
        return None
    return data.decode('utf-8', 'replace')


def scan_paths(paths, rules, max_bytes=LIMIT, skip=None):
    """Scan files and directories without Git. Names are the paths as given, normalised."""
    dirs = SKIP if skip is None else skip
    found, seen = [], set()
    for arg in paths:
        top = Path(arg)
        if top.is_dir():
            for folder, subdirs, names in os.walk(top):
                subdirs[:] = sorted(d for d in subdirs if d not in dirs and not os.path.islink(os.path.join(folder, d)))
                for filename in sorted(names):
                    p = Path(folder, filename)
                    rel = p.relative_to(top)
                    if p.is_symlink() or skipped(rel, dirs):
                        continue
                    real = os.path.realpath(p)
                    if real in seen:
                        continue
                    seen.add(real)
                    try:
                        if p.stat().st_size > max_bytes:
                            continue
                        data = p.read_bytes()
                    except OSError:
                        continue
                    if is_text(data):
                        found += scan(data.decode('utf-8', 'replace'), display_name(p), rules, 'files')
        elif top.is_file():
            real = os.path.realpath(top)
            if real in seen:
                continue
            seen.add(real)
            name = display_name(top)
            text = read_text_file(top, name, max_bytes)
            if text is not None:
                found += scan(text, name, rules, 'files')
        elif top.exists():
            raise ValueError(f'Not a file or directory: {arg}')
        else:
            raise ValueError(f'Path not found: {arg}')
    return found


def scan_stdin(rules, name='<stdin>', max_bytes=LIMIT, stream=None):
    stream = stream or sys.stdin
    raw = getattr(stream, 'buffer', None)
    data = raw.read(max_bytes + 1) if raw else stream.read(max_bytes + 1).encode('utf-8')
    if len(data) > max_bytes:
        skip_note(name, 'over size limit')
        return []
    if not is_text(data):
        skip_note(name, 'binary')
        return []
    return scan(data.decode('utf-8', 'replace'), name, rules, 'stdin')


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def get_root(path):
    r = git(path, 'rev-parse', '--show-toplevel')
    if r.returncode:
        raise ValueError('Git repository not found (use --files PATH... or --stdin to scan outside a git repo)')
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


def _identity_allowed(email, name, expected):
    """True when email (and optional name) matches an expected identity entry."""
    email_l = email.lower()
    for entry in expected:
        if entry['email'].lower() != email_l:
            continue
        want_name = entry.get('name')
        if want_name is None or want_name == name:
            return True
    return False


def unexpected_commit_identities(root, expected):
    """Findings for history commits whose author or committer is outside expected.

    expected is a list of dicts with required 'email' and optional 'name'.
    Path encodes field:email so the unexpected address is visible in output.
    """
    if not expected:
        return []
    r = git(root, 'log', '--all', '--format=%H%x00%ae%x00%an%x00%ce%x00%cn')
    if r.returncode:
        raise ValueError('Could not read commit identities from Git history')
    found = []
    for line in r.stdout.decode('utf-8', 'replace').splitlines():
        parts = line.split('\0')
        if len(parts) != 5:
            continue
        commit, author_email, author_name, committer_email, committer_name = parts
        source = f'history:{commit[:8]}'
        if not _identity_allowed(author_email, author_name, expected):
            found.append((f'author:{author_email}', 1, 'unexpected-commit-identity', source))
        if not _identity_allowed(committer_email, committer_name, expected):
            found.append((f'committer:{committer_email}', 1, 'unexpected-commit-identity', source))
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
    p.add_argument('paths', nargs='*', metavar='path', help='Git repository to scan (default: .). With --files: files and directories to scan; - reads stdin')
    p.add_argument('--files', action='store_true', help='Scan the given files and directories without Git')
    p.add_argument('--stdin', action='store_true', help='Scan text from stdin without Git (same as a - path)')
    p.add_argument('--stdin-name', default='<stdin>', metavar='NAME', help='Name shown in findings for stdin (default: <stdin>)')
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
    p.add_argument('--expect-email', action='append', default=[], metavar='EMAIL',
                   help='In --history mode, allow this author/committer email (repeatable). Merges with expected_identities from config.')
    a = p.parse_args(argv)
    use_stdin = a.stdin or '-' in a.paths
    paths = [x for x in a.paths if x != '-']
    outside_git = a.files or use_stdin
    try:
        if outside_git:
            clashes = [flag for flag, on in (('--staged', a.staged), ('--history', a.history), ('--pre-push', a.pre_push),
                                             ('--range', a.revision_range), ('--install-hook', a.install_hook)) if on]
            if clashes:
                raise ValueError(f'--files / --stdin cannot be combined with {clashes[0]}')
            if not paths and not use_stdin:
                raise ValueError('--files needs at least one path (or --stdin / -)')
            root = Path.cwd()
        else:
            if len(paths) > 1:
                raise ValueError('Only one repository path is allowed (use --files to scan several paths)')
            root = get_root(Path(paths[0] if paths else '.').resolve())
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
        expected_identities = []
        allowed_email_values = []
        if config.is_file():
            import tomllib
            with open(config, 'rb') as f:
                data = tomllib.load(f)
            rules += [(x['name'], re.compile(x['pattern'])) for x in data.get('rules', [])]
            allowed_email_values = data.get('allowed_email_values', [])
            if not isinstance(allowed_email_values, list) or not all(isinstance(x, str) and re.fullmatch(r'[^@\s]+@[^@\s]+', x) for x in allowed_email_values):
                raise ValueError('allowed_email_values must be a list of email strings')
            if allowed_email_values:
                escaped = '|'.join(re.escape(x) for x in allowed_email_values)
                rules = [(n, re.compile(r'(?i)\b(?!(?:' + escaped + r')\b)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b') if n == 'email_address' else p) for n, p in rules]
            if 'skip_dirs' in data:
                if not isinstance(data['skip_dirs'], list) or not all(isinstance(x, str) for x in data['skip_dirs']):
                    raise ValueError('skip_dirs must be a list of directory name strings')
                skip = set(data['skip_dirs'])
            if 'max_file_bytes' in data:
                max_bytes = int(data['max_file_bytes'])
            if 'expected_identities' in data:
                raw_ids = data['expected_identities']
                if not isinstance(raw_ids, list):
                    raise ValueError('expected_identities must be a list of tables with email (and optional name)')
                for i, entry in enumerate(raw_ids):
                    if not isinstance(entry, dict) or 'email' not in entry or not isinstance(entry['email'], str) or not entry['email']:
                        raise ValueError(f'expected_identities[{i}] must be a table with a non-empty email string')
                    item = {'email': entry['email']}
                    if 'name' in entry:
                        if not isinstance(entry['name'], str) or not entry['name']:
                            raise ValueError(f'expected_identities[{i}].name must be a non-empty string when set')
                        item['name'] = entry['name']
                    expected_identities.append(item)
        for email in a.expect_email:
            expected_identities.append({'email': email})
        if a.max_bytes is not None:
            max_bytes = a.max_bytes
        if max_bytes < 0:
            raise ValueError('--max-bytes / max_file_bytes must be non-negative')
        if outside_git:
            found = scan_paths(paths, rules, max_bytes, skip)
            if use_stdin:
                found += scan_stdin(rules, a.stdin_name, max_bytes)
        else:
            found = pre_push(root, rules, max_bytes=max_bytes, skip=skip) if a.pre_push else commit_range(root, [a.revision_range], rules, max_bytes, skip) if a.revision_range else staged(root, rules, max_bytes, skip) if a.staged else history(root, rules, max_bytes, skip) if a.history else working(root, rules, max_bytes, skip)
        if a.history and expected_identities:
            found += unexpected_commit_identities(root, expected_identities)
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
