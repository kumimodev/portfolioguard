"""Offline scanner for likely secrets and personal data in Git repositories."""
import argparse
import json
import os
import re
import shutil
import shlex
import stat
import subprocess
import sys
from pathlib import Path

VERSION = "0.3.1"
LIMIT = 1_000_000
EXIT_NOT_SCANNED = 3
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

# Linear stand-in for the old email regex r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'.
# Anchoring on '@' keeps the same hits and avoids a hang on a long dotted line with no '@'.
_EMAIL_LOCAL = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-')
_EMAIL_DOMAIN = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-')
_EMAIL_LETTER = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
_WORD_RE = re.compile(r'\w')
# Python re.IGNORECASE also folds these four onto ASCII s, k, i and i.
# allowed_email_values uses that flag, so the linear matcher follows it there.
_EMAIL_SPECIAL = frozenset('\u017f\u212a\u0130\u0131')
_EMAIL_FOLD = str.maketrans({
    '\u017f': 's',
    '\u212a': 'k',
    '\u0130': 'i',
    '\u0131': 'i',
})


def _fold_email(text):
    return text.translate(_EMAIL_FOLD).lower()


def _is_word(ch):
    return _WORD_RE.match(ch) is not None


def _is_boundary(line, i):
    """True if a regex \\b would match at index i, using Unicode word characters."""
    left = i > 0 and _is_word(line[i - 1])
    right = i < len(line) and _is_word(line[i])
    return left != right


class _EmailMatch:
    __slots__ = ('_text', '_start', '_end')

    def __init__(self, text, start, end):
        self._text, self._start, self._end = text, start, end

    def group(self, *args):
        return self._text

    def start(self, *args):
        return self._start

    def end(self, *args):
        return self._end


def search_email(line, begin=0, special=None):
    """First email in line at or after begin. Same hits as the old quadratic regex.

    special is an extra set of letters treated as local, domain and TLD
    characters. allowed_email_values passes _EMAIL_SPECIAL so the matcher
    follows the IGNORECASE folds of the previous regex.
    """
    if not special:
        special = frozenset()
    local = _EMAIL_LOCAL | special
    domain = _EMAIL_DOMAIN | special
    letter = _EMAIL_LETTER | special
    n = len(line)
    pos = begin
    while True:
        at = line.find('@', pos)
        if at < 0:
            return None
        if at == 0 or line[at - 1] not in local:
            pos = at + 1
            continue
        loc = at - 1
        while loc >= begin and line[loc] in local:
            loc -= 1
        loc += 1
        while loc < at and not _is_boundary(line, loc):
            loc += 1
        if loc >= at:
            pos = at + 1
            continue
        if at + 1 >= n or line[at + 1] not in domain:
            pos = at + 1
            continue
        run_end = at + 1
        while run_end < n and line[run_end] in domain:
            run_end += 1
        end = None
        i = run_end - 1
        while i >= at + 2:
            if line[i] == '.':
                j = i + 1
                while j < run_end and line[j] in letter:
                    j += 1
                if j - i - 1 >= 2 and _is_boundary(line, j):
                    end = j
                    break
            i -= 1
        if end is None:
            pos = at + 1
            continue
        return _EmailMatch(line[loc:end], loc, end)


class EmailPattern:
    """Linear matcher with the same hits as the old email_address regex.

    ignore is a list of exact, case insensitive values to skip, matching
    allowed_email_values: a hit is skipped when the allowed value sits at the
    start of the match and is followed by a word boundary.
    """

    def __init__(self, ignore=()):
        self.ignore = tuple(_fold_email(x) for x in ignore)
        self.special = _EMAIL_SPECIAL if self.ignore else frozenset()

    def search(self, line):
        begin = 0
        while True:
            match = search_email(line, begin, special=self.special)
            if match is None:
                return None
            start = match.start()
            if any(
                start + len(email) <= len(line)
                and _fold_email(line[start:start + len(email)]) == email
                and _is_boundary(line, start + len(email))
                for email in self.ignore
            ):
                begin = start + 1
                continue
            return match



_SECRET_KEYWORD_RE = re.compile(
    r'(?i)(?:api[_-]?key|secret|password|passwd|token|client[_-]?secret)')
_SECRET_SPACE_RE = re.compile(r'\s')
_SECRET_ALNUM = frozenset(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    '\u017f\u212a\u0130\u0131')
_SECRET_VALUE = _SECRET_ALNUM | frozenset('_./+=-')
_SECRET_QUOTE = frozenset('"\'')
_SECRET_JOINER = frozenset('_-')
_SECRET_ASSIGN = frozenset(':=')


def search_secret(line, begin=0):
    """First generic_secret_assignment hit at or after begin.

    Same spans as the old quadratic regex, including its IGNORECASE folds.
    """
    n = len(line)
    best = None
    pos = begin
    run_lo = run_hi = -1
    # Advance one character after each hit so a keyword can be found inside
    # a longer one, e.g. secret in xclient_secret=.
    while True:
        kw = _SECRET_KEYWORD_RE.search(line, pos)
        if kw is None:
            break
        k0, k1 = kw.start(), kw.end()
        pos = k0 + 1
        # A later keyword at or after the current hit's keyword end sits after
        # the assign character, so it cannot start earlier.
        if best is not None and k0 >= best[3]:
            break
        j = k1
        if j < n and line[j] in _SECRET_QUOTE:
            j += 1
        while j < n and _SECRET_SPACE_RE.match(line[j]):
            j += 1
        if j >= n or line[j] not in _SECRET_ASSIGN:
            continue
        j += 1
        while j < n and _SECRET_SPACE_RE.match(line[j]):
            j += 1
        if j < n and line[j] in _SECRET_QUOTE:
            j += 1
        val = j
        if run_lo <= val <= run_hi:
            j = run_hi
        else:
            while j < n and line[j] in _SECRET_VALUE:
                j += 1
            run_lo, run_hi = val, j
        if j - val < 8:
            continue
        end = j
        name_pos = k0
        while name_pos >= 2 and line[name_pos - 1] in _SECRET_JOINER and line[name_pos - 2] in _SECRET_ALNUM:
            name_pos -= 1
            name_pos -= 1
            while name_pos > 0 and line[name_pos - 1] in _SECRET_ALNUM:
                name_pos -= 1
        name_start = name_pos
        start = None
        if name_start >= 1 and line[name_start - 1] in _SECRET_QUOTE:
            if name_start - 1 == 0:
                start = 0
            elif line[name_start - 2] not in _SECRET_ALNUM:
                start = name_start - 2
        if start is None:
            if name_start == 0:
                start = 0
            elif line[name_start - 1] not in _SECRET_ALNUM:
                start = name_start - 1
            else:
                continue
        cand = (start, end, k0, k1)
        if best is None or cand[0] < best[0] or (cand[0] == best[0] and cand[2] > best[2]):
            best = cand
    if best is None:
        return None
    start, end = best[0], best[1]
    return _EmailMatch(line[start:end], start, end)


class SecretPattern:
    """Linear matcher with the same hits as the old generic_secret_assignment regex."""

    def search(self, line):
        return search_secret(line)



# Linear stand-in for the old phone regex
# r'(?<![\w-])(?:\+\d[\d .()\-]{8,}\d|\d[\d .()\-]{8,}\d)(?![\w-])'.
# The old pattern retried every digit start and backtracked over the whole run, which
# was quadratic on a line such as " 1-1-1-". Here each maximal run of phone
# characters is read once. Every start in a run shares the same best end, so only the
# first valid start and the last valid end of the run matter.
_PHONE_RUN_RE = re.compile(r'[\d .()\-]+')
_PHONE_GAP = frozenset(' .()')


def search_phone(line):
    """First phone number hit in line. Same spans as the old quadratic regex."""
    n = len(line)
    for run in _PHONE_RUN_RE.finditer(line):
        a, r = run.start(), run.end()
        if r - a < 10:
            continue
        # Largest end e: a digit that is followed by a gap character inside the run,
        # or that ends the run with a non word character (or the line end) after it.
        end = -1
        for e in range(r - 1, a + 8, -1):
            if not line[e].isdecimal():
                continue
            if e + 1 < r:
                if line[e + 1] in _PHONE_GAP:
                    end = e
                    break
            elif r >= n or not _is_word(line[r]):
                end = e
                break
        if end < 0:
            continue
        # First start: a digit whose previous character is not a word character or hyphen.
        for p in range(a, end - 8):
            if line[p].isdecimal() and (p == 0 or not (_is_word(line[p - 1]) or line[p - 1] == '-')):
                start = p
                break
        else:
            continue
        if start == a and a > 0 and line[a - 1] == '+' and (a == 1 or not (_is_word(line[a - 2]) or line[a - 2] == '-')):
            start = a - 1
        return _EmailMatch(line[start:end + 1], start, end + 1)
    return None


class PhonePattern:
    """Linear matcher with the same hits as the old phone_number regex."""

    def search(self, line):
        return search_phone(line)



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
    ('generic_secret_assignment', SecretPattern()),
    ('nric_fin', r'(?<![A-Za-z0-9])[STFGM]\d{7}[A-Z](?![A-Za-z0-9])'),
    ('mykad', r'(?<![A-Za-z0-9])(?:\d{6}-\d{2}-\d{4}|\d{12})(?![A-Za-z0-9])'),
    ('email_address', EmailPattern()),
    ('phone_number', PhonePattern()),
]


# Opt-in rule sets, switched on with --profile NAME or profile = ["NAME"] in portfolioguard.toml.
# They are meant for Markdown drafts and other copy that is about to go public. Default scans never use them.
_OCTET = r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
_IP_TAIL = r'\.' + _OCTET + r'\.' + _OCTET
_IP_END = r'(?!\d|\.\d)'
DRAFT_DEVICE_TERMS = ('TP-Link', 'Netgear', 'Linksys', 'D-Link', 'Tenda', 'MikroTik', 'Ubiquiti', 'UniFi', 'Eero', 'Orbi',
                      'Synology', 'QNAP')
DRAFT_OVERCLAIM_TERMS = ('cannot', 'guarantee', 'guarantees', 'guaranteed', 'secure', 'secured', 'secures', 'fully',
                         'always', 'completely', 'perfectly', 'impossible', 'bulletproof', 'foolproof', 'unhackable',
                         '100%', 'on the first try', 'on the first attempt')
DRAFT_RULES = [
    ('private_ipv4', r'(?<![\d.])(?:10' + _IP_TAIL + r'\.' + _OCTET + r'|172\.(?:1[6-9]|2\d|3[01])' + _IP_TAIL + r'|192\.168' + _IP_TAIL + r')' + _IP_END),
    ('cgnat_ipv4', r'(?<![\d.])100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])' + _IP_TAIL + _IP_END),
    ('tailscale_hostname', r'(?i)(?<![a-z0-9-])[a-z0-9-]+\.ts\.net\b'),
    ('mac_address', r'(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])'),
    ('device_brand_model', r'(?i)(?<![A-Za-z0-9])(?:' + '|'.join(re.escape(x) for x in DRAFT_DEVICE_TERMS)
     + r'|RE\d{3}[A-Z]?|Archer\s+[A-Z]{1,2}\d{2,4}|TL-[A-Z]{1,3}\d{3,4}[A-Z]*)(?![A-Za-z0-9])'),
    ('overclaim_word', r'(?i)(?<![A-Za-z0-9])(?:' + '|'.join(re.escape(x) for x in DRAFT_OVERCLAIM_TERMS) + r')(?![A-Za-z0-9])'),
]
_NEGATION = re.compile(r"(?i)(?:\bnot\b|\bno\b|\bnever\b|n't\b|\bwithout\b)")
# Rules that only warn: they are listed but never change the exit code.
WARNING_RULES = frozenset({'overclaim_word'})
PROFILES = {'drafts': DRAFT_RULES}


def profile_rules(names, extra=None):
    """Compiled rules for the named profiles. extra: {'device_terms': [...], 'overclaim_terms': [...]} from config."""
    extra = extra or {}
    rules = []
    for name in dict.fromkeys(names):
        for label, pattern in PROFILES[name]:
            terms = extra.get({'device_brand_model': 'device_terms', 'overclaim_word': 'overclaim_terms'}.get(label, ''), [])
            if terms:
                pattern = pattern[:-len(r')(?![A-Za-z0-9])')] + '|' + '|'.join(re.escape(x) for x in terms) + r')(?![A-Za-z0-9])'
            rules.append((label, re.compile(pattern)))
    return rules


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
            match = pattern.search(line) if hasattr(pattern, 'search') else re.search(pattern, line)
            if not match:
                continue
            if label == 'overclaim_word':
                # A hit with a negation just before it in the same clause ("not a guarantee", "never fully") is a disclaimer.
                match = next((m for m in re.finditer(pattern, line)
                              if not _NEGATION.search(re.split(r'[,;.:!?()]', line[max(0, m.start() - 24):m.start()])[-1])), None)
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


def clean_label(text):
    """Replace newlines and other control characters so a name cannot fake output lines."""
    return re.sub(r'[\x00-\x1f\x7f-\x9f]', '?', text)


def display_name(path):
    return clean_label(os.path.normpath(str(path)).replace(os.sep, '/'))


class Skips:
    """Inputs that were not scanned. Named ones are reported one by one, directory ones are counted."""

    def __init__(self, strict=False):
        self.named = []
        self.in_dirs = {}
        self.strict = strict

    @property
    def failing(self):
        """True when something was not scanned that must not read as clean."""
        return bool(self.named) or (self.strict and bool(self.in_dirs))

    def named_input(self, name, reason):
        self.named.append((name, reason))
        print(f'PortfolioGuard: skipped {name} ({reason})', file=sys.stderr)

    def in_dir(self, reason):
        self.in_dirs[reason] = self.in_dirs.get(reason, 0) + 1

    def summary(self):
        lines = []
        if self.named:
            lines.append(f'NOT SCANNED: {len(self.named)} named input(s) were skipped (see stderr). A clean result does not cover them.')
        if self.in_dirs:
            parts = ', '.join(f'{n} {why}' for why, n in sorted(self.in_dirs.items()))
            total = sum(self.in_dirs.values())
            if self.strict:
                lines.append(f'NOT SCANNED (--strict): {total} file(s) inside directories were skipped: {parts}. A clean result does not cover them.')
            else:
                lines.append(f'Skipped {total} file(s) inside directories: {parts}.')
        return lines


def read_text_file(path, name, max_bytes, skips):
    """Return decoded text for an explicitly named file, or None after recording the skip."""
    try:
        if path.stat().st_size > max_bytes:
            skips.named_input(name, 'over size limit')
            return None
        data = path.read_bytes()
    except OSError:
        skips.named_input(name, 'unreadable')
        return None
    if not is_text(data):
        skips.named_input(name, 'binary')
        return None
    return data.decode('utf-8', 'replace')


def scan_paths(paths, rules, max_bytes=LIMIT, skip=None, skips=None):
    """Scan files and directories without Git. Names are the paths as given, normalised."""
    dirs = SKIP if skip is None else skip
    skips = skips if skips is not None else Skips()
    found, seen = [], set()
    for arg in paths:
        top = Path(arg)
        if top.is_dir():
            for folder, subdirs, names in os.walk(top):
                subdirs[:] = sorted(d for d in subdirs if d not in dirs and not os.path.islink(os.path.join(folder, d)))
                for filename in sorted(names):
                    p = Path(folder, filename)
                    rel = p.relative_to(top)
                    try:
                        mode = p.lstat().st_mode
                    except OSError:
                        skips.in_dir('unreadable')
                        continue
                    if stat.S_ISLNK(mode) or skipped(rel, dirs):
                        continue
                    if not stat.S_ISREG(mode):
                        # FIFOs, sockets and devices can block forever on read, so never open them
                        skips.in_dir('not a regular file')
                        continue
                    real = os.path.realpath(p)
                    if real in seen:
                        continue
                    seen.add(real)
                    try:
                        if p.stat().st_size > max_bytes:
                            skips.in_dir('over size limit')
                            continue
                        data = p.read_bytes()
                    except OSError:
                        skips.in_dir('unreadable')
                        continue
                    if is_text(data):
                        found += scan(data.decode('utf-8', 'replace'), display_name(p), rules, 'files')
                    else:
                        skips.in_dir('binary')
        elif top.is_file():
            real = os.path.realpath(top)
            if real in seen:
                continue
            seen.add(real)
            name = display_name(top)
            text = read_text_file(top, name, max_bytes, skips)
            if text is not None:
                found += scan(text, name, rules, 'files')
        elif top.exists():
            raise ValueError(f'Not a file or directory: {clean_label(str(arg))}')
        else:
            raise ValueError(f'Path not found: {clean_label(str(arg))}')
    return found


def scan_stdin(rules, name='<stdin>', max_bytes=LIMIT, stream=None, skips=None):
    skips = skips if skips is not None else Skips()
    name = clean_label(name)
    stream = stream or sys.stdin
    if stream is None:
        raise ValueError('Standard input is closed, so there is nothing to scan')
    try:
        tty = stream.isatty()
    except ValueError:
        raise ValueError('Standard input is closed, so there is nothing to scan') from None
    if tty:
        print('PortfolioGuard: reading standard input, press Ctrl-D (Ctrl-Z then Enter on Windows) to finish', file=sys.stderr)
    raw = getattr(stream, 'buffer', None)
    data = raw.read(max_bytes + 1) if raw else stream.read(max_bytes + 1).encode('utf-8')
    if len(data) > max_bytes:
        skips.named_input(name, 'over size limit')
        return []
    if not is_text(data):
        skips.named_input(name, 'binary')
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
    p.add_argument('--strict', action='store_true', help='With --files/--stdin: files skipped inside directories (binary, over size, unreadable, special) also make the run exit 3')
    p.add_argument('--profile', action='append', default=[], choices=sorted(PROFILES), metavar='NAME',
                   help='Add an opt-in rule set (repeatable). Available: ' + ', '.join(sorted(PROFILES)) + '. Can also be set as profile = ["NAME"] in portfolioguard.toml')
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
            if a.strict:
                raise ValueError('--strict only applies to --files / --stdin')
            if len(paths) > 1:
                raise ValueError('Only one repository path is allowed (use --files to scan several paths)')
            root = get_root(Path(paths[0] if paths else '.').resolve())
        if a.install_hook:
            hook = install_hook(root, a.force)
            print(f'Installed PortfolioGuard pre-push hook: {hook}')
            return 0
        rules = [(n, x if hasattr(x, 'search') else re.compile(x)) for n, x in RULES]
        config = Path(a.rules).resolve() if a.rules else (root / 'portfolioguard.toml' if (root / 'portfolioguard.toml').is_file() else Path(__file__).resolve().parent / 'portfolioguard.toml')
        if a.rules and not config.is_file():
            raise ValueError(f'Rules file not found: {config}')
        skip = None
        max_bytes = LIMIT
        expected_identities = []
        allowed_email_values = []
        profiles = list(a.profile)
        drafts_cfg = {}
        if config.is_file():
            import tomllib
            with open(config, 'rb') as f:
                data = tomllib.load(f)
            rules += [(x['name'], re.compile(x['pattern'])) for x in data.get('rules', [])]
            cfg_profiles = data.get('profile', [])
            if not isinstance(cfg_profiles, list) or not all(isinstance(x, str) and x in PROFILES for x in cfg_profiles):
                raise ValueError('profile must be a list of known profile names: ' + ', '.join(sorted(PROFILES)))
            profiles += cfg_profiles
            drafts_cfg = data.get('drafts', {})
            if not isinstance(drafts_cfg, dict) or not all(k in ('device_terms', 'overclaim_terms') and isinstance(v, list)
                                                           and all(isinstance(t, str) and t for t in v) for k, v in drafts_cfg.items()):
                raise ValueError('[drafts] may only hold device_terms and overclaim_terms, each a list of non-empty strings')
            allowed_email_values = data.get('allowed_email_values', [])
            if not isinstance(allowed_email_values, list) or not all(isinstance(x, str) and re.fullmatch(r'[^@\s]+@[^@\s]+', x) for x in allowed_email_values):
                raise ValueError('allowed_email_values must be a list of email strings')
            if allowed_email_values:
                rules = [(n, EmailPattern(allowed_email_values) if n == 'email_address' else p) for n, p in rules]
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
        rules += profile_rules(profiles, drafts_cfg)
        for email in a.expect_email:
            expected_identities.append({'email': email})
        if a.max_bytes is not None:
            max_bytes = a.max_bytes
        if max_bytes < 0:
            raise ValueError('--max-bytes / max_file_bytes must be non-negative')
        skips = Skips(a.strict)
        if outside_git:
            found = scan_paths(paths, rules, max_bytes, skip, skips)
            if use_stdin:
                found += scan_stdin(rules, a.stdin_name, max_bytes, skips=skips)
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
    warned = [rule in WARNING_RULES and not ok for (_n, _l, rule, _s), ok in zip(found, allowed)]
    issues = sum(not ok and not w for ok, w in zip(allowed, warned))
    if a.candidates:
        for name, line, rule, _source in found:
            print(f'{name}:{line}:{rule}')
    elif a.format == 'json':
        rows = [{'source': s, 'path': n, 'line': ln, 'rule': rule, 'allowed': ok}
                for (n, ln, rule, s), ok in zip(found, allowed)]
        if profiles:
            for row, w in zip(rows, warned):
                row['warning'] = w
        print(json.dumps(rows, indent=2))
    else:
        for (name, line, rule, source), ok, w in zip(found, allowed, warned):
            suffix = ' [allowed]' if ok else ' [warning]' if w else ''
            print(f'{source}: {name}:{line} [{rule}]{suffix}')
        if found:
            print(f'\nFound {issues} non-allowlisted issue(s) across {len(found)} finding(s). Review locally before sharing.')
            if any(warned):
                print(f'{sum(warned)} warning(s) are word list hits to read, they do not change the exit code.')
        elif not skips.failing:
            print('No configured patterns matched.')
    # Skips only exist in files mode. In text mode they are part of the report, otherwise they go to stderr.
    for line in skips.summary():
        print(line, file=sys.stdout if not (a.candidates or a.format == 'json') else sys.stderr)
    if issues:
        return 1
    return EXIT_NOT_SCANNED if skips.failing else 0


if __name__ == '__main__':
    raise SystemExit(main())
