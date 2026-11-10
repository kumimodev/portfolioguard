"""Differential fuzz harness for the linear email and secret matchers.

The hand written matchers in portfolioguard.py replaced three regexes (email,
secret and phone number) that could take quadratic time. This script keeps the
old regexes as the reference and checks that each gives the same span on a
large, deterministic set of strings.
It also runs a mutation check: deliberately broken copies of the matchers must
be caught, which proves the fuzz run is able to see a wrong result.

Usage:
    python3 fuzz_regex.py                       CI sized run, a few seconds
    python3 fuzz_regex.py --count 400000        bigger local run
    PG_FUZZ_COUNT=400000 PG_FUZZ_SEED=7 python3 fuzz_regex.py

Exit status is 0 when every comparison agrees and every mutation is caught.
Only fake, generated strings are used. Nothing is read from disk but the scanner.
"""
import argparse
import itertools
import os
import random
import re
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'portfolioguard.py'
DEFAULT_COUNT = 15000
DEFAULT_SEED = 20261111

# Reference patterns, exactly as shipped before the linear rewrite.
OLD_SECRET = re.compile(
    r"""(?i)(?:^|[^A-Za-z0-9])["']?(?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|secret|password|passwd|token|client[_-]?secret)["']?\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{8,})""")
OLD_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
OLD_PHONE = re.compile(r'(?<![\w-])(?:\+\d[\d .()\-]{8,}\d|\d[\d .()\-]{8,}\d)(?![\w-])')
ALLOWED_SETS = (
    ['a@b.co'],
    ['x.y@ex.com', 'admin@example.test'],
    ['AB@C.DE'],
    ['hello@example.test', 'jane.doe@example.test', 'a+b@x.io'],
    ['\u00e9@x.com'],
    ['\u017f@x.com', '\u212a@x.com'],
)


def old_allowed_email(values):
    escaped = '|'.join(re.escape(x) for x in values)
    return re.compile(r'(?i)\b(?!(?:' + escaped + r')\b)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')


def load_module(source=None):
    """Execute portfolioguard.py (or a mutated copy of its text) as a private module."""
    text = SOURCE.read_text(encoding='utf-8') if source is None else source
    module = types.ModuleType('portfolioguard_under_fuzz')
    module.__file__ = str(SOURCE)
    exec(compile(text, str(SOURCE), 'exec'), module.__dict__)
    return module


# Each mutation breaks one detail of a matcher. The harness must notice every one.
# Entries are (description, family, source text to find, replacement).
MUTATIONS = (
    ('secret value run cache bound off by one', 'secret',
     'if run_lo <= val <= run_hi:', 'if run_lo <= val <= run_hi + 1:'),
    ('secret value run cache reused past the end of its run', 'secret',
     'if run_lo <= val <= run_hi:', 'if run_lo <= val:'),
    ('secret minimum value length 7 instead of 8', 'secret',
     'if j - val < 8:', 'if j - val < 7:'),
    ('email top level domain needs one letter instead of two', 'email',
     'if j - i - 1 >= 2 and', 'if j - i - 1 >= 1 and'),
    ('email domain scan reaches the at sign', 'email',
     'while i >= at + 2:', 'while i >= at + 1:'),
    ('phone start allowed one position too late', 'phone',
     'for p in range(a, end - 8):', 'for p in range(a, end - 7):'),
    ('phone end may be followed by a hyphen', 'phone',
     "_PHONE_GAP = frozenset(' .()')", "_PHONE_GAP = frozenset(' .()-')"),
    ('phone leading plus is taken after any character', 'phone',
     "line[a - 1] == '+' and (a == 1 or not (_is_word(line[a - 2]) or line[a - 2] == '-'))",
     "line[a - 1] == '+'"),
    ('phone start may follow a hyphen', 'phone',
     "(p == 0 or not (_is_word(line[p - 1]) or line[p - 1] == '-'))", "(p == 0 or not _is_word(line[p - 1]))"),
)


# Pieces for the generated strings. Spellings include the IGNORECASE folds
# that Python applies (long s, Kelvin sign, dotted and dotless i).
KEYWORDS = ['api_key', 'apikey', 'api-key', 'api key', 'secret', 'SECRET', 'Secret', 'password', 'PASSWORD', 'passwd',
            'token', 'TOKEN', 'client_secret', 'client-secret', 'clientsecret', 'Client_Secret', '\u017fecret',
            'tOken', 'toKen', 'token\u0130', 'passwor\u0131', 'pass', 'key', 'api', '_secret', '-token', 'secrets',
            'mytoken', 'my_password', 'x-api-key', 'DB_PASSWORD', 'sEcrEt', '\u212aey', 'toK\u212aen', 'pas\u017f']
SEPARATORS = ['=', ':', ' = ', ': ', '= ', ' :', '\t=', '=\t', '==', '=>', ' ', '', '"', "'", '"=', "='", "'='",
              '" : "', "':'", '\u00a0=', '\u2003=', '=\u2003', '\n', '=:', ':=', '_', '-', '--', '__']
VALUES = ['abcdefgh', 'abcdefg', 'a1b2c3d4e5', 'x' * 8, 'x' * 7, 'a.b/c+d=e-f_g', '12345678', 'secret=secret=',
          '\u00e91234567', 'abcdefg\u00e9', '\u017f' * 8, '\u212a' * 8, '\u0130' * 8, '\u0131' * 8, '"abcdefgh"',
          "'abcdefgh'", 'a' * 40, 'a b c d e f g h', '-' * 8 + ' ', '_' * 8, '.' * 8, '=' * 9, '+/+/+/+/']
PREFIXES = ['', 'x', 'x ', 'x_', 'x-', '_', '-', 'a_b_', 'a-b-', '1_', '"', "'", '"x_', "'x-", ' ', '  ', '\u00e9',
            '\u00e9_', '\u00e9-', 'x__', 'x--', 'x_-', '_-', '.', '(', '[', ',', 'a b-', '=', '"" ', '""', "''"]
SUFFIXES = ['', '"', "'", ' ', '\n', 'x', ';', ',', ' secret=abcdefgh', '\tpassword: 12345678', ' token=short']
NOISE = ['a', 'b', '_', '-', '=', ':', '"', "'", ' ', '.', '/', '+', '\u00e9', '\u017f', 'K', '\u0130', '\u0131', '1',
         'S', 'e', 'c', 'r', 't', 'T', 'O', 'k', 'n', 'p', 'w', 'd', '\t']


def secret_strings(rng, count):
    """Deterministic strings aimed at the secret matcher: structured, compound and random shapes."""
    for _ in range(count):
        kind = rng.random()
        if kind < 0.4:
            yield (rng.choice(PREFIXES) + rng.choice(KEYWORDS) + rng.choice(SEPARATORS)
                   + rng.choice(VALUES) + rng.choice(SUFFIXES))
        elif kind < 0.65:
            parts = []
            for _ in range(rng.randint(1, 6)):
                parts += [rng.choice(PREFIXES), rng.choice(KEYWORDS), rng.choice(['_', '-', '', '__', ' ', '--']),
                          rng.choice(KEYWORDS), rng.choice(SEPARATORS), rng.choice(VALUES), rng.choice(SUFFIXES)]
            yield ''.join(parts)
        elif kind < 0.85:
            yield ''.join(rng.choice(NOISE) for _ in range(rng.randint(0, 40)))
        else:
            word = rng.choice(KEYWORDS)
            yield (''.join(rng.choice(NOISE) for _ in range(rng.randint(0, 6))) + word
                   + ''.join(rng.choice(NOISE) for _ in range(rng.randint(0, 6)))
                   + rng.choice(VALUES)[:rng.randint(0, 12)])


EMAIL_NOISE = ['a', 'b', 'Z', '1', '0', '.', '-', '_', '%', '+', '@', '@', '@', 'c', 'o', 'm', 'x', ' ', '\u00e9',
               '\u00df', '\u03a9', '\u4e2d', '\u0301', '\u0663', '\u200d', 'K', '\u017f', '\u0130', '\u0131',
               '\u00a0', '\t', '/', ':', ',', '(', ')', '<', '>', 'E', 'COM', 'com', 'co', 'uk']
LOCAL = ['a', 'b', '.', '-', '_', '%', '+', '\u00e9', '1', 'Z', '\u4e2d', '\u0301', '\u0663', '\u00df', 'K', '\u017f']
DOMAIN = ['a', 'b', '.', '-', '\u00e9', '1', '\u4e2d', '_', 'Z', '\u0301', '\u017f', 'K']
TLDS = ['com', 'c', '', 'co.uk', '\u00e9', 'COM', 'c\u00f3m', 'co-op', 'c0m', '\u017fo', 'KO', 'com.', 'com-', 'com_',
        'com1', 'com\u00e9', 'com\u4e2d']
EMAIL_PRE = ['', '\u00e9', ' ', '.', 'x', '_', '\u4e2d', '\u0301', '(', '<', 'K']
EMAIL_POST = ['', ' ', '\u00e9', '.', 'a', '-', '_', '1', '\u4e2d', '\u0301', ',', '@', '@a.com']


def email_strings(rng, count):
    """Deterministic strings aimed at the email matcher, with unicode and boundary noise."""
    for _ in range(count):
        kind = rng.random()
        if kind < 0.15:
            yield ''.join(rng.choice(EMAIL_NOISE) for _ in range(rng.randint(0, 24)))
            continue
        text = (rng.choice(EMAIL_PRE) + ''.join(rng.choice(LOCAL) for _ in range(rng.randint(0, 6))) + '@'
                + ''.join(rng.choice(DOMAIN) for _ in range(rng.randint(0, 6))) + '.' + rng.choice(TLDS)
                + rng.choice(EMAIL_POST))
        if kind > 0.85:
            text += (rng.choice(EMAIL_PRE) + ''.join(rng.choice(LOCAL) for _ in range(rng.randint(0, 4))) + '@'
                     + ''.join(rng.choice(DOMAIN) for _ in range(rng.randint(0, 4))) + '.' + rng.choice(TLDS))
        yield text


PHONE_NOISE = ['0', '1', '1', '2', '9', '\u0663', '\uff11', '\u00b2', 'a', '_', '\u00e9', ' ', ' ', '.', '(', ')', '-',
               '-', '+', '+', 'x', '\u00a0', '\t', '/', ',']
PHONE_DIGITS = ['1', '2', '3', '\u0663', '\uff11']
PHONE_LEAD = ['', 'x', '+', 'x+', '-', '(', ' ', 'a ', '\u00e9', '_']
PHONE_TAIL = ['', 'x', '-', ' ', '.', '_', '\u00e9', '+', '1', '\u0663', '-1', ' a']
PHONE_EXTRA = ['', ' +4412345678901', ' 12345678901']


def phone_strings(rng, count):
    """Deterministic strings aimed at the phone matcher: separators, unicode digits, plus signs, hyphen tails."""
    for _ in range(count):
        kind = rng.random()
        if kind < 0.4:
            yield ''.join(rng.choice(PHONE_NOISE) for _ in range(rng.randint(0, 30)))
        elif kind < 0.7:
            body = ''.join(rng.choice(PHONE_DIGITS + [' ', '-', '.', '(', ')']) for _ in range(rng.randint(5, 24)))
            yield rng.choice(PHONE_LEAD) + body + rng.choice(PHONE_TAIL) + rng.choice(PHONE_EXTRA)
        else:
            parts = []
            for _ in range(rng.randint(1, 8)):
                parts.append(rng.choice(['+', '', 'x', '-', ' ', '  ', '('])
                             + ''.join(rng.choice('0123456789 -.()') for _ in range(rng.randint(1, 16)))
                             + rng.choice(['', ' ', '-', 'x', '_', '.']))
            yield ''.join(parts)


def short_phone_strings():
    """Every string up to six characters over five hostile characters, then up to 11 over digit, space and hyphen."""
    for length in range(7):
        for combo in itertools.product(['1', ' ', '-', '+', 'a'], repeat=length):
            yield ''.join(combo)
    for length in range(7, 12):
        for combo in itertools.product(['1', ' ', '-'], repeat=length):
            yield ''.join(combo)


def short_email_strings():
    """Every string up to five characters over a small hostile alphabet."""
    alphabet = ['a', '.', '@', '_', '\u00e9', '-', '\u4e2d', '\u0301', '1', '+', ' ', 'K']
    for length in range(6):
        for combo in itertools.product(alphabet, repeat=length):
            yield ''.join(combo)


def allowed_strings(rng, count, values):
    """Email strings that also embed the allowed values in odd cases and neighbours."""
    for text in email_strings(rng, count):
        yield text
    for value in values:
        for pre in ['', 'x', '.', '\u00e9', '\u4e2d', '_', '-', '(', ' ', '\u0301']:
            for post in ['', ' ', '.', '\u00e9', '-', '_', 'x', '\u0301', '\u4e2d', '.com', '@z.co']:
                for form in (value, value.upper(), value.title()):
                    yield pre + form + post
                    yield 'foo.' + pre + form + post
                    yield pre + form + post + ' ' + form


def _span(match):
    return None if match is None else (match.start(), match.end(), match.group())


class Report:
    def __init__(self, label):
        self.label = label
        self.checked = 0
        self.ref_hits = 0
        self.mismatches = []

    def line(self):
        return (f'{self.label}: {self.checked} strings, {self.ref_hits} with a reference match, '
                f'{len(self.mismatches)} mismatches')


def compare(label, reference, candidates, strings, stop_after=None):
    """Compare reference.search with every candidate.search on each string."""
    report = Report(label)
    for text in strings:
        want = _span(reference.search(text))
        report.checked += 1
        report.ref_hits += want is not None
        for got_fn in candidates:
            got = _span(got_fn(text))
            if got != want:
                report.mismatches.append((text, want, got))
                break
        if stop_after and len(report.mismatches) >= stop_after:
            break
    return report


def run_matchers(module, count, seed, stop_after=None, families=('secret', 'email', 'phone')):
    """Run the comparisons for one module. Returns a list of Report objects.

    Each family has its own random stream, so selecting a subset does not change the strings.
    """
    reports = []
    if 'secret' in families:
        rng = random.Random(f'{seed}:secret')
        secret = module.SecretPattern()
        reports.append(compare('generic_secret_assignment', OLD_SECRET,
                               [module.search_secret, secret.search], secret_strings(rng, count), stop_after))
    if 'email' in families:
        rng = random.Random(f'{seed}:email')
        default_email = module.EmailPattern()
        reports.append(compare('email_address default', OLD_EMAIL, [default_email.search],
                               itertools.chain(short_email_strings(), email_strings(rng, count)), stop_after))
        for values in ALLOWED_SETS:
            reports.append(compare(f'email_address allowed {values!r}', old_allowed_email(values),
                                   [module.EmailPattern(values).search],
                                   allowed_strings(rng, max(count // 6, 1), values), stop_after))
    if 'phone' in families:
        rng = random.Random(f'{seed}:phone')
        reports.append(compare('phone_number', OLD_PHONE, [module.search_phone, module.PhonePattern().search],
                               itertools.chain(short_phone_strings(), phone_strings(rng, count)), stop_after))
    return reports


def mutated_source(source, old, new):
    if source.count(old) != 1:
        raise SystemExit(f'mutation anchor not found exactly once, update MUTATIONS: {old!r}')
    return source.replace(old, new)


def run_mutation_check(count, seed):
    """Return a list of (name, caught, mismatches) for every deliberately broken copy."""
    base = SOURCE.read_text(encoding='utf-8')
    results = []
    for name, family, old, new in MUTATIONS:
        module = load_module(mutated_source(base, old, new))
        reports = run_matchers(module, count, seed, stop_after=3, families=(family,))
        bad = sum(len(r.mismatches) for r in reports)
        results.append((name, bad > 0, bad))
    return results


def _whole_number(name, minimum):
    def convert(text):
        try:
            value = int(text)
        except (TypeError, ValueError):
            raise argparse.ArgumentTypeError(f'{name} must be a whole number, got {text!r}')
        if value < minimum:
            raise argparse.ArgumentTypeError(f'{name} must be {minimum} or more, got {value}')
        return value
    return convert


def settings(argv=None):
    """Parse options. A bad value, including a bad environment variable, ends with a one line error and exit 2."""
    parser = argparse.ArgumentParser(description='Differential fuzz of the linear matchers against the old regexes.')
    parser.add_argument('--count', type=_whole_number('--count or PG_FUZZ_COUNT', 1),
                        default=os.environ.get('PG_FUZZ_COUNT', str(DEFAULT_COUNT)),
                        help='strings per family, 1 or more (env PG_FUZZ_COUNT, default %(default)s)')
    parser.add_argument('--seed', type=_whole_number('--seed or PG_FUZZ_SEED', 0),
                        default=os.environ.get('PG_FUZZ_SEED', str(DEFAULT_SEED)),
                        help='random seed, 0 or more (env PG_FUZZ_SEED, default %(default)s)')
    parser.add_argument('--no-mutation', action='store_true', help='skip the mutation check')
    return parser.parse_args(argv)


def main(argv=None):
    args = settings(argv)
    print(f'fuzz seed {args.seed}, {args.count} strings per family')
    failed = False
    for report in run_matchers(load_module(), args.count, args.seed):
        print(report.line())
        for text, want, got in report.mismatches[:5]:
            print('   ', ascii(text)[:100], want, got)
        failed = failed or bool(report.mismatches)
    if not args.no_mutation:
        for name, caught, bad in run_mutation_check(args.count, args.seed):
            print(f'mutation {"caught" if caught else "NOT CAUGHT"}: {name} ({bad} mismatches)')
            failed = failed or not caught
    print('FAIL' if failed else 'OK')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
