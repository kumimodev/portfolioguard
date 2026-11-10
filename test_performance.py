"""Performance guard: a 1MB hostile line must not slow any rule down.

Every built in rule and every drafts profile rule is run alone on a single 1,000,000
character line built from repeated hostile units (keywords, separator runs, prefixes
that almost match). Each run is a separate process with a 10 second limit, so a
quadratic or exponential regex fails the test instead of hanging CI. Healthy rules
finish in well under a second. The limit is 10 seconds, not less, so a slow runner
does not flake while the old quadratic matchers (tens of seconds) still fail.

A new rule without an entry in PAYLOADS fails test_every_rule_has_timing_payloads.
Set PG_PERF_REPORT=1 to print a timing table on stderr. PG_PERF_WORKERS (a whole number
of 1 or more, default 2) sets how many children run at once.
"""
import json
import os
import subprocess
import sys
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import portfolioguard

HERE = Path(__file__).resolve().parent
SIZE = 1_000_000
LIMIT_SECONDS = 10

# Kept in pieces so a source scan does not read the fixtures as credentials.
AWS_KEY = 'AK' + 'IA' + 'ABCDEFGHIJKLMNOP'
SLACK_BOT = 'xo' + 'xb-'
SLACK_APP = 'xa' + 'pp-'
STRIPE_LIVE = 'sk' + '_' + 'live' + '_'
OPENAI = 'sk' + '-'

# (mode, rule label) -> hostile units. A unit is repeated and cut to SIZE characters.
# mode builtin: portfolioguard.RULES. mode drafts: the opt-in profile. mode email_allowed:
# the email rule with allowed_email_values set, which uses a separate matcher path.
PAYLOADS = {
    ('builtin', 'private_key'): ['-----BEGIN RSA PRIVATE KEY', '-----BEGIN ', '-'],
    ('builtin', 'aws_access_key'): [AWS_KEY + ' ', 'AKIA', 'AKIA' + 'A' * 30],
    ('builtin', 'github_token'): ['ghp_' + 'a' * 19 + ' ', 'ghp_', 'github' + '_pat_', 'ghp_' + 'a' * 10000],
    ('builtin', 'openai_api_key'): [OPENAI + 'a' * 23 + ' ', OPENAI, OPENAI + 'proj-' + 'a' * 30000],
    ('builtin', 'slack_token'): [SLACK_BOT + 'a' * 11 + ' ', SLACK_BOT, SLACK_APP, SLACK_APP + '1-' * 20000],
    ('builtin', 'slack_webhook'): ['hooks.' + 'slack.com/services/T0/', 'hooks.' + 'slack.com/services/T' + 'A' * 20000],
    ('builtin', 'discord_bot_token'): ['M' + 'a' * 23 + '.' + 'b' * 6 + '.', 'M' + 'a' * 30000, 'M' + 'a' * 24 + '.bbbbbb.'],
    ('builtin', 'discord_webhook'): ['discord.com/api/webhooks/12345/', 'discord.com/api/webhooks/' + '1' * 30000],
    ('builtin', 'stripe_secret_key'): [STRIPE_LIVE + 'a' * 15 + ' ', STRIPE_LIVE, STRIPE_LIVE + 'a' * 30000],
    ('builtin', 'azure_connection_string'): ['AccountKey=', 'AccountKey = ', 'SharedAccessSignature=', 'AccountKey' + ' ' * 50000],
    ('builtin', 'azure_shared_access_signature'): ['SharedAccessSignature ', 'sig=', 'SharedAccessSignature ' + 'a' * 30000],
    ('builtin', 'generic_secret_assignment'): [
        'a-', 'a_', 'password=', 'token=a', 'secret=', 'xpassword=', 'xtoken=a', 'password=password=',
        'client_secret=', 'xclient_secret=', 'x-password-', 'a-api-key-', 'api_key', 'password: ', '"password"=',
        'password' + ' ' * 50000, 'password=' + 'a' * 50000],
    ('builtin', 'nric_fin'): ['S1234567 ', 'S1234567A', 'S' + '1' * 30000],
    ('builtin', 'mykad'): ['123456-12-123 ', '990101-01-123 ', '1' * 30000, '1234567890 '],
    ('builtin', 'email_address'): ['a.', 'a@', 'a@b ', 'a@b.', '@', 'a@a' + '.a' * 30000, '.', '-', 'a@b.c'],
    ('builtin', 'phone_number'): ['1 ', '1.', '+1234567 ', '12345678 ', '+' + '1' * 30000, '1' + ' ' * 30000,
                                  ' 1-', ' 123-', ' 123456789-', '1-1.'],
    ('email_allowed', 'email_address'): [
        'hello@example.test ', 'hello@example.test', 'hello@example.test.', 'a@b.cc ', '\u017f@k.io ', 'a.', '@'],
    ('drafts', 'private_ipv4'): ['10.0.0.', '192.168.', '172.16.', '10.0.0.1.', '1.', '10.'],
    ('drafts', 'cgnat_ipv4'): ['100.64.', '100.64.0.', '100.64.0.1.', '100.'],
    ('drafts', 'tailscale_hostname'): ['a.ts.net', 'a-a-a-', 'a.', 'ts.net', 'a' * 30000],
    ('drafts', 'mac_address'): ['aa:bb:cc:dd:ee:', 'aa-bb-', 'aa:bb:cc:dd:ee:ff:', 'aa:'],
    ('drafts', 'device_brand_model'): ['TP-Link', 'TL-A', 'TL-A1', 'Archer A', 'Archer ', 'RE', 'RE123', 'Orbi'],
    ('drafts', 'overclaim_word'): ['always ', 'cannot ', 'not always ', 'never fully ', '100% ', 'on the first try '],
}

# Whole CLI, drafts profile on, so every rule and the output code run on the same line.
END_TO_END = ['a.', 'password=', '@', '1 ', ' 1-', 'a-', 'hello@example.test ', '10.0.0.']

# Children end themselves a few seconds after the limit, so they cannot outlive a runner that was
# hard killed. faulthandler's watchdog is a C thread, so it still fires while a regex holds the GIL.
SELF_LIMIT_SECONDS = LIMIT_SECONDS + 5
WATCHDOG = f'''
import faulthandler
faulthandler.dump_traceback_later({SELF_LIMIT_SECONDS}, exit=True)
try:
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, ({SELF_LIMIT_SECONDS + 5}, {SELF_LIMIT_SECONDS + 5}))
except ImportError:
    pass
'''

# The job (mode, rule, unit, size) arrives as JSON on stdin, because a 60,000 character unit
# would break the 32,767 character command line limit on Windows.
CHILD = WATCHDOG + r'''
import json, sys, time
sys.path.insert(0, sys.argv[1])
import portfolioguard as pg
job = json.load(sys.stdin)
mode, label, unit, size = job['mode'], job['label'], job['unit'], job['size']
payload = (unit * (size // len(unit) + 1))[:size]
assert len(payload) == size
if mode == 'builtin':
    rules = [(n, p) for n, p in pg.RULES if n == label]
elif mode == 'drafts':
    rules = [(n, p) for n, p in pg.profile_rules(['drafts']) if n == label]
else:
    rules = [(label, pg.EmailPattern(['hello@example.test', 'a@b.cc']))]
assert len(rules) == 1, (mode, label)
start = time.perf_counter()
found = pg.scan(payload, 'perf', rules=rules)
print(json.dumps({'seconds': time.perf_counter() - start, 'findings': len(found)}))
'''

# Runs the real CLI under the same watchdog.
CLI_WRAPPER = WATCHDOG + '''
import runpy, sys
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name='__main__')
'''


def perf_workers():
    text = os.environ.get('PG_PERF_WORKERS', '2')
    try:
        value = int(text)
    except ValueError:
        value = 0
    if value < 1:
        raise ValueError(f'PG_PERF_WORKERS must be a whole number of 1 or more, got {text!r}')
    return value


def _run(job):
    mode, label, unit = job
    request = json.dumps({'mode': mode, 'label': label, 'unit': unit, 'size': SIZE})
    try:
        done = subprocess.run(
            [sys.executable, '-c', CHILD, str(HERE)], input=request,
            timeout=LIMIT_SECONDS, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except subprocess.TimeoutExpired:
        return job, None, f'no result inside {LIMIT_SECONDS}s'
    if done.returncode != 0:
        return job, None, done.stderr[-400:]
    return job, json.loads(done.stdout), None


def _show(unit):
    return repr(unit if len(unit) <= 24 else unit[:20] + '...')


class RuleTimingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        jobs = [(mode, label, unit) for (mode, label), units in PAYLOADS.items() for unit in units]
        workers = perf_workers()
        with ThreadPoolExecutor(max_workers=workers) as pool:
            cls.results = list(pool.map(_run, jobs))
        if os.environ.get('PG_PERF_REPORT'):
            print('\nmode, rule, unit, seconds', file=sys.stderr)
            for (mode, label, unit), data, error in cls.results:
                seconds = 'FAILED' if data is None else f'{data["seconds"]:.3f}'
                print(f'{mode}, {label}, {_show(unit)}, {seconds}', file=sys.stderr)

    def test_every_rule_has_timing_payloads(self):
        listed = {('builtin', name) for name, _ in portfolioguard.RULES}
        listed |= {('drafts', name) for name, _ in getattr(portfolioguard, 'DRAFT_RULES', [])}
        listed.add(('email_allowed', 'email_address'))
        self.assertEqual(sorted(listed - set(PAYLOADS)), [], 'add 1MB timing payloads for the new rule')
        self.assertEqual(sorted(set(PAYLOADS) - listed), [], 'payloads exist for a rule that is gone')
        for key, units in PAYLOADS.items():
            with self.subTest(key=key):
                self.assertGreaterEqual(len(units), 2)

    def test_every_rule_runs_in_time_on_one_megabyte_hostile_lines(self):
        for (mode, label, unit), data, error in self.results:
            with self.subTest(mode=mode, rule=label, unit=_show(unit)):
                self.assertIsNone(error, f'{label} {_show(unit)} failed on a 1MB line: {error}')
                self.assertLess(data['seconds'], LIMIT_SECONDS)

    def test_known_matches_are_still_found_on_one_megabyte_lines(self):
        # A guard that times a rule which silently stopped matching would prove nothing.
        found = {(m, l, u): d['findings'] for (m, l, u), d, e in self.results if d}
        needed = [('builtin', 'generic_secret_assignment', 'password='), ('builtin', 'generic_secret_assignment', 'xpassword='),
                  ('builtin', 'email_address', 'a@b.c'), ('builtin', 'email_address', 'a@a' + '.a' * 30000),
                  ('builtin', 'aws_access_key', AWS_KEY + ' '), ('drafts', 'private_ipv4', '10.0.0.1.'),
                  ('drafts', 'overclaim_word', 'always '), ('builtin', 'phone_number', '1-1.'),
                  ('builtin', 'phone_number', ' 1-')]
        self.assertEqual([k[:2] for k in needed if k not in found], [], 'these timing runs did not finish')
        self.assertEqual(found[('builtin', 'generic_secret_assignment', 'password=')], 1)
        self.assertEqual(found[('builtin', 'generic_secret_assignment', 'xpassword=')], 0)
        self.assertEqual(found[('builtin', 'email_address', 'a@b.c')], 1)
        self.assertEqual(found[('builtin', 'email_address', 'a@a' + '.a' * 30000)], 1)
        self.assertEqual(found[('builtin', 'aws_access_key', AWS_KEY + ' ')], 1)
        self.assertEqual(found[('drafts', 'private_ipv4', '10.0.0.1.')], 0)
        self.assertEqual(found[('drafts', 'overclaim_word', 'always ')], 1)
        self.assertEqual(found[('builtin', 'phone_number', '1-1.')], 1)
        self.assertEqual(found[('builtin', 'phone_number', ' 1-')], 0)


class EndToEndTimingTests(unittest.TestCase):
    def test_cli_with_the_drafts_profile_stays_fast_on_one_megabyte_lines(self):
        script = HERE / 'portfolioguard.py'
        for unit in END_TO_END:
            payload = (unit * (SIZE // len(unit) + 1))[:SIZE]
            with self.subTest(unit=_show(unit)):
                try:
                    done = subprocess.run(
                        [sys.executable, '-c', CLI_WRAPPER, str(script), '--stdin', '--max-bytes', str(SIZE),
                         '--profile', 'drafts'],
                        input=payload.encode(), timeout=LIMIT_SECONDS,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                except subprocess.TimeoutExpired:
                    self.fail(f'CLI took over {LIMIT_SECONDS}s on a 1MB {_show(unit)} line')
                self.assertIn(done.returncode, (0, 1), done.stderr[-300:])


class SettingsTests(unittest.TestCase):
    def test_worker_count_must_be_a_positive_whole_number(self):
        from unittest import mock
        for bad in ('0', '-1', 'two', ''):
            with self.subTest(value=bad), mock.patch.dict(os.environ, {'PG_PERF_WORKERS': bad}):
                with self.assertRaisesRegex(ValueError, 'PG_PERF_WORKERS must be a whole number of 1 or more'):
                    perf_workers()
        with mock.patch.dict(os.environ, {'PG_PERF_WORKERS': '3'}):
            self.assertEqual(perf_workers(), 3)

    def test_children_end_themselves_without_a_parent(self):
        # A child that would run for ever must stop on its own, so a hard killed runner leaves no orphan.
        code = WATCHDOG.replace(str(SELF_LIMIT_SECONDS), '1', 1) + 'while True:\n    pass\n'
        started = time.monotonic()
        done = subprocess.run([sys.executable, '-c', code], timeout=LIMIT_SECONDS,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(done.returncode, 0)
        self.assertLess(time.monotonic() - started, LIMIT_SECONDS)


if __name__ == '__main__':
    try:
        perf_workers()
    except ValueError as error:
        sys.exit(f'test_performance.py: {error}')
    unittest.main()
