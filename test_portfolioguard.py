import contextlib
import os
import io
import json
import re
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import shlex
from pathlib import Path

from portfolioguard import EmailPattern, PhonePattern, SecretPattern, install_hook, is_allowed, load_allowlist, main, profile_rules, scan


def run_git(root, *args, **kwargs):
    # Drop box/CI GIT_* identity overrides unless the caller passed env=
    # (history fixtures rely on repo user.* config, not ambient committer env).
    if 'env' not in kwargs:
        env = os.environ.copy()
        for key in list(env):
            if key.startswith(('GIT_AUTHOR_', 'GIT_COMMITTER_')):
                env.pop(key, None)
        kwargs['env'] = env
    return subprocess.run(['git', '-C', str(root), *args], check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, **kwargs)


class ScannerTests(unittest.TestCase):
    def test_secret_and_personal_data(self):
        got = {(x[1], x[2]) for x in scan('email=alex@example.test\npassword="test-secret-value"\nkey=' + 'AKIA' + 'EXAMPLEKEY123456', 'demo')}
        self.assertIn((1, 'email_address'), got)
        self.assertIn((2, 'generic_secret_assignment'), got)
        self.assertIn((3, 'aws_access_key'), got)

    def test_clean_text(self):
        self.assertEqual(scan('hello world', 'demo'), [])

    def test_phone_rule_requires_more_digits(self):
        self.assertEqual(scan('id=12345678', 'demo'), [])
        self.assertIn('phone_number', {x[2] for x in scan('Call +44 (20) 1234 5678', 'demo')})
        uuid_rules = {x[2] for x in scan('550e8400-e29b-41d4-a716-446655440000', 'demo')}
        self.assertNotIn('phone_number', uuid_rules)
        self.assertNotIn('slack_token', uuid_rules)

    def test_phone_svg_and_linkedin_context(self):
        samples = [
            'viewBox="39.20 39.20 921.60 921.60"',
            '<path d="M 123.45 678.90 L 987.65 432.10"/>',
            'Originally shared on LinkedIn urn:li:activity:7521137514804400128',
            'urn:li:share:7521137514804400128',
        ]
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertNotIn('phone_number', {x[2] for x in scan(sample, 'fixture.svg')})
        self.assertIn('phone_number', {x[2] for x in scan('Call +44 (20) 1234 5678', 'fixture.svg')})

    def test_configured_public_email_value_allow(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root / 'portfolioguard.toml').write_text('allowed_email_values = ["hello@kumimo.dev"]\n')
            (root / 'contacts.txt').write_text('hello@kumimo.dev\nprivate.person@gmail.com\n')
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([str(root)])
            self.assertEqual(code, 1)
            self.assertNotIn('hello@kumimo.dev', output.getvalue())
            self.assertIn('email_address', output.getvalue())

    def test_new_secret_rules(self):
        samples = [
            ('key=' + 'sk' + '-' + 'proj-' + 'EXAMPLEEXAMPLEEXAMPLEEXAMPLEexample', 'openai_api_key'),
            ('key=' + 'sk' + '-' + 'exampleexampleexampleexample1234', 'openai_api_key'),
            ('token=' + 'xox' + 'b-' + '123456789012-123456789012-EXAMPLEexampleExample12', 'slack_token'),
            ('token=' + 'xapp-' + '1-EXAMPLEEXAMPLEEX-abcdefgh', 'slack_token'),
            ('DefaultEndpointsProtocol=https;AccountName=examplestorage;AccountKey=EXAMPLEbase64+/key==;EndpointSuffix=core.windows.net', 'azure_connection_string'),
            ('{"password": "test-secret-value"}', 'generic_secret_assignment'),
            ('OPENAI_API_KEY=' + 'sk' + '-' + 'exampleexampleexampleexample1234', 'generic_secret_assignment'),
            ('slack_token=EXAMPLEfake-token-value', 'generic_secret_assignment'),
            ('S0000000J', 'nric_fin'),
            ('T0000000G', 'nric_fin'),
        ]
        for text, rule in samples:
            with self.subTest(rule=rule):
                self.assertIn(rule, {x[2] for x in scan(text, 'fixture')})

    def test_azure_requires_secret_fragment(self):
        self.assertEqual(scan('DefaultEndpointsProtocol=https;EndpointSuffix=core.windows.net', 'docs'), [])
        self.assertIn('azure_connection_string', {x[2] for x in scan('AccountKey=EXAMPLEbase64+/key==', 'fixture')})
        self.assertIn('azure_connection_string', {x[2] for x in scan('SharedAccessSignature=sv=2024&sig=EXAMPLEsigvalue123', 'fixture')})
        self.assertIn('azure_shared_access_signature', {x[2] for x in scan('https://example.test/?sig=EXAMPLEsignature123', 'fixture')})

    def test_nric_checksum_and_token_boundaries(self):
        self.assertIn('nric_fin', {x[2] for x in scan('S0000000J', 'fixture')})
        self.assertNotIn('nric_fin', {x[2] for x in scan('S1234567A', 'fixture')})
        for value in ('XS0000000J', 'S0000000JA', 'aS0000000J', 'S0000000Jf'):
            with self.subTest(value=value):
                self.assertNotIn('nric_fin', {x[2] for x in scan(value, 'fixture')})

    def test_toml_auto_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root / 'portfolioguard.toml').write_text('[[rules]]\nname="custom_marker"\npattern="CUSTOM-[0-9]{4}"\n')
            (root / 'sample.txt').write_text('CUSTOM-1234\n')
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([str(root)])
            self.assertEqual(code, 1)
            self.assertIn('[custom_marker]', output.getvalue())

    def test_allowlist_suppression(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / '.portfolioguard-allowlist'
            path.write_text('src/config.txt:4:generic_secret_assignment\nlogs/*.txt:email_address\n')
            entries = load_allowlist(path)
        self.assertTrue(is_allowed(('src/config.txt', 4, 'generic_secret_assignment', 'working-tree'), entries))
        self.assertTrue(is_allowed(('logs/demo.txt', 8, 'email_address', 'working-tree'), entries))
        self.assertFalse(is_allowed(('src/config.txt', 5, 'generic_secret_assignment', 'working-tree'), entries))

    def test_json_output_has_shape_and_no_matched_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root / 'sample.txt').write_text('password="test-secret-value"\nemail=alex@example.test\n')
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([str(root), '--format', 'json'])
            self.assertEqual(code, 1)
            data = json.loads(output.getvalue())
            self.assertEqual({(x['source'], x['path'], x['line'], x['rule']) for x in data}, {
                ('working-tree', 'sample.txt', 1, 'generic_secret_assignment'),
                ('working-tree', 'sample.txt', 2, 'email_address'),
            })
            self.assertTrue(all(x['allowed'] is False for x in data))
            self.assertNotIn('test-secret-value', output.getvalue())
            self.assertNotIn('alex@example.test', output.getvalue())

    def test_hook_install_refuses_and_backs_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            hook = root / '.git' / 'hooks' / 'pre-push'
            hook.write_text('#!/bin/sh\nexit 0\n')
            with self.assertRaises(ValueError):
                install_hook(root)
            install_hook(root, force=True)
            self.assertIn('--pre-push', hook.read_text())
            self.assertTrue((hook.parent / 'pre-push.portfolioguard.bak').exists())

    def test_hook_quotes_paths(self):
        with tempfile.TemporaryDirectory(prefix='portfolio guard ') as tmp:
            root = Path(tmp)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            interpreter = '/tmp/python "quoted" path/python3'
            with patch('portfolioguard.sys.executable', interpreter):
                hook = install_hook(root)
            body = hook.read_text()
            self.assertIn(shlex.quote(interpreter), body)
            self.assertIn(shlex.quote(str(Path(__file__).resolve().parent / 'portfolioguard.py')), body)

    def test_pre_push_blocks_committed_secret_and_allows_clean_push(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo, bare = base / 'repo', base / 'remote.git'
            subprocess.run(['git', 'init', '-q', str(repo)], check=True)
            subprocess.run(['git', 'init', '--bare', '-q', str(bare)], check=True)
            run_git(repo, 'config', 'user.email', 'fixture@example.test')
            run_git(repo, 'config', 'user.name', 'Fixture')
            run_git(repo, 'remote', 'add', 'origin', str(bare))
            install_hook(repo)
            (repo / 'clean.txt').write_text('clean baseline\n')
            run_git(repo, 'add', 'clean.txt')
            run_git(repo, 'commit', '-m', 'baseline')
            run_git(repo, 'push', '-u', 'origin', 'HEAD')
            baseline = run_git(repo, 'rev-parse', 'HEAD').stdout.decode().strip()
            (repo / 'config.txt').write_text('password="test-secret-value"\n')
            run_git(repo, 'add', 'config.txt')
            run_git(repo, 'commit', '-m', 'fake secret fixture')
            failed = subprocess.run(['git', '-C', str(repo), 'push', 'origin', 'HEAD'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(failed.returncode, 0)
            self.assertNotIn('test-secret-value', failed.stdout.decode() + failed.stderr.decode())
            remote_tip = subprocess.run(['git', '--git-dir', str(bare), 'rev-parse', 'refs/heads/master'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if remote_tip.returncode:
                remote_tip = subprocess.run(['git', '--git-dir', str(bare), 'rev-parse', 'refs/heads/main'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(remote_tip.stdout.decode().strip(), baseline)
            run_git(repo, 'reset', '--hard', baseline)
            (repo / 'safe.txt').write_text('clean follow-up\n')
            run_git(repo, 'add', 'safe.txt')
            run_git(repo, 'commit', '-m', 'clean commit')
            run_git(repo, 'push', 'origin', 'HEAD')

    def test_pre_push_new_branch_scans_unpublished_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo, bare = base / 'repo', base / 'remote.git'
            subprocess.run(['git', 'init', '-q', str(repo)], check=True)
            subprocess.run(['git', 'init', '--bare', '-q', str(bare)], check=True)
            run_git(repo, 'config', 'user.email', 'fixture@example.test')
            run_git(repo, 'config', 'user.name', 'Fixture')
            run_git(repo, 'remote', 'add', 'origin', str(bare))
            install_hook(repo)
            (repo / 'secret.txt').write_text('password="test-secret-value"\n')
            run_git(repo, 'add', 'secret.txt')
            run_git(repo, 'commit', '-m', 'new branch fake secret')
            run_git(repo, 'checkout', '-b', 'new-feature')
            result = subprocess.run(['git', '-C', str(repo), 'push', '-u', 'origin', 'new-feature'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('test-secret-value', result.stdout.decode() + result.stderr.decode())
            self.assertNotEqual(subprocess.run(['git', '--git-dir', str(bare), 'show-ref'], stdout=subprocess.PIPE).returncode, 0)

    def test_toml_skip_dirs_and_max_file_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root / 'dist').mkdir()
            (root / 'dist' / 'bundle.js').write_text('password="test-secret-value"\n')
            # Default skip would ignore dist/; override omits dist so the secret is found.
            (root / 'portfolioguard.toml').write_text(
                'skip_dirs = [".git", "node_modules", ".venv", "venv", "__pycache__", ".idea", ".vscode"]\n'
                'max_file_bytes = 50\n'
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([str(root)])
            self.assertEqual(code, 1)
            self.assertIn('dist/bundle.js', output.getvalue())
            # File larger than max_file_bytes is skipped even when not under a skipped dir.
            (root / 'big.txt').write_text(('password="another-secret-value"\n' + ('x' * 80)))
            output2 = io.StringIO()
            with contextlib.redirect_stdout(output2):
                code2 = main([str(root)])
            self.assertEqual(code2, 1)
            self.assertNotIn('big.txt', output2.getvalue())
            # CLI --max-bytes overrides toml and still finds the dist secret; raise enough for big.txt too.
            output3 = io.StringIO()
            with contextlib.redirect_stdout(output3):
                code3 = main([str(root), '--max-bytes', '1000'])
            self.assertEqual(code3, 1)
            self.assertIn('big.txt', output3.getvalue())

    def test_mykad_positive_and_negative(self):
        # Build fixtures from pieces so blobs never hold a full person-looking IC.
        dashed = '90' + '01' + '01' + '-' + '14' + '-' + '567' + '1'
        self.assertIn('mykad', {x[2] for x in scan('ic ' + dashed, 'fixture')})
        self.assertIn('mykad', {x[2] for x in scan(dashed, 'fixture')})
        compact = '90' + '01' + '01' + '14' + '567' + '1'
        self.assertIn('mykad', {x[2] for x in scan('MyKad ' + compact, 'fixture')})
        self.assertIn('mykad', {x[2] for x in scan('IC No: ' + compact, 'fixture')})
        # Dashless without context stays quiet.
        self.assertNotIn('mykad', {x[2] for x in scan(compact, 'fixture')})
        # Invalid month / day.
        bad_month = '90' + '13' + '01' + '-' + '14' + '-' + '567' + '1'
        bad_day = '90' + '01' + '32' + '-' + '14' + '-' + '567' + '1'
        bad_apr = '90' + '04' + '31' + '-' + '14' + '-' + '567' + '1'
        bad_feb = '90' + '02' + '30' + '-' + '14' + '-' + '567' + '1'
        for value in (bad_month, bad_day, bad_apr, bad_feb):
            with self.subTest(value=value):
                self.assertNotIn('mykad', {x[2] for x in scan(value, 'fixture')})
        # Invalid PB codes (17-20 and 00 are outside the JPN ranges we accept).
        bad_pb = '90' + '01' + '01' + '-' + '17' + '-' + '567' + '1'
        bad_pb0 = '90' + '01' + '01' + '-' + '00' + '-' + '567' + '1'
        self.assertNotIn('mykad', {x[2] for x in scan(bad_pb, 'fixture')})
        self.assertNotIn('mykad', {x[2] for x in scan(bad_pb0, 'fixture')})
        # Digits inside a longer number must not match.
        longer = '1' + '90' + '01' + '01' + '14' + '567' + '1' + '9'
        self.assertNotIn('mykad', {x[2] for x in scan('MyKad ' + longer, 'fixture')})
        longer_dashed = '9' + '90' + '01' + '01' + '-' + '14' + '-' + '567' + '1'
        self.assertNotIn('mykad', {x[2] for x in scan(longer_dashed, 'fixture')})

    def test_slack_discord_stripe_rules(self):
        slack_bot = 'xo' + 'xb-' + '123456789012-123456789012-EXAMPLEexampleExample12'
        slack_user = 'xo' + 'xp-' + '123456789012-123456789012-EXAMPLEexampleExample12'
        slack_app = 'xo' + 'xa-' + '123456789012-123456789012-EXAMPLEexampleExample12'
        slack_config = 'xo' + 'xr-' + '123456789012-123456789012-EXAMPLEexampleExample12'
        slack_session = 'xo' + 'xs-' + '123456789012-123456789012-EXAMPLEexampleExample12'
        slack_xapp = 'xa' + 'pp-' + '1-EXAMPLEEXAMPLEEX-abcdefgh'
        for token, rule in (
            (slack_bot, 'slack_token'),
            (slack_user, 'slack_token'),
            (slack_app, 'slack_token'),
            (slack_config, 'slack_token'),
            (slack_session, 'slack_token'),
            (slack_xapp, 'slack_token'),
        ):
            with self.subTest(token=token[:8]):
                self.assertIn(rule, {x[2] for x in scan('token=' + token, 'fixture')})

        slack_hook = 'https://' + 'hooks.' + 'slack' + '.com/' + 'services/' + 'T' + '00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'
        self.assertIn('slack_webhook', {x[2] for x in scan(slack_hook, 'fixture')})

        discord_token = 'M' + ('a' * 23) + '.' + ('b' * 6) + '.' + ('c' * 27)
        self.assertIn('discord_bot_token', {x[2] for x in scan('bot=' + discord_token, 'fixture')})
        discord_hook = 'https://' + 'discord' + '.com/api/webhooks/' + '1234567890123456789/' + ('a' * 40)
        discord_hook_app = 'https://' + 'discord' + 'app' + '.com/api/webhooks/' + '1234567890123456789/' + ('b' * 40)
        self.assertIn('discord_webhook', {x[2] for x in scan(discord_hook, 'fixture')})
        self.assertIn('discord_webhook', {x[2] for x in scan(discord_hook_app, 'fixture')})

        stripe_live = 'sk' + '_' + 'live' + '_' + ('A' * 24)
        stripe_test = 'sk' + '_' + 'test' + '_' + ('B' * 24)
        stripe_rk = 'rk' + '_' + 'live' + '_' + ('C' * 24)
        for key, rule in (
            (stripe_live, 'stripe_secret_key'),
            (stripe_test, 'stripe_secret_key'),
            (stripe_rk, 'stripe_secret_key'),
        ):
            with self.subTest(key=key[:10]):
                self.assertIn(rule, {x[2] for x in scan('key=' + key, 'fixture')})

        # Negatives: short / wrong prefix / embedded in longer token-like junk.
        self.assertNotIn('slack_token', {x[2] for x in scan('token=' + 'xo' + 'xb-short', 'fixture')})
        self.assertNotIn('stripe_secret_key', {x[2] for x in scan('key=' + 'sk' + '_' + 'live' + '_short', 'fixture')})
        self.assertNotIn('discord_bot_token', {x[2] for x in scan('bot=NotADiscordToken', 'fixture')})
        embedded = 'X' + 'xo' + 'xb-' + '123456789012-123456789012-EXAMPLEexampleExample12'
        # Leading word char should fail the \b on slack_token.
        self.assertNotIn('slack_token', {x[2] for x in scan(embedded, 'fixture')})


    def test_history_expected_identities_all_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            run_git(root, 'config', 'user.email', 'dev@example.com')
            run_git(root, 'config', 'user.name', 'Dev Example')
            (root / 'readme.txt').write_text('clean baseline\n')
            run_git(root, 'add', 'readme.txt')
            run_git(root, 'commit', '-m', 'baseline')
            (root / 'portfolioguard.toml').write_text(
                '[[expected_identities]]\n'
                'email = "dev@example.com"\n'
                'name = "Dev Example"\n'
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([str(root), '--history'])
            self.assertEqual(code, 0)
            self.assertNotIn('unexpected-commit-identity', output.getvalue())

    def test_history_unexpected_committer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root / 'readme.txt').write_text('clean baseline\n')
            run_git(root, 'add', 'readme.txt')
            env = os.environ.copy()
            env.update({
                'GIT_AUTHOR_NAME': 'Dev Example',
                'GIT_AUTHOR_EMAIL': 'dev@example.com',
                'GIT_COMMITTER_NAME': 'Other Person',
                'GIT_COMMITTER_EMAIL': 'other@example.com',
            })
            run_git(root, 'commit', '-m', 'mixed identities', env=env)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([str(root), '--history', '--expect-email', 'dev@example.com'])
            self.assertEqual(code, 1)
            body = output.getvalue()
            self.assertIn('unexpected-commit-identity', body)
            self.assertIn('committer:other@example.com', body)
            self.assertNotIn('author:dev@example.com', body)

    def test_history_unexpected_author(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root / 'readme.txt').write_text('clean baseline\n')
            run_git(root, 'add', 'readme.txt')
            env = os.environ.copy()
            env.update({
                'GIT_AUTHOR_NAME': 'Odd Author',
                'GIT_AUTHOR_EMAIL': 'odd@example.com',
                'GIT_COMMITTER_NAME': 'Dev Example',
                'GIT_COMMITTER_EMAIL': 'dev@example.com',
            })
            run_git(root, 'commit', '-m', 'odd author', env=env)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([str(root), '--history', '--expect-email', 'dev@example.com'])
            self.assertEqual(code, 1)
            body = output.getvalue()
            self.assertIn('unexpected-commit-identity', body)
            self.assertIn('author:odd@example.com', body)
            self.assertNotIn('committer:dev@example.com', body)


class EmailAddressTests(unittest.TestCase):
    def test_default_email_rule_one_megabyte_dotted_line_does_not_hang(self):
        # Regression for a quadratic email_address pattern on a long dotted line with no @.
        payload = 'a.' * 500000
        self.assertEqual(len(payload), 1_000_000)
        script = Path(__file__).resolve().parent / 'portfolioguard.py'
        try:
            done = subprocess.run(
                [sys.executable, str(script), '--stdin', '--max-bytes', '1000000'],
                input=payload.encode(), timeout=5,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        except subprocess.TimeoutExpired:
            self.fail('default email rule hung on a 1MB dotted line')
        self.assertEqual(done.returncode, 0)
        self.assertNotIn(b'[', done.stdout)

    def test_email_address_matches_legacy_pattern(self):
        legacy = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
        pat = EmailPattern()
        samples = [
            'a@b@c.com', 'user@foo.bar.com', 'user@foo.com.', 'user@foo.com_x',
            '...user@host.com', '-user@host.com', '_user@host.com', '%user@host.com',
            'a.@host.com', '!.@host.com', 'user@.com', 'user@localhost', 'user@foo.c',
            'user@foo.com2', 'user@127.0.0.1', 'User@Foo.COM', 'user@foo.bar-baz',
            'user@host.comx', 'éuser@host.com', 'user@host.comé', 'α.c6+.@ymZcq3f4.yOZ',
            'H%zHi7Grt@vP.ofGa', 'hello@kumimo.dev.evil@x.com', 'mailto:user@host.com',
        ]
        for text in samples:
            with self.subTest(text=text):
                old, new = legacy.search(text), pat.search(text)
                self.assertEqual(
                    None if old is None else (old.group(), old.start(), old.end()),
                    None if new is None else (new.group(), new.start(), new.end()),
                )

    def test_allowed_email_values_keep_legacy_skip_behaviour(self):
        legacy = re.compile(
            r'(?i)\b(?!(?:hello@example.test)\b)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
        pat = EmailPattern(['hello@example.test'])
        samples = [
            'hello@example.test', 'HELLO@EXAMPLE.TEST',
            'hello@example.test private.person@gmail.com',
            'hello@example.test.evil@x.com', 'xhello@example.test',
            'hello@example.te\u017ft', 'hello@example.te\u0131est',
            '\u017fello@example.test', 'hello@example.te\u212at',
        ]
        for text in samples:
            with self.subTest(text=text):
                old, new = legacy.search(text), pat.search(text)
                self.assertEqual(
                    None if old is None else (old.group(), old.start(), old.end()),
                    None if new is None else (new.group(), new.start(), new.end()),
                )

    def test_allowed_email_values_one_megabyte_line_does_not_hang(self):
        # Regression for quadratic allowed-value skipping on a long line of repeats.
        unit = 'hello@example.test '
        payload = (unit * 52632)[:1_000_000]
        self.assertEqual(len(payload), 1_000_000)
        script = Path(__file__).resolve().parent / 'portfolioguard.py'
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / 'rules.toml'
            rules.write_text('allowed_email_values = ["hello@example.test"]\n')
            try:
                done = subprocess.run(
                    [sys.executable, str(script), '--stdin', '--rules', str(rules),
                     '--max-bytes', '1000000'],
                    input=payload.encode(), timeout=5,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
            except subprocess.TimeoutExpired:
                self.fail('allowed email rule hung on a 1MB repeated address line')
        self.assertEqual(done.returncode, 0)
        self.assertNotIn(b'[', done.stdout)


class GenericSecretTests(unittest.TestCase):
    LEGACY = re.compile(
        r"""(?i)(?:^|[^A-Za-z0-9])["']?(?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|secret|password|passwd|token|client[_-]?secret)["']?\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{8,})""")

    def _span(self, match):
        return None if match is None else (match.group(), match.start(), match.end())

    def test_generic_secret_matches_legacy_pattern(self):
        pat = SecretPattern()
        samples = [
            '{"password": "test-secret-value"}',
            'OPENAI_API_KEY=sk-exampleexampleexampleexample1234',
            'slack_token=EXAMPLEfake-token-value',
            '  token=12345678',
            'tokenizer=abcdefgh',
            'secretive=abcdefgh',
            'password1=abcdefgh',
            'xpassword=abcdefgh',
            'api_key==abcdefgh',
            'token = : abcdefgh',
            'password="abcdefghijkl"',
            'x"token"=abcdefgh',
            ' {"password":"abcdefgh"}',
            'foo=password=abcdefgh',
            'my__token=abcdefgh',
            'my_-token=abcdefgh',
            'my-_token=abcdefgh',
            '_token=abcdefgh',
            '-token=abcdefgh',
            '9token=abcdefgh',
            'a_token=abcdefgh',
            'a9_token=abcdefgh',
            'passwordpassword=abcdefgh',
            'secret_token=abcdefghijkl',
            'token secret=abcdefgh',
            'api_key_token=abcdefgh',
            'my_token_password=abcdefgh',
            'xclient_secret=abcdefgh',
            'client_secret_api_key=abcdefgh',
            'client_secret_token=abcdefgh',
            'clientsecret=abcdefgh',
            'api-key=abcdefgh',
            'apikey=abcdefgh',
            'passwd=abcdefgh',
            'password=abcdefg',
            'TOKEN=abcdefgh',
            'foo_TOKEN=abcdefgh',
            'foo_"token"=abcdefgh',
            '"foo_token"=abcdefgh',
            "x 'api_key' = abcdefgh",
            'password=abcdefgh leftover',
            'password=abcdefgh=xyz',
            "password=''abcdefgh",
            'password=""abcdefgh',
            'password=  abcdefgh',
            'password =abcdefgh',
            'password: abcdefgh',
            "password :'abcdefgh",
            'export TOKEN="abcdefgh"',
            'token-value=abcdefgh',
            'notasecret=abcdefgh',
            'the_secret=abcdefgh',
            'a-a-a-a-a-token=abcdefgh',
            'a_a_a_a_a_token=abcdefgh',
            '\u017fecret=abcdefgh',
            'pa\u017fsword=abcdefgh',
            'to\u212aen=abcdefgh',
            'api_\u212aey=abcdefgh',
            'password=\u00a0abcdefgh',
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertEqual(self._span(self.LEGACY.search(text)), self._span(pat.search(text)))

    def test_generic_secret_one_megabyte_hyphen_line_does_not_hang(self):
        # Regression for a quadratic generic_secret_assignment pattern on a long
        # hyphen or underscore run.
        script = Path(__file__).resolve().parent / 'portfolioguard.py'
        for unit in ('a-', 'a_'):
            payload = unit * 500000
            self.assertEqual(len(payload), 1_000_000)
            with self.subTest(unit=unit):
                try:
                    done = subprocess.run(
                        [sys.executable, str(script), '--stdin', '--max-bytes', '1000000'],
                        input=payload.encode(), timeout=5,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    )
                except subprocess.TimeoutExpired:
                    self.fail(f'generic_secret rule hung on a 1MB {unit!r} line')
                self.assertEqual(done.returncode, 0)
                self.assertNotIn(b'[', done.stdout)

    def test_generic_secret_one_megabyte_keyword_repeats_do_not_hang(self):
        # Regression for a quadratic value-run rescan on repeated keywords.
        script = Path(__file__).resolve().parent / 'portfolioguard.py'
        cases = (
            ('password=', 1, True),
            ('token=a', 1, True),
            ('xpassword=', 0, False),
        )
        for unit, code, expect_hit in cases:
            payload = (unit * (1_000_000 // len(unit) + 1))[:1_000_000]
            self.assertEqual(len(payload), 1_000_000)
            with self.subTest(unit=unit):
                try:
                    done = subprocess.run(
                        [sys.executable, str(script), '--stdin', '--max-bytes', '1000000'],
                        input=payload.encode(), timeout=5,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    )
                except subprocess.TimeoutExpired:
                    self.fail(f'generic_secret rule hung on a 1MB {unit!r} line')
                self.assertEqual(done.returncode, code)
                if expect_hit:
                    self.assertIn(b'[generic_secret_assignment]', done.stdout)
                else:
                    self.assertNotIn(b'[', done.stdout)


AWS_LINE = 'key=' + 'AKIA' + 'EXAMPLEKEY123456'
MAIL_LINE = 'contact=' + 'alex' + '@' + 'example.test'
LEAKY = 'clean intro\n' + MAIL_LINE + '\n' + AWS_LINE + '\n'


def run_cli(args, stdin=None, cwd=None):
    """Run main() and return (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    old = os.getcwd()
    stream = io.TextIOWrapper(io.BytesIO(stdin if isinstance(stdin, bytes) else (stdin or '').encode()), encoding='utf-8')
    try:
        if cwd:
            os.chdir(cwd)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), patch('sys.stdin', stream):
            code = main(args)
    finally:
        os.chdir(old)
    return code, out.getvalue(), err.getvalue()


class PhoneNumberTests(unittest.TestCase):
    LEGACY = re.compile(r'(?<![\w-])(?:\+\d[\d .()\-]{8,}\d|\d[\d .()\-]{8,}\d)(?![\w-])')

    def _span(self, match):
        return None if match is None else (match.start(), match.end(), match.group())

    def test_phone_matches_legacy_pattern(self):
        pat = PhonePattern()
        samples = [
            'Call +44 (20) 1234 5678', 'Call +44 (20) 1234 5678.', 'x+1234567890', ' +1234567890', '+1234567890',
            '1234567890', '123456789', '12345678-', '1234567890-', '1234567890 -', '-1234567890', 'a1234567890',
            '1234567890a', '1234567890_', '1234567890\u00e9', '+ 1234567890', '++1234567890', '12 34 56 78 90',
            '(12) 3456-7890', '555-1234-5678 and 555.123.4567', '1-1-1-1-1-1-1-1-1-1-1', ' 1-1-1-1-1-1-1-1-1-1-1',
            '\u0663\u0663\u0663\u0663\u0663\u0663\u0663\u0663\u0663\u0663', 'x 1234567890 y', '1234567890)', '(1234567890',
            '12345678901234567890-', 'abc 12345678-9 12345678-9 1234567890', '', ' ', '+', '1' * 9, '1' * 10, '1 ' * 5,
        ]
        for text in samples:
            with self.subTest(text=text):
                self.assertEqual(self._span(pat.search(text)), self._span(self.LEGACY.search(text)))

    def test_phone_matches_legacy_pattern_on_seeded_random_strings(self):
        import random
        rng = random.Random(20261111)
        alphabet = list('0112 9a_-+.()\u00e9\u0663') + [' ', '-', ' ']
        pat = PhonePattern()
        for _ in range(20000):
            text = ''.join(rng.choice(alphabet) for _ in range(rng.randint(0, 28)))
            self.assertEqual(self._span(pat.search(text)), self._span(self.LEGACY.search(text)), text)

    def test_phone_one_megabyte_separator_lines_do_not_hang(self):
        # Regression for a quadratic phone_number regex on a line such as ' 1-1-1-'.
        script = Path(__file__).resolve().parent / 'portfolioguard.py'
        for unit in (' 1-', ' 123-', ' 123456789-'):
            payload = (unit * (1_000_000 // len(unit) + 1))[:1_000_000]
            self.assertEqual(len(payload), 1_000_000)
            with self.subTest(unit=unit):
                try:
                    done = subprocess.run(
                        [sys.executable, str(script), '--stdin', '--max-bytes', '1000000'],
                        input=payload.encode(), timeout=10,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    )
                except subprocess.TimeoutExpired:
                    self.fail(f'phone_number rule hung on a 1MB {unit!r} line')
                self.assertEqual(done.returncode, 0)
                self.assertNotIn(b'[', done.stdout)


class FilesModeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.assertNotEqual(subprocess.run(['git', '-C', str(self.dir), 'rev-parse'], stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE).returncode, 0, 'fixture dir must be outside git')

    def write(self, name, text):
        path = self.dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            path.write_bytes(text)
        else:
            path.write_text(text, encoding='utf-8')
        return path

    def test_clean_file_exits_zero(self):
        clean = self.write('clean.md', 'Nothing to see here.\n')
        code, out, err = run_cli(['--files', str(clean)])
        self.assertEqual((code, out.strip(), err), (0, 'No configured patterns matched.', ''))

    def test_leaky_file_same_format_and_rules_as_scan(self):
        leaky = self.write('leaky.md', LEAKY)
        code, out, err = run_cli(['--files', str(leaky)], cwd=self.dir)
        self.assertEqual(code, 1)
        name = leaky.as_posix()
        self.assertIn(f'files: {name}:2 [email_address]\n', out)
        self.assertIn(f'files: {name}:3 [aws_access_key]\n', out)
        self.assertIn('Found 2 non-allowlisted issue(s) across 2 finding(s). Review locally before sharing.', out)
        self.assertNotIn('AKIA', out)
        self.assertNotIn('example.test', out)
        expected = {(n, rule) for _, n, rule, _ in scan(LEAKY, 'x')}
        shown = {(int(m[1]), m[2]) for m in (re.match(r'files: .+:(\d+) \[(\w+)\]$', x) for x in out.splitlines() if x.startswith('files:'))}
        self.assertEqual(shown, expected)

    def test_relative_path_name_is_normalised(self):
        self.write('drafts/post.md', LEAKY)
        code, out, _ = run_cli(['--files', './drafts/../drafts/post.md'], cwd=self.dir)
        self.assertEqual(code, 1)
        self.assertIn('files: drafts/post.md:2 [email_address]', out)

    def test_multiple_paths(self):
        self.write('a.md', 'fine\n')
        self.write('b.md', LEAKY)
        code, out, _ = run_cli(['--files', 'a.md', 'b.md', 'a.md'], cwd=self.dir)
        self.assertEqual(code, 1)
        self.assertIn('files: b.md:2 [email_address]', out)
        self.assertNotIn('a.md', out)
        code, out, _ = run_cli(['--files', 'a.md', 'a.md'], cwd=self.dir)
        self.assertEqual(code, 0)

    def test_directory_walk_skip_dirs_binary_and_stable_order(self):
        self.write('drafts/z.md', LEAKY)
        self.write('drafts/sub/a.md', LEAKY)
        self.write('drafts/node_modules/dep/x.md', LEAKY)
        self.write('drafts/build/y.md', LEAKY)
        self.write('drafts/image.bin', b'\0\1\2' + LEAKY.encode())
        code, out, _ = run_cli(['--files', 'drafts'], cwd=self.dir)
        self.assertEqual(code, 1)
        names = [x.split(' ')[1].rsplit(':', 1)[0] for x in out.splitlines() if x.startswith('files:')]
        self.assertEqual(names, ['drafts/z.md', 'drafts/z.md', 'drafts/sub/a.md', 'drafts/sub/a.md'])
        # a directory's own files come first, then its sorted sub directories
        # naming a skipped directory explicitly still scans its own files
        code, out, _ = run_cli(['--files', 'drafts/build'], cwd=self.dir)
        self.assertIn('files: drafts/build/y.md:2 [email_address]', out)

    def test_directory_walk_ignores_symlinks_and_dedupes(self):
        real = self.write('real/a.md', LEAKY)
        self.write('other/clean.md', 'fine\n')
        try:
            os.symlink(real, self.dir / 'other' / 'link.md')
            os.symlink(self.dir / 'real', self.dir / 'other' / 'linkdir')
        except (OSError, NotImplementedError):
            self.skipTest('symlinks not available')
        code, out, _ = run_cli(['--files', 'other'], cwd=self.dir)
        self.assertEqual((code, out.strip()), (0, 'No configured patterns matched.'))
        code, out, _ = run_cli(['--files', 'real', 'real/a.md'], cwd=self.dir)
        self.assertEqual(out.count('files: real/a.md:2 [email_address]'), 1)

    def test_stdin_flag_and_dash(self):
        for args in (['--stdin'], ['-'], ['--files', '-']):
            with self.subTest(args=args):
                code, out, _ = run_cli(args, stdin=LEAKY)
                self.assertEqual(code, 1)
                self.assertIn('stdin: <stdin>:2 [email_address]\n', out)
                self.assertIn('stdin: <stdin>:3 [aws_access_key]\n', out)
                self.assertNotIn('AKIA', out)
        code, out, _ = run_cli(['--stdin'], stdin='all good\n')
        self.assertEqual((code, out.strip()), (0, 'No configured patterns matched.'))

    def test_stdin_name_and_mixed_with_file(self):
        self.write('b.md', LEAKY)
        code, out, _ = run_cli(['--stdin', '--stdin-name', 'draft.md', 'b.md'], stdin=LEAKY, cwd=self.dir)
        self.assertEqual(code, 1)
        self.assertIn('files: b.md:2 [email_address]', out)
        self.assertIn('stdin: draft.md:2 [email_address]', out)

    def test_stdin_binary_and_oversize_are_reported_not_silent(self):
        code, out, err = run_cli(['--stdin'], stdin=b'\0abc')
        self.assertEqual(code, 3)
        self.assertIn('PortfolioGuard: skipped <stdin> (binary)', err)
        self.assertIn('NOT SCANNED: 1 named input(s) were skipped', out)
        self.assertNotIn('No configured patterns matched.', out)
        code, out, err = run_cli(['--stdin', '--max-bytes', '10'], stdin=LEAKY)
        self.assertEqual(code, 3)
        self.assertIn('PortfolioGuard: skipped <stdin> (over size limit)', err)

    def test_allowlist_exact_and_glob(self):
        self.write('b.md', LEAKY)
        allow = self.write('allow.txt', 'b.md:2:email_address\n*.md:aws_access_key\n')
        code, out, _ = run_cli(['--files', 'b.md', '--allowlist', str(allow)], cwd=self.dir)
        self.assertEqual(code, 0)
        self.assertIn('files: b.md:2 [email_address] [allowed]', out)
        self.assertIn('files: b.md:3 [aws_access_key] [allowed]', out)
        self.assertIn('Found 0 non-allowlisted issue(s) across 2 finding(s).', out)
        partial = self.write('partial.txt', 'b.md:2:email_address\n')
        code, out, _ = run_cli(['--files', 'b.md', '--allowlist', str(partial)], cwd=self.dir)
        self.assertEqual(code, 1)
        self.assertIn('Found 1 non-allowlisted issue(s)', out)

    def test_default_allowlist_is_read_from_cwd(self):
        self.write('b.md', LEAKY)
        self.write('.portfolioguard-allowlist', 'b.md:email_address\nb.md:aws_access_key\n')
        code, out, _ = run_cli(['--files', 'b.md'], cwd=self.dir)
        self.assertEqual(code, 0)
        self.assertIn('[allowed]', out)

    def test_stdin_findings_can_be_allowlisted_by_name(self):
        allow = self.write('allow.txt', '<stdin>:2:email_address\n<stdin>:aws_access_key\n')
        code, out, _ = run_cli(['--stdin', '--allowlist', str(allow)], stdin=LEAKY)
        self.assertEqual(code, 0)
        self.assertIn('stdin: <stdin>:2 [email_address] [allowed]', out)

    def test_json_and_candidates_output(self):
        self.write('b.md', LEAKY)
        code, out, _ = run_cli(['--files', 'b.md', '--format', 'json'], stdin=None, cwd=self.dir)
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual({(x['source'], x['path'], x['line'], x['rule'], x['allowed']) for x in data},
                         {('files', 'b.md', 2, 'email_address', False), ('files', 'b.md', 3, 'aws_access_key', False)})
        self.assertNotIn('AKIA', out)
        code, out, _ = run_cli(['--stdin', '--format', 'json'], stdin=LEAKY)
        self.assertEqual({x['source'] for x in json.loads(out)}, {'stdin'})
        code, out, _ = run_cli(['--files', 'b.md', '--candidates'], cwd=self.dir)
        self.assertEqual(out.splitlines(), ['b.md:2:email_address', 'b.md:3:aws_access_key'])

    def test_config_from_cwd_and_rules_flag(self):
        self.write('b.md', 'CUSTOM-1234\n' + MAIL_LINE + '\n')
        self.write('portfolioguard.toml', 'allowed_email_values = ["alex' + '@' + 'example.test"]\n'
                   '[[rules]]\nname="custom_marker"\npattern="CUSTOM-[0-9]{4}"\n')
        code, out, _ = run_cli(['--files', 'b.md'], cwd=self.dir)
        self.assertEqual(code, 1)
        self.assertIn('files: b.md:1 [custom_marker]', out)
        self.assertNotIn('email_address', out)
        other = self.write('other.toml', '[[rules]]\nname="other_marker"\npattern="CUSTOM-[0-9]{4}"\n')
        code, out, _ = run_cli(['--files', 'b.md', '--rules', str(other)], cwd=self.dir)
        self.assertIn('[other_marker]', out)
        self.assertNotIn('[custom_marker]', out)
        self.assertIn('email_address', out)

    def test_max_bytes_skip_of_named_file_is_reported(self):
        self.write('big.md', LEAKY)
        code, out, err = run_cli(['--files', 'big.md', '--max-bytes', '5'], cwd=self.dir)
        self.assertEqual(code, 3)
        self.assertIn('PortfolioGuard: skipped big.md (over size limit)', err)
        self.assertIn('NOT SCANNED: 1 named input(s) were skipped', out)
        self.write('bin.dat', b'\0' + LEAKY.encode())
        code, out, err = run_cli(['--files', 'bin.dat'], cwd=self.dir)
        self.assertEqual(code, 3)
        self.assertIn('PortfolioGuard: skipped bin.dat (binary)', err)

    def test_errors_exit_two(self):
        self.write('a.md', 'fine\n')
        cases = [
            ['--files', 'missing.md'],
            ['--files'],
            ['--files', 'a.md', '--history'],
            ['--stdin', '--staged'],
            ['--files', 'a.md', '--range', 'HEAD~1..HEAD'],
            ['--files', 'a.md', '--pre-push'],
            ['--files', 'a.md', '--install-hook'],
            ['a.md', 'b.md'],
        ]
        for args in cases:
            with self.subTest(args=args):
                code, out, err = run_cli(args, stdin='', cwd=self.dir)
                self.assertEqual(code, 2)
                self.assertEqual(out, '')
                self.assertTrue(err.startswith('PortfolioGuard: '), err)
        code, _, err = run_cli(['--files', 'missing.md'], cwd=self.dir)
        self.assertIn('Path not found: missing.md', err)

    def test_files_mode_never_runs_git(self):
        self.write('b.md', LEAKY)
        boom = AssertionError('git must not be called in files mode')
        with patch('portfolioguard.git', side_effect=boom), patch('portfolioguard.subprocess.run', side_effect=boom):
            code, out, _ = run_cli(['--files', 'b.md'], cwd=self.dir)
            self.assertEqual(code, 1)
            code, out, _ = run_cli(['--stdin'], stdin=LEAKY)
            self.assertEqual(code, 1)

    def test_default_mode_outside_git_still_exits_two(self):
        self.write('b.md', LEAKY)
        code, out, err = run_cli([str(self.dir)])
        self.assertEqual((code, out), (2, ''))
        self.assertTrue(err.startswith('PortfolioGuard: Git repository not found'), err)
        self.assertIn('--files', err)

    def test_utf16_named_file_is_not_reported_as_clean(self):
        self.write('utf16.md', LEAKY.encode('utf-16'))
        code, out, err = run_cli(['--files', 'utf16.md'], cwd=self.dir)
        self.assertEqual(code, 3)
        self.assertIn('skipped utf16.md (binary)', err)
        self.assertNotIn('No configured patterns matched.', out)

    def test_findings_win_over_not_scanned_exit_code(self):
        self.write('b.md', LEAKY)
        self.write('bin.dat', b'\0abc')
        code, out, err = run_cli(['--files', 'b.md', 'bin.dat'], cwd=self.dir)
        self.assertEqual(code, 1)
        self.assertIn('Found 2 non-allowlisted issue(s)', out)
        self.assertIn('NOT SCANNED: 1 named input(s)', out)

    def test_not_scanned_notice_goes_to_stderr_for_json_and_candidates(self):
        self.write('bin.dat', b'\0abc')
        code, out, err = run_cli(['--files', 'bin.dat', '--format', 'json'], cwd=self.dir)
        self.assertEqual((code, json.loads(out)), (3, []))
        self.assertIn('NOT SCANNED', err)
        code, out, err = run_cli(['--files', 'bin.dat', '--candidates'], cwd=self.dir)
        self.assertEqual((code, out), (3, ''))
        self.assertIn('NOT SCANNED', err)

    def test_skips_inside_directories_are_counted(self):
        self.write('d/ok.md', 'fine\n')
        self.write('d/a.bin', b'\0abc')
        self.write('d/b.bin', b'\0abc')
        self.write('d/big.md', LEAKY)
        code, out, err = run_cli(['--files', 'd', '--max-bytes', '20'], cwd=self.dir)
        self.assertEqual(code, 0)
        self.assertIn('No configured patterns matched.', out)
        self.assertIn('Skipped 3 file(s) inside directories: 2 binary, 1 over size limit.', out)
        self.assertEqual(err, '')

    def test_stdin_name_control_characters_are_sanitised(self):
        code, out, _ = run_cli(['--stdin', '--stdin-name', 'x\nFound 0 non-allowlisted issue(s) across 0 finding(s).\x1b[2J'], stdin=LEAKY)
        self.assertEqual(code, 1)
        for line in out.splitlines():
            self.assertNotIn('\x1b', line)
        self.assertEqual([x for x in out.splitlines() if x.startswith('Found ')], [x for x in out.splitlines() if x.startswith('Found 2 ')])
        self.assertIn('stdin: x?Found 0 non-allowlisted issue(s) across 0 finding(s).?[2J:2 [email_address]', out)

    def test_named_symlink_is_followed(self):
        real = self.write('outside/real.md', LEAKY)
        self.write('d/placeholder.md', 'fine\n')
        try:
            os.symlink(real, self.dir / 'd' / 'link.md')
            os.symlink(self.dir / 'outside', self.dir / 'linkdir')
        except (OSError, NotImplementedError):
            self.skipTest('symlinks not available')
        code, out, _ = run_cli(['--files', 'd/link.md'], cwd=self.dir)
        self.assertEqual(code, 1)
        self.assertIn('files: d/link.md:2 [email_address]', out)
        code, out, _ = run_cli(['--files', 'linkdir'], cwd=self.dir)
        self.assertEqual(code, 1)
        self.assertIn('files: linkdir/real.md:2 [email_address]', out)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'mkfifo not available')
    def test_fifo_inside_directory_does_not_hang(self):
        self.write('d/a.md', LEAKY)
        os.mkfifo(self.dir / 'd' / 'pipe')
        script = Path(__file__).resolve().parent / 'portfolioguard.py'
        try:
            done = subprocess.run([sys.executable, str(script), '--files', 'd'], cwd=self.dir, timeout=20,
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.TimeoutExpired:
            self.fail('directory scan hung on a FIFO')
        out = done.stdout.decode()
        self.assertEqual(done.returncode, 1)
        self.assertIn('files: d/a.md:2 [email_address]', out)
        self.assertIn('Skipped 1 file(s) inside directories: 1 not a regular file.', out)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'mkfifo not available')
    def test_named_fifo_and_devices_exit_two(self):
        os.mkfifo(self.dir / 'pipe')
        script = Path(__file__).resolve().parent / 'portfolioguard.py'
        targets = ['pipe'] + (['/dev/null'] if os.path.exists('/dev/null') else [])
        for target in targets:
            with self.subTest(target=target):
                try:
                    done = subprocess.run([sys.executable, str(script), '--files', target], cwd=self.dir, timeout=20,
                                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                except subprocess.TimeoutExpired:
                    self.fail('named special file hung')
                self.assertEqual(done.returncode, 2)
                self.assertIn('Not a file or directory', done.stderr.decode())

    @unittest.skipUnless(hasattr(socket, 'AF_UNIX'), 'unix sockets not available')
    def test_socket_inside_directory_is_skipped(self):
        self.write('d/a.md', 'fine\n')
        sock = socket.socket(socket.AF_UNIX)
        self.addCleanup(sock.close)
        try:
            sock.bind(str(self.dir / 'd' / 's'))
        except OSError:
            self.skipTest('cannot bind a unix socket here')
        code, out, _ = run_cli(['--files', 'd'], cwd=self.dir)
        self.assertEqual(code, 0)
        self.assertIn('Skipped 1 file(s) inside directories: 1 not a regular file.', out)

    @unittest.skipIf(hasattr(os, 'geteuid') and os.geteuid() == 0, 'root can read everything')
    def test_unreadable_files_are_reported(self):
        locked = self.write('d/locked.md', LEAKY)
        self.write('d/ok.md', 'fine\n')
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o600)
        code, out, err = run_cli(['--files', 'd'], cwd=self.dir)
        self.assertEqual(code, 0)
        self.assertIn('Skipped 1 file(s) inside directories: 1 unreadable.', out)
        code, out, err = run_cli(['--files', 'd/locked.md'], cwd=self.dir)
        self.assertEqual(code, 3)
        self.assertIn('skipped d/locked.md (unreadable)', err)

    def test_stdin_prompt_only_on_a_terminal(self):
        class Tty(io.StringIO):
            def isatty(self):
                return True
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), patch('sys.stdin', Tty('fine\n')):
            code = main(['--stdin'])
        self.assertEqual(code, 0)
        self.assertIn('press Ctrl-D', err.getvalue())
        code, out, err = run_cli(['--stdin'], stdin='fine\n')
        self.assertEqual(err, '')

    @unittest.skipUnless(os.name == 'posix', 'needs POSIX file descriptors')
    def test_closed_stdin_is_a_clean_error(self):
        script = Path(__file__).resolve().parent / 'portfolioguard.py'
        for args in (['--stdin'], ['-'], ['--files', '-']):
            with self.subTest(args=args):
                done = subprocess.run([sys.executable, str(script), *args], cwd=self.dir, timeout=20,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=lambda: os.close(0))
                err = done.stderr.decode()
                self.assertEqual(done.returncode, 2)
                self.assertTrue(err.startswith('PortfolioGuard: Standard input is closed'), err)
                self.assertNotIn('Traceback', err)
                self.assertEqual(done.stdout, b'')

    def test_stdin_none_and_closed_stream_exit_two(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), patch('sys.stdin', None):
            self.assertEqual(main(['--stdin']), 2)
        self.assertIn('Standard input is closed', err.getvalue())
        closed = io.StringIO()
        closed.close()
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err), patch('sys.stdin', closed):
            self.assertEqual(main(['--stdin']), 2)
        self.assertIn('Standard input is closed', err.getvalue())

    def test_strict_makes_directory_skips_fail(self):
        self.write('d/ok.md', 'fine\n')
        self.write('d/a.bin', b'\0abc')
        self.write('d/utf16.md', 'fine\n'.encode('utf-16'))
        code, out, _ = run_cli(['--files', 'd'], cwd=self.dir)
        self.assertEqual(code, 0)
        self.assertIn('Skipped 2 file(s) inside directories: 2 binary.', out)
        code, out, err = run_cli(['--files', 'd', '--strict'], cwd=self.dir)
        self.assertEqual(code, 3)
        self.assertIn('NOT SCANNED (--strict): 2 file(s) inside directories were skipped: 2 binary.', out)
        self.assertNotIn('No configured patterns matched.', out)
        self.assertEqual(err, '')

    def test_strict_with_nothing_skipped_and_with_findings(self):
        self.write('clean/ok.md', 'fine\n')
        code, out, _ = run_cli(['--files', 'clean', '--strict'], cwd=self.dir)
        self.assertEqual((code, out.strip()), (0, 'No configured patterns matched.'))
        self.write('mixed/b.md', LEAKY)
        self.write('mixed/a.bin', b'\0abc')
        code, out, _ = run_cli(['--files', 'mixed', '--strict'], cwd=self.dir)
        self.assertEqual(code, 1)
        self.assertIn('NOT SCANNED (--strict)', out)

    def test_strict_counts_special_oversize_and_unreadable_but_not_symlinks(self):
        self.write('d/big.md', LEAKY)
        code, out, _ = run_cli(['--files', 'd', '--strict', '--max-bytes', '5'], cwd=self.dir)
        self.assertEqual(code, 3)
        self.assertIn('1 over size limit', out)
        self.write('s/ok.md', 'fine\n')
        try:
            os.symlink(self.dir / 'd' / 'big.md', self.dir / 's' / 'link.md')
        except (OSError, NotImplementedError):
            self.skipTest('symlinks not available')
        code, out, _ = run_cli(['--files', 's', '--strict'], cwd=self.dir)
        self.assertEqual(code, 0)
        if hasattr(os, 'mkfifo'):
            os.mkfifo(self.dir / 's' / 'pipe')
            code, out, _ = run_cli(['--files', 's', '--strict'], cwd=self.dir)
            self.assertEqual(code, 3)
            self.assertIn('1 not a regular file', out)

    def test_strict_notice_goes_to_stderr_for_json_and_needs_files_mode(self):
        self.write('d/a.bin', b'\0abc')
        code, out, err = run_cli(['--files', 'd', '--strict', '--format', 'json'], cwd=self.dir)
        self.assertEqual((code, json.loads(out)), (3, []))
        self.assertIn('NOT SCANNED (--strict)', err)
        code, out, err = run_cli(['--strict', str(self.dir)])
        self.assertEqual((code, out), (2, ''))
        self.assertIn('--strict only applies to --files / --stdin', err)


DRAFT_FIXTURES = {
    'private_ipv4': ['router 192.' + '168.42.5 here', 'host 10.' + '0.0.5.', 'x 172.' + '16.5.4 y', 'x 172.' + '31.255.255 y'],
    'cgnat_ipv4': ['node 100.' + '64.0.1 up', 'node 100.' + '127.255.254 up'],
    'tailscale_hostname': ['box.tail' + '1a2b3c.ts.net', 'http://laptop.' + 'ts.net/path'],
    'mac_address': ['mac aa:bb:cc:dd:' + 'ee:ff', 'MAC AA-BB-CC-' + 'DD-EE-FF'],
    'device_brand_model': ['a TP-Link router', 'an RE999 unit', 'Archer AX55', 'a Netgear box', 'TL-WR841N'],
    'overclaim_word': ['this cannot fail', 'it is impossible', 'a guarantee for you', 'fully secure', 'works on the first try', '100% safe', 'always works'],
}
DRAFT_CLEAN = [
    'public 8.8.8.8 and 172.' + '32.0.1 and 100.' + '63.1.1 and 100.' + '128.0.1',
    'version 10.' + '0.19045.1234 and 10.' + '1.2.3.4',
    'time 12:34:56 and ipv6 2001:db8:aa:bb:cc:dd:ee:ff12',
    'host example.com and tailored and ts.net on its own',
    'an orbit and a network and renew450 and RE45',
    'not a guarantee, never fully, no secrets here, it is not secure',
]


class DraftProfileTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def candidates(self, text, *extra, cwd=None):
        code, out, err = run_cli(['--stdin', '--candidates', *extra], stdin=text, cwd=cwd or self.dir)
        return code, [x.split(':')[-1] for x in out.splitlines()], err

    def test_profile_is_off_by_default(self):
        for rule, samples in DRAFT_FIXTURES.items():
            for text in samples:
                with self.subTest(text=text):
                    self.assertNotIn(rule, self.candidates(text)[1])

    def test_each_rule_matches_its_fixtures(self):
        for rule, samples in DRAFT_FIXTURES.items():
            for text in samples:
                with self.subTest(rule=rule, text=text):
                    self.assertIn(rule, self.candidates(text, '--profile', 'drafts')[1])

    def test_clean_lines_stay_quiet(self):
        draft_rules = set(DRAFT_FIXTURES)
        for text in DRAFT_CLEAN:
            with self.subTest(text=text):
                self.assertFalse(draft_rules & set(self.candidates(text, '--profile', 'drafts')[1]))

    def test_output_never_echoes_matched_values(self):
        text = '\n'.join(x[0] for x in DRAFT_FIXTURES.values())
        for extra in ([], ['--format', 'json']):
            code, out, _ = run_cli(['--stdin', '--profile', 'drafts', *extra], stdin=text)
            for value in ('192.' + '168.42.5', 'ts.net', 'aa:bb:cc', 'cannot', 'TP' + '-Link', '100.' + '64.0.1'):
                self.assertNotIn(value, out)

    def test_overclaim_is_a_warning_and_does_not_fail_the_run(self):
        code, out, _ = run_cli(['--stdin', '--profile', 'drafts'], stdin='this cannot fail\nalways works\n')
        self.assertEqual(code, 0)
        self.assertIn('stdin: <stdin>:1 [overclaim_word] [warning]', out)
        self.assertIn('Found 0 non-allowlisted issue(s) across 2 finding(s).', out)
        self.assertIn('2 warning(s) are word list hits to read, they do not change the exit code.', out)
        code, out, _ = run_cli(['--stdin', '--profile', 'drafts'], stdin='this cannot fail\nrouter 192.' + '168.42.5\n')
        self.assertEqual(code, 1)
        self.assertIn('Found 1 non-allowlisted issue(s) across 2 finding(s).', out)

    def test_allowlist_applies_to_profile_rules(self):
        allow = self.dir / 'allow.txt'
        allow.write_text('<stdin>:1:private_ipv4\n<stdin>:overclaim_word\n')
        code, out, _ = run_cli(['--stdin', '--profile', 'drafts', '--allowlist', str(allow)], stdin='router 192.' + '168.42.5\nalways works\n')
        self.assertEqual(code, 0)
        self.assertIn('[private_ipv4] [allowed]', out)
        self.assertIn('[overclaim_word] [allowed]', out)
        self.assertNotIn('[warning]', out)

    def test_json_gets_warning_key_only_when_a_profile_is_on(self):
        code, out, _ = run_cli(['--stdin', '--format', 'json'], stdin=AWS_LINE + '\n')
        self.assertEqual({tuple(sorted(x)) for x in json.loads(out)}, {('allowed', 'line', 'path', 'rule', 'source')})
        code, out, _ = run_cli(['--stdin', '--format', 'json', '--profile', 'drafts'], stdin='always works\n' + AWS_LINE + '\n')
        rows = {x['rule']: x for x in json.loads(out)}
        self.assertIs(rows['overclaim_word']['warning'], True)
        self.assertIs(rows['aws_access_key']['warning'], False)

    def test_negated_overclaims_are_ignored_but_later_hits_count(self):
        for text in ('not a guarantee', 'this is not fully done', 'there is no guarantee', "it isn't secure", 'never always'):
            with self.subTest(text=text):
                self.assertNotIn('overclaim_word', self.candidates(text, '--profile', 'drafts')[1])
        self.assertIn('overclaim_word', self.candidates('not a guarantee, but it always works', '--profile', 'drafts')[1])

    def test_config_profile_and_extra_terms(self):
        (self.dir / 'portfolioguard.toml').write_text(
            'profile = ["drafts"]\n[drafts]\ndevice_terms = ["Zyxel", "example-host"]\noverclaim_terms = ["flawless"]\n')
        code, rules, _ = self.candidates('router at 192.' + '168.42.5\na Zyxel box\nexample-host vm\nflawless run\n')
        self.assertEqual(rules, ['private_ipv4', 'device_brand_model', 'device_brand_model', 'overclaim_word'])
        code, rules, _ = self.candidates('a Zyxel box', '--rules', str(self.dir / 'portfolioguard.toml'))
        self.assertEqual(rules, ['device_brand_model'])
        # without the profile the extra terms do nothing
        (self.dir / 'plain.toml').write_text('[drafts]\ndevice_terms = ["Zyxel"]\n')
        self.assertEqual(self.candidates('a Zyxel box', '--rules', str(self.dir / 'plain.toml'))[1], [])

    def test_bad_profile_settings_exit_two(self):
        for body in ('profile = ["nope"]\n', 'profile = "drafts"\n', '[drafts]\nwrong = ["x"]\n', '[drafts]\ndevice_terms = [1]\n'):
            with self.subTest(body=body):
                (self.dir / 'bad.toml').write_text(body)
                code, out, err = run_cli(['--stdin', '--rules', str(self.dir / 'bad.toml')], stdin='x\n')
                self.assertEqual(code, 2)
                self.assertTrue(err.startswith('PortfolioGuard: '))
        with self.assertRaises(SystemExit) as caught, contextlib.redirect_stderr(io.StringIO()):
            main(['--stdin', '--profile', 'nope'])
        self.assertEqual(caught.exception.code, 2)

    def test_profile_works_in_git_modes_and_is_off_without_it(self):
        repo = self.dir / 'repo'
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        run_git(repo, 'config', 'user.email', 'fixture@example.test')
        run_git(repo, 'config', 'user.name', 'Fixture')
        (repo / 'notes.md').write_text('router 192.' + '168.42.5\n')
        run_git(repo, 'add', '.')
        run_git(repo, 'commit', '-m', 'fixture')
        self.assertEqual(run_cli([str(repo)])[:2], (0, 'No configured patterns matched.\n'))
        code, out, _ = run_cli([str(repo), '--profile', 'drafts'])
        self.assertEqual(code, 1)
        self.assertIn('working-tree: notes.md:1 [private_ipv4]', out)
        code, out, _ = run_cli([str(repo), '--history', '--profile', 'drafts'])
        self.assertRegex(out, r'history:[0-9a-f]{8}: notes\.md:1 \[private_ipv4\]')
        code, out, _ = run_cli([str(repo), '--staged', '--profile', 'drafts'])
        self.assertEqual(code, 0)

    def test_files_mode_with_profile_over_a_directory(self):
        (self.dir / 'drafts').mkdir()
        (self.dir / 'drafts' / 'post.md').write_text('host box.tail' + '1a2b3c.ts.net\nthis cannot fail\n')
        code, out, _ = run_cli(['--files', 'drafts', '--profile', 'drafts'], cwd=self.dir)
        self.assertEqual(code, 1)
        self.assertIn('files: drafts/post.md:1 [tailscale_hostname]', out)
        self.assertIn('files: drafts/post.md:2 [overclaim_word] [warning]', out)

    def test_drafts_profile_one_megabyte_dotted_line_does_not_hang(self):
        # Regression for a quadratic tailscale_hostname pattern on a long dotted line.
        payload = 'a.' * 500000
        self.assertEqual(len(payload), 1_000_000)
        script = Path(__file__).resolve().parent / 'portfolioguard.py'
        try:
            done = subprocess.run(
                [sys.executable, str(script), '--stdin', '--profile', 'drafts',
                 '--max-bytes', '1000000'],
                input=payload.encode(), timeout=5,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        except subprocess.TimeoutExpired:
            self.fail('drafts profile hung on a 1MB dotted line')
        self.assertEqual(done.returncode, 0)
        self.assertNotIn(b'[', done.stdout)


class InRepoUnchangedTests(unittest.TestCase):
    def make_repo(self, tmp):
        repo = Path(tmp)
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        run_git(repo, 'config', 'user.email', 'fixture@example.test')
        run_git(repo, 'config', 'user.name', 'Fixture')
        (repo / 'tracked.md').write_text(LEAKY)
        (repo / 'clean.md').write_text('fine\n')
        run_git(repo, 'add', '.')
        run_git(repo, 'commit', '-m', 'fixture')
        return repo

    def test_default_scan_still_reports_working_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            (repo / 'untracked.md').write_text(LEAKY)
            code, out, err = run_cli([str(repo)])
            self.assertEqual(code, 1)
            self.assertIn('working-tree: tracked.md:2 [email_address]', out)
            self.assertIn('working-tree: untracked.md:3 [aws_access_key]', out)
            self.assertNotIn('files:', out)
            self.assertEqual(err, '')
            # no argument means the current directory
            code, out, _ = run_cli([], cwd=repo)
            self.assertIn('working-tree: tracked.md:2 [email_address]', out)

    def test_files_mode_inside_repo_scans_only_named_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            (repo / 'untracked.md').write_text(LEAKY)
            code, out, _ = run_cli(['--files', 'clean.md'], cwd=repo)
            self.assertEqual((code, out.strip()), (0, 'No configured patterns matched.'))
            code, out, _ = run_cli(['--files', 'untracked.md'], cwd=repo)
            self.assertEqual(code, 1)
            self.assertIn('files: untracked.md:2 [email_address]', out)
            self.assertNotIn('tracked.md:', out.replace('untracked.md:', ''))

    def test_history_and_staged_still_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.make_repo(tmp)
            code, out, _ = run_cli([str(repo), '--history'])
            self.assertEqual(code, 1)
            self.assertRegex(out, r'history:[0-9a-f]{8}: tracked\.md:2 \[email_address\]')
            (repo / 'clean.md').write_text('still fine\n')
            run_git(repo, 'add', 'clean.md')
            code, out, _ = run_cli([str(repo), '--staged'])
            self.assertEqual((code, out.strip()), (0, 'No configured patterns matched.'))

    def test_two_repo_paths_are_an_error_without_files(self):
        code, _, err = run_cli(['.', '..'])
        self.assertEqual(code, 2)
        self.assertIn('Only one repository path is allowed', err)




if __name__ == '__main__':
    unittest.main()
