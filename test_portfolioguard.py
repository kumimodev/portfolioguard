import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import shlex
from pathlib import Path

from portfolioguard import RULES, install_hook, is_allowed, load_allowlist, main, scan


def run_git(root, *args, **kwargs):
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

    def test_new_secret_rules(self):
        samples = [
            ('key=' + 'sk-' + 'proj-' + 'EXAMPLEEXAMPLEEXAMPLEEXAMPLEexample', 'openai_api_key'),
            ('key=' + 'sk-' + 'exampleexampleexampleexample1234', 'openai_api_key'),
            ('token=' + 'xox' + 'b-' + '123456789012-123456789012-EXAMPLEexampleExample12', 'slack_token'),
            ('token=' + 'xapp-' + '1-EXAMPLEEXAMPLEEX-abcdefgh', 'slack_token'),
            ('DefaultEndpointsProtocol=https;AccountName=examplestorage;AccountKey=EXAMPLEbase64+/key==;EndpointSuffix=core.windows.net', 'azure_connection_string'),
            ('{"password": "test-secret-value"}', 'generic_secret_assignment'),
            ('OPENAI_API_KEY=' + 'sk-' + 'exampleexampleexampleexample1234', 'generic_secret_assignment'),
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


if __name__ == '__main__':
    unittest.main()
