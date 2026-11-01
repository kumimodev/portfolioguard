import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from portfolioguard import RULES, install_hook, is_allowed, load_allowlist, main, scan


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
            self.assertIn('--staged', hook.read_text())
            self.assertTrue((hook.parent / 'pre-push.portfolioguard.bak').exists())


if __name__ == '__main__':
    unittest.main()
