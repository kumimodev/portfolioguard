"""CI wrapper for fuzz_regex.py. Run a bigger fuzz locally with PG_FUZZ_COUNT=400000."""
import contextlib
import io
import os
import unittest
from unittest import mock

import fuzz_regex


class DifferentialFuzzTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.args = fuzz_regex.settings([])

    def test_linear_matchers_agree_with_the_old_regexes(self):
        module = fuzz_regex.load_module()
        for report in fuzz_regex.run_matchers(module, self.args.count, self.args.seed):
            with self.subTest(report.label):
                self.assertGreater(report.ref_hits, 0, 'the generator never produced a match')
                self.assertEqual(report.mismatches[:3], [], report.line())

    def test_a_broken_matcher_is_caught(self):
        # Without this the fuzz run could pass because it is blind. Every mutation, including a
        # broken value run cache, has to produce at least one mismatch.
        results = fuzz_regex.run_mutation_check(self.args.count, self.args.seed)
        self.assertEqual(len(results), len(fuzz_regex.MUTATIONS))
        for name, caught, bad in results:
            with self.subTest(name):
                self.assertTrue(caught, f'mutation not caught: {name}')

    def test_every_mutation_changes_the_source(self):
        base = fuzz_regex.SOURCE.read_text(encoding='utf-8')
        for name, family, old, new in fuzz_regex.MUTATIONS:
            with self.subTest(name):
                self.assertEqual(base.count(old), 1)
                self.assertNotEqual(old, new)

    def test_bad_counts_are_a_clear_error_not_a_vacuous_pass(self):
        for argv in (['--count', '0'], ['--count', '-3'], ['--count', 'many'], ['--seed', 'x']):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()) as err:
                with self.assertRaises(SystemExit) as caught:
                    fuzz_regex.settings(argv)
                self.assertEqual(caught.exception.code, 2)
                self.assertIn('must be', err.getvalue())
        with mock.patch.dict(os.environ, {'PG_FUZZ_COUNT': 'zero'}), contextlib.redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(SystemExit):
                fuzz_regex.settings([])
            self.assertIn('PG_FUZZ_COUNT', err.getvalue())


if __name__ == '__main__':
    unittest.main()
