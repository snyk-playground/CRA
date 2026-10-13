import argparse
import unittest

from snyk_generate_cra_sbom_vex import cli


class ParseTagTests(unittest.TestCase):
    def test_valid_tag(self):
        self.assertEqual(cli.parse_tag("team=unicorn"), ("team", "unicorn"))

    def test_missing_equals(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            cli.parse_tag("team")

    def test_empty_key(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            cli.parse_tag("=unicorn")

    def test_empty_value(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            cli.parse_tag("team=")


class ParseArgsTests(unittest.TestCase):
    def test_requires_at_least_one_source(self):
        with self.assertRaises(SystemExit) as ctx:
            cli.parse_args([])
        self.assertEqual(ctx.exception.code, 2)

    def test_single_org(self):
        args = cli.parse_args(["--org", "acme-platform"])
        self.assertEqual(args.org, ["acme-platform"])
        self.assertEqual(args.target, [])
        self.assertEqual(args.sbom_format, cli.DEFAULT_SBOM_FORMAT)
        # None here, not cli.DEFAULT_API_VERSION -- resolving --api-version's
        # actual default (env var, then the hardcoded fallback) is
        # config.py's job, tested in test_config.py.
        self.assertIsNone(args.api_version)
        self.assertFalse(args.no_vex)
        self.assertFalse(args.fail_fast)
        self.assertFalse(args.debug)

    def test_repeatable_and_combinable_sources(self):
        args = cli.parse_args(
            [
                "--org", "acme-platform",
                "--target", "3f9c",
                "--target", "7a21",
                "--project", "55e0",
                "--tag", "team=platform-security",
            ]
        )
        self.assertEqual(args.org, ["acme-platform"])
        self.assertEqual(args.target, ["3f9c", "7a21"])
        self.assertEqual(args.project, ["55e0"])
        self.assertEqual(args.tag, [("team", "platform-security")])

    def test_all_six_source_types_combinable(self):
        args = cli.parse_args(
            [
                "--org", "A",
                "--target", "B",
                "--target", "C",
                "--project", "D",
                "--group", "E",
                "--tag", "team=unicorn",
                "--asset", "F",
            ]
        )
        self.assertEqual(args.org, ["A"])
        self.assertEqual(args.target, ["B", "C"])
        self.assertEqual(args.project, ["D"])
        self.assertEqual(args.group, ["E"])
        self.assertEqual(args.asset, ["F"])
        self.assertEqual(args.tag, [("team", "unicorn")])

    def test_invalid_tag_exits(self):
        with self.assertRaises(SystemExit) as ctx:
            cli.parse_args(["--tag", "not-a-tag"])
        self.assertEqual(ctx.exception.code, 2)

    def test_invalid_sbom_format_exits(self):
        with self.assertRaises(SystemExit) as ctx:
            cli.parse_args(["--org", "A", "--sbom-format", "bogus"])
        self.assertEqual(ctx.exception.code, 2)

    def test_token_flag(self):
        args = cli.parse_args(["--org", "A", "--token", "secret-token"])
        self.assertEqual(args.token, "secret-token")

    def test_debug_short_flag(self):
        args = cli.parse_args(["--org", "A", "-v"])
        self.assertTrue(args.debug)

    def test_no_vex_and_fail_fast_flags(self):
        args = cli.parse_args(["--org", "A", "--no-vex", "--fail-fast"])
        self.assertTrue(args.no_vex)
        self.assertTrue(args.fail_fast)


if __name__ == "__main__":
    unittest.main()
