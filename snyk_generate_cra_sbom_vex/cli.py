"""Command-line argument parsing and validation (FR-2, FR-2a).

This module owns the CLI surface described in the requirements doc, §4.
Nothing below cli.py is permitted to parse arguments or read the
environment directly (see §8.3), so this is the single place the flag
set is defined.
"""

from __future__ import annotations

import argparse
from typing import Optional, Sequence, Tuple

from .config import API_VERSION_ENV_VAR, DEFAULT_API_VERSION

PROG_NAME = "snyk-generate-cra-sbom-vex"

# Formats the Snyk SBOM API is documented to support (FR-11). SPDX has no
# VEX equivalent, so selecting an spdx* format disables VEX generation
# (see config.build_config).
SBOM_FORMAT_CHOICES: Tuple[str, ...] = (
    "cyclonedx1.6+json",
    "cyclonedx1.5+json",
    "cyclonedx1.5+xml",
    "cyclonedx1.4+json",
    "cyclonedx1.4+xml",
    "spdx2.3+json",
)
DEFAULT_SBOM_FORMAT = "cyclonedx1.6+json"


def parse_tag(value: str) -> Tuple[str, str]:
    """Parses a --tag KEY=VALUE argument into a (key, value) pair."""
    if "=" not in value:
        raise argparse.ArgumentTypeError(
            f"invalid --tag value {value!r}: expected KEY=VALUE"
        )
    key, _, val = value.partition("=")
    key, val = key.strip(), val.strip()
    if not key or not val:
        raise argparse.ArgumentTypeError(
            f"invalid --tag value {value!r}: both KEY and VALUE must be non-empty"
        )
    return key, val


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG_NAME,
        description=(
            "Aggregate Snyk Open Source and Container project SBOMs, and derive a "
            "matching CycloneDX VEX document, across a combination of Snyk "
            "organizations, targets, assets, projects, groups, and tags."
        ),
    )

    sources = parser.add_argument_group(
        "source selection",
        "At least one of these six flags is required. Each is repeatable and all "
        "six are freely combinable (FR-2); the union of everything they resolve "
        "to is de-duplicated by (org, project) before SBOM/VEX generation (FR-2a).",
    )
    sources.add_argument(
        "--org",
        action="append",
        default=[],
        metavar="ID",
        help="A Snyk organization ID. Resolves to every in-scope project in that org.",
    )
    sources.add_argument(
        "--target",
        action="append",
        default=[],
        metavar="ID",
        help="A Snyk target ID (e.g. a repo or image). Resolves to every project under it.",
    )
    sources.add_argument(
        "--asset",
        action="append",
        default=[],
        metavar="ID",
        help=(
            "A Snyk Asset Inventory ID. Resolution depends on an unconfirmed API "
            "(Open Risk #1) and may be unavailable."
        ),
    )
    sources.add_argument(
        "--project",
        action="append",
        default=[],
        metavar="ID",
        help="A Snyk project ID, used directly with no lookup.",
    )
    sources.add_argument(
        "--group",
        action="append",
        default=[],
        metavar="ID",
        help="A Snyk group ID. Resolves to every org in the group, then each org's projects.",
    )
    sources.add_argument(
        "--tag",
        action="append",
        default=[],
        type=parse_tag,
        metavar="KEY=VALUE",
        help=(
            "A project tag. Resolves to every project carrying this tag across "
            "every org the token can access, since a tag is not scoped to one org."
        ),
    )

    auth = parser.add_argument_group("authentication")
    auth.add_argument(
        "--token",
        default=None,
        help=(
            "Snyk API token. Overrides SNYK_TOKEN if both are set. Never logged, "
            "including in --debug output."
        ),
    )

    output = parser.add_argument_group("output")
    output.add_argument(
        "--sbom-format",
        choices=SBOM_FORMAT_CHOICES,
        default=DEFAULT_SBOM_FORMAT,
        metavar="FORMAT",
        help=(
            f"SBOM output format (default: {DEFAULT_SBOM_FORMAT}). Choices: "
            f"{', '.join(SBOM_FORMAT_CHOICES)}. Selecting an spdx* format skips VEX "
            "generation, since VEX is not defined for SPDX."
        ),
    )
    output.add_argument(
        "--api-version",
        default=None,
        metavar="DATE",
        help=(
            "Snyk REST API version string to call. Defaults to the "
            f"{API_VERSION_ENV_VAR} environment variable if set, else "
            f"{DEFAULT_API_VERSION} (the latest known-GA version as of this "
            "script's last update -- see config.resolve_api_version)."
        ),
    )
    output.add_argument(
        "--output-prefix",
        default=None,
        metavar="PREFIX",
        help="Path/prefix for the two output files (default: sbom/vex in the current working directory).",
    )
    output.add_argument(
        "--no-vex",
        action="store_true",
        help="Write the SBOM only; skip VEX generation.",
    )

    behavior = parser.add_argument_group("run behavior")
    behavior.add_argument(
        "--fail-fast",
        action="store_true",
        help=(
            "Abort the whole run on the first project-level failure, instead of "
            "the default of continuing and reporting failures in the final summary."
        ),
    )
    behavior.add_argument(
        "--debug",
        "-v",
        action="store_true",
        help=(
            "Enable verbose/debug logging: every HTTP request/response (token "
            "redacted), pagination progress, per-project status, source "
            "resolution, and VEX vulnerability de-duplication/conflict "
            "decisions (FR-9a)."
        ),
    )

    return parser


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parses and validates CLI arguments.

    Exits the process via argparse's usual SystemExit(2) behavior on a
    malformed flag, and on the FR-2 "at least one source" rule below.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if not any((args.org, args.target, args.asset, args.project, args.group, args.tag)):
        parser.error(
            "at least one source must be supplied: --org, --target, --asset, "
            "--project, --group, or --tag"
        )

    return args
