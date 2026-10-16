"""Command-line argument parsing and validation.

This module owns the CLI surface.
Nothing below cli.py is permitted to parse arguments or read the
environment directly, so this is the single place the flag
set is defined.
"""

from __future__ import annotations

import argparse
from typing import Optional, Sequence, Tuple

from .config import API_VERSION_ENV_VAR, DEFAULT_API_VERSION, PRODUCT_ENV_VARS

PROG_NAME = "snyk-generate-cra-sbom-vex"

# Formats the Snyk SBOM API is documented to support. SPDX has no
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


DESCRIPTION = (
    "Aggregate Snyk Open Source and Container project SBOMs, and derive a "
    "matching CycloneDX VEX document, across a combination of Snyk "
    "organizations, targets, assets, projects, groups, and tags."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=PROG_NAME, description=DESCRIPTION)

    sources = parser.add_argument_group(
        "source selection",
        "At least one of these six flags is required. Each is repeatable and all "
        "six are freely combinable; the union of everything they resolve "
        "to is de-duplicated by (org, project) before SBOM/VEX generation.",
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
            "and may be unavailable."
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
        help=(
            "Path and filename stem for the output file(s); missing directories are created. "
            "CycloneDX writes one combined file, <PREFIX>.cdx.json (default: sbom.cdx.json). "
            "SPDX writes <PREFIX>.sbom.spdx.json and <PREFIX>.vex.cdx.json "
            "(default: sbom.spdx.json and vex.cdx.json). Default location is the current directory."
        ),
    )
    output.add_argument(
        "--no-vex",
        action="store_true",
        help="Write the SBOM only; skip VEX generation.",
    )

    product = parser.add_argument_group(
        "product and SBOM creator (CRA)",
        "Snyk cannot determine who the manufacturer or SBOM author is, so supply "
        "them here. Each flag falls back to the environment variable shown. They "
        "populate metadata.manufacturer, metadata.authors and metadata.component "
        "(CycloneDX output only).",
    )
    for dest, flag, text in (
        ("manufacturer_name", "--manufacturer-name", "Legal name of the product's manufacturer."),
        ("manufacturer_url", "--manufacturer-url", "Manufacturer website URL (valid SBOM creator contact)."),
        ("manufacturer_email", "--manufacturer-email", "Manufacturer contact email."),
        ("author_name", "--author-name", "Name of the person or team that authored the SBOM."),
        ("author_email", "--author-email", "Email of the SBOM author (valid SBOM creator contact)."),
        ("product_name", "--product-name", "Name of the product this SBOM describes (metadata.component)."),
        ("product_version", "--product-version", "Version of the product this SBOM describes."),
    ):
        product.add_argument(
            flag,
            dest=dest,
            default=None,
            metavar="VALUE",
            help=f"{text} Env: {PRODUCT_ENV_VARS[dest]}.",
        )
    product.add_argument(
        "--cra-strict",
        action="store_true",
        help=(
            "Exit with an error before any API calls if the manufacturer name, an "
            "SBOM creator contact, or the product name is missing. Without it, "
            "a warning is logged and the run continues."
        ),
    )

    enrichment = parser.add_argument_group("enrichment")
    enrichment.add_argument(
        "--enrich-maven",
        action="store_true",
        help=(
            "Fill in what Snyk's SBOM omits for pkg:maven components, from Maven "
            "Central: SHA-512 hash (computed from the downloaded jar), supplier "
            "(POM organization), distribution/vcs URLs and filename. Downloads "
            "each unique jar once, so it adds network traffic and run time "
            "(CycloneDX output only)."
        ),
    )

    product.add_argument(
        "--dependency-completeness",
        choices=("unknown", "incomplete", "complete"),
        default="unknown",
        help=(
            "Completeness of the dependency list, written as a CycloneDX "
            "composition (default: unknown). Only assert 'complete' if you have "
            "verified that no vendored or natively linked code is missing."
        ),
    )
    parser.add_argument(
        "--check-cra",
        metavar="FILE",
        default=None,
        help=(
            "Don't generate anything: report which CRA-relevant fields the "
            "CycloneDX SBOM/VEX file FILE lacks, then exit (1 if any are missing, "
            "else 0). Needs no token or network access."
        ),
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
            "decisions."
        ),
    )

    return parser


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parses and validates CLI arguments.

    Exits the process via argparse's usual SystemExit(2) behavior on a
    malformed flag, and on the "at least one source" rule below.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.check_cra:
        return args

    if not any((args.org, args.target, args.asset, args.project, args.group, args.tag)):
        parser.error(
            "at least one source must be supplied: --org, --target, --asset, "
            "--project, --group, or --tag"
        )

    return args
