"""Builds a single immutable RunConfig from parsed CLI args and the environment (FR-5).

config.py is the only module besides cli.py that is allowed to read
os.environ (see §8.3) -- everything downstream (discovery, sbom, vex,
writers) takes a RunConfig, never argparse.Namespace or the environment
directly.
"""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from typing import Optional, Tuple

from .errors import ConfigError

SPDX_FORMAT_PREFIX = "spdx"

# Latest known-GA Snyk REST API version at the time this script was last
# updated (FR-12). Snyk's REST API versions are dated and evolve
# independently of this script -- reverify against
# https://apidocs.snyk.io before relying on this default long-term (Open
# Risk #3). SNYK_API_VERSION lets an operator override the effective
# default without editing source, e.g. once this pinned value is
# deprecated and before a code change ships; --api-version still wins
# over both.
DEFAULT_API_VERSION = "2024-10-15"
API_VERSION_ENV_VAR = "SNYK_API_VERSION"


@dataclass(frozen=True)
class SourceSelection:
    """The raw, as-supplied values for each of the six source flags (FR-2)."""

    orgs: Tuple[str, ...]
    targets: Tuple[str, ...]
    assets: Tuple[str, ...]
    projects: Tuple[str, ...]
    groups: Tuple[str, ...]
    tags: Tuple[Tuple[str, str], ...]

    def is_empty(self) -> bool:
        return not any(
            (self.orgs, self.targets, self.assets, self.projects, self.groups, self.tags)
        )

    def count(self) -> int:
        return (
            len(self.orgs)
            + len(self.targets)
            + len(self.assets)
            + len(self.projects)
            + len(self.groups)
            + len(self.tags)
        )


@dataclass(frozen=True)
class RunConfig:
    """Fully resolved, immutable configuration for a single run."""

    sources: SourceSelection
    token: str
    sbom_format: str
    api_version: str
    output_prefix: Optional[str]
    generate_vex: bool
    vex_skip_reason: Optional[str]
    fail_fast: bool
    debug: bool


def resolve_token(args: argparse.Namespace) -> str:
    """Resolves the API token per FR-5: --token takes precedence over SNYK_TOKEN."""
    token = args.token or os.environ.get("SNYK_TOKEN")
    if not token:
        raise ConfigError(
            "No Snyk API token supplied. Set the SNYK_TOKEN environment variable "
            "or pass --token."
        )
    return token


def resolve_api_version(args: argparse.Namespace) -> str:
    """Resolves the API version: --api-version, then $SNYK_API_VERSION, then the
    hardcoded default (FR-12, Open Risk #3)."""
    return args.api_version or os.environ.get(API_VERSION_ENV_VAR) or DEFAULT_API_VERSION


def build_config(args: argparse.Namespace) -> RunConfig:
    """Builds a RunConfig from parsed CLI args, raising ConfigError on invalid input."""
    token = resolve_token(args)

    sources = SourceSelection(
        orgs=tuple(args.org),
        targets=tuple(args.target),
        assets=tuple(args.asset),
        projects=tuple(args.project),
        groups=tuple(args.group),
        tags=tuple(args.tag),
    )
    if sources.is_empty():
        # cli.parse_args already enforces this; re-checked here so build_config is
        # safe to call on its own (e.g. from tests) without going through argparse.
        raise ConfigError(
            "at least one source must be supplied: --org, --target, --asset, "
            "--project, --group, or --tag"
        )

    generate_vex = not args.no_vex
    vex_skip_reason: Optional[str] = None
    if generate_vex and args.sbom_format.startswith(SPDX_FORMAT_PREFIX):
        generate_vex = False
        vex_skip_reason = (
            f"--sbom-format {args.sbom_format} selected; VEX is not defined for "
            "SPDX, so VEX generation will be skipped (FR-11)."
        )

    return RunConfig(
        sources=sources,
        token=token,
        sbom_format=args.sbom_format,
        api_version=resolve_api_version(args),
        output_prefix=args.output_prefix,
        generate_vex=generate_vex,
        vex_skip_reason=vex_skip_reason,
        fail_fast=args.fail_fast,
        debug=args.debug,
    )
