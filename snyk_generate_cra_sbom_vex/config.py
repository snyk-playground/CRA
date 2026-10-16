"""Builds a single immutable RunConfig from parsed CLI args and the environment.

config.py is the only module besides cli.py that is allowed to read
os.environ -- everything downstream (discovery, sbom, vex,
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
# updated. Snyk's REST API versions are dated and evolve
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
    """The raw, as-supplied values for each of the six source flags."""

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


# Product/creator identity flags. Snyk cannot supply these (they describe the
# party placing the product on the EU market), so they come from the operator,
# either as a flag or as the matching environment variable.
PRODUCT_ENV_VARS = {
    "manufacturer_name": "CRA_MANUFACTURER_NAME",
    "manufacturer_url": "CRA_MANUFACTURER_URL",
    "manufacturer_email": "CRA_MANUFACTURER_EMAIL",
    "author_name": "CRA_AUTHOR_NAME",
    "author_email": "CRA_AUTHOR_EMAIL",
    "product_name": "CRA_PRODUCT_NAME",
    "product_version": "CRA_PRODUCT_VERSION",
}


@dataclass(frozen=True)
class ProductMetadata:
    """Operator-supplied identity written to the SBOM's metadata block."""

    manufacturer_name: Optional[str] = None
    manufacturer_url: Optional[str] = None
    manufacturer_email: Optional[str] = None
    author_name: Optional[str] = None
    author_email: Optional[str] = None
    product_name: Optional[str] = None
    product_version: Optional[str] = None

    def missing_cra_fields(self) -> Tuple[str, ...]:
        """Human-readable list of CRA-relevant identity data that is absent.

        BSI TR-03183-2 needs a creator contact (email or URL) for the SBOM, and
        the SBOM should identify the product it describes.
        """
        missing = []
        if not self.manufacturer_name:
            missing.append("manufacturer name (--manufacturer-name)")
        if not (self.author_email or self.manufacturer_email or self.manufacturer_url):
            missing.append(
                "SBOM creator contact (--author-email, --manufacturer-email or --manufacturer-url)"
            )
        if not self.product_name:
            missing.append("product name (--product-name)")
        return tuple(missing)


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
    product: ProductMetadata = ProductMetadata()
    cra_strict: bool = False
    enrich_maven: bool = False
    dependency_completeness: str = "unknown"


def resolve_token(args: argparse.Namespace) -> str:
    """Resolves the API token --token takes precedence over SNYK_TOKEN."""
    token = args.token or os.environ.get("SNYK_TOKEN")
    if not token:
        raise ConfigError(
            "No Snyk API token supplied. Set the SNYK_TOKEN environment variable "
            "or pass --token."
        )
    return token


def resolve_api_version(args: argparse.Namespace) -> str:
    """Resolves the API version: --api-version, then $SNYK_API_VERSION, then the
    hardcoded default ."""
    return args.api_version or os.environ.get(API_VERSION_ENV_VAR) or DEFAULT_API_VERSION


def resolve_product(args: argparse.Namespace) -> ProductMetadata:
    """Resolves each identity field: flag first, then its CRA_* environment variable."""
    values = {}
    for field, env_var in PRODUCT_ENV_VARS.items():
        value = getattr(args, field, None) or os.environ.get(env_var)
        values[field] = value.strip() if value and value.strip() else None
    return ProductMetadata(**values)


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
            "SPDX, so VEX generation will be skipped."
        )

    product = resolve_product(args)
    cra_strict = bool(getattr(args, "cra_strict", False))
    if cra_strict and product.missing_cra_fields():
        raise ConfigError(
            "--cra-strict: missing required CRA identity data: "
            + "; ".join(product.missing_cra_fields())
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
        product=product,
        cra_strict=cra_strict,
        enrich_maven=bool(getattr(args, "enrich_maven", False)),
        dependency_completeness=getattr(args, "dependency_completeness", "unknown"),
    )
