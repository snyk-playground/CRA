#!/usr/bin/env python3
"""Entry point for the Snyk CRA SBOM/VEX generator.

This file is a thin shim: argument parsing is delegated to
snyk_generate_cra_sbom_vex.cli, and it holds no SBOM/VEX business logic
of its own -- only logging setup and top-level error-handling/exit-code
logic.

This build implements the full pipeline: source resolution/discovery,
per-project SBOM fetch, aggregation into one
CycloneDX document that keeps every duplicate component occurrence
rather than de-duplicating by purl (CycloneDX+JSON only), VEX
derivation from each project's issue/ignore data that de-duplicates
vulnerabilities across those occurrences via the affects array
(CycloneDX+JSON only), and writing the output -- one combined
file for CycloneDX, or a separate SBOM/VEX file pair for SPDX.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional

from snyk_generate_cra_sbom_vex import cli, config, cra_check, discovery, enrich, logging_setup, reporting, sbom, vex, writers
from snyk_generate_cra_sbom_vex.errors import SnykCraSbomVexError
from snyk_generate_cra_sbom_vex.snyk_api.client import SnykClient


def main(argv: Optional[List[str]] = None) -> int:
    args = cli.parse_args(argv)
    print(reporting.render_banner(cli.PROG_NAME, cli.DESCRIPTION), flush=True)

    if args.check_cra:
        try:
            findings = cra_check.check_file(Path(args.check_cra))
        except (OSError, ValueError) as exc:
            print(f"cannot read {args.check_cra} as a CycloneDX JSON file: {exc}", file=sys.stderr)
            return 2
        print(cra_check.render_report(findings), flush=True)
        return 1 if any(not f.ok for f in findings) else 0

    # Configure logging before the token is known so any error raised
    # while resolving it is still reported (nothing sensitive can reach
    # the log at this point, since we never log args.token directly).
    logger = logging_setup.configure(debug=args.debug)

    try:
        run_config = config.build_config(args)
    except SnykCraSbomVexError as exc:
        logger.error(str(exc))
        return exc.exit_code

    # Re-configure now that the token is known, so every subsequent log
    # line has it redacted.
    logger = logging_setup.configure(debug=run_config.debug, redact=[run_config.token])

    missing_cra = run_config.product.missing_cra_fields()
    if missing_cra:
        logger.warning(
            "The SBOM will lack CRA-required identity data: %s. Pass the flags "
            "(or CRA_* environment variables), or use --cra-strict to enforce them.",
            "; ".join(missing_cra),
        )

    if run_config.vex_skip_reason:
        logger.warning(run_config.vex_skip_reason)

    sources = run_config.sources
    logger.info(
        "Resolving %d source argument(s): %d org, %d target, %d asset, %d project, "
        "%d group, %d tag...",
        sources.count(),
        len(sources.orgs),
        len(sources.targets),
        len(sources.assets),
        len(sources.projects),
        len(sources.groups),
        len(sources.tags),
    )

    client = SnykClient(token=run_config.token, api_version=run_config.api_version)

    try:
        projects = discovery.discover(client, sources)
    except SnykCraSbomVexError as exc:
        logger.error(str(exc))
        return exc.exit_code

    in_scope_count = sum(1 for p in projects if p.in_scope)
    org_count = len({p.org_id for p in projects})
    logger.info(
        "Discovered %d unique project(s) across %d org(s): %d in-scope for SBOM/VEX "
        "(Open Source/Container), %d other type(s).",
        len(projects),
        org_count,
        in_scope_count,
        len(projects) - in_scope_count,
    )
    print(reporting.render_projects_table(projects), flush=True)

    try:
        fetch_results = sbom.fetch_sboms(
            client, projects, run_config.sbom_format, fail_fast=run_config.fail_fast,
            show_progress=True,
        )
    except SnykCraSbomVexError as exc:
        logger.error(str(exc))
        return exc.exit_code

    ok_count = sum(1 for r in fetch_results if r.ok)
    fail_count = len(fetch_results) - ok_count
    logger.info(
        "Fetched %d/%d in-scope project SBOM(s) successfully (%d failed, %d skipped as "
        "out-of-scope).",
        ok_count,
        len(fetch_results),
        fail_count,
        len(projects) - len(fetch_results),
    )
    print(reporting.render_sbom_fetch_table(fetch_results), flush=True)

    merge_result = sbom.merge_sboms(
        fetch_results, run_config.sbom_format, run_config.product, run_config.dependency_completeness
    )
    if merge_result.skipped_reason:
        logger.warning(merge_result.skipped_reason)
    print(reporting.render_merge_summary(merge_result), flush=True)

    if run_config.enrich_maven and merge_result.document is not None:
        enrich_result = enrich.enrich_maven_components(merge_result.document, show_progress=True)
        print(reporting.render_enrich_summary(enrich_result), flush=True)

    vex_result = vex.derive_vex(client, fetch_results, merge_result, run_config.generate_vex, show_progress=True)
    if vex_result.skipped_reason:
        logger.warning(vex_result.skipped_reason)
    print(reporting.render_vex_summary(vex_result), flush=True)

    try:
        write_result = writers.write_outputs(
            merge_result.document, vex_result.document, run_config.sbom_format, run_config.output_prefix
        )
    except SnykCraSbomVexError as exc:
        logger.error(str(exc))
        return exc.exit_code
    print(reporting.render_write_summary(write_result), flush=True)
    if merge_result.document is not None:
        report_doc = dict(merge_result.document)
        if vex_result.document:
            report_doc["vulnerabilities"] = vex_result.document.get("vulnerabilities", [])
        print(cra_check.render_report(cra_check.check_document(report_doc)), flush=True)

    return 1 if fail_count else 0


if __name__ == "__main__":
    sys.exit(main())
