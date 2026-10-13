"""Renders discovery/fetch/merge/VEX results, and the files written, for terminal output.

This module owns presentation only; writers.py does the actual file I/O.
"""

from __future__ import annotations

from typing import List, Sequence, Tuple

from .resolvers.base import ResolvedProject
from .sbom import MergeResult, SbomFetchResult
from .vex import VexBuildResult
from .writers import WriteResult

_PROJECTS_HEADERS = ("ORG", "PROJECT", "TYPE", "SCOPE", "NAME", "SOURCE(S)")
_SBOM_HEADERS = ("ORG", "PROJECT", "NAME", "STATUS", "ITEMS", "BYTES", "DETAIL")


def _render_table(headers: Sequence[str], rows: Sequence[Tuple[str, ...]]) -> str:
    if not rows:
        return "(none)"

    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(row: Tuple[str, ...]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))

    lines = [fmt_row(headers), "  ".join("-" * w for w in widths)]
    lines.extend(fmt_row(row) for row in rows)
    return "\n".join(lines)


def render_projects_table(projects: List[ResolvedProject]) -> str:
    rows = [
        (
            p.org_id,
            p.project_id,
            p.project_type or "-",
            "in-scope" if p.in_scope else "skip",
            p.name or "-",
            p.source,
        )
        for p in projects
    ]
    return _render_table(_PROJECTS_HEADERS, rows)


def render_sbom_fetch_table(results: List[SbomFetchResult]) -> str:
    rows = []
    for r in results:
        rows.append(
            (
                r.project.org_id,
                r.project.project_id,
                r.project.name or "-",
                "ok" if r.ok else "FAILED",
                str(r.item_count) if r.item_count is not None else "-",
                str(len(r.document)) if r.document is not None else "-",
                "-" if r.ok else (r.error or ""),
            )
        )
    return _render_table(_SBOM_HEADERS, rows)


def render_merge_summary(result: MergeResult) -> str:
    if result.skipped_reason:
        return f"Merge skipped: {result.skipped_reason}"
    return (
        f"Aggregated {result.component_count} component occurrence(s) across all fetched "
        f"SBOMs (no de-duplication -- every occurrence is kept per FR-8), "
        f"{result.dependency_count} dependency edge(s). "
        f"serialNumber={result.document['serialNumber']}"
    )


def render_vex_summary(result: VexBuildResult) -> str:
    if result.skipped_reason:
        return f"VEX skipped: {result.skipped_reason}"
    warnings = []
    if result.needs_manual_justification:
        warnings.append(f"{result.needs_manual_justification} need manual justification (FR-4)")
    if result.unmatched_count:
        warnings.append(f"{result.unmatched_count} could not be matched to an aggregate SBOM component")
    if result.conflicting_state_count:
        warnings.append(
            f"{result.conflicting_state_count} had conflicting per-occurrence states collapsed (FR-9a)"
        )
    suffix = f" ({'; '.join(warnings)})" if warnings else ""
    return f"Derived {result.vulnerability_count} unique VEX entry(ies) (de-duplicated across occurrences, FR-9a){suffix}."


def render_write_summary(result: WriteResult) -> str:
    sbom_line = (
        f"SBOM: {result.sbom_path}" if result.sbom_path is not None else "SBOM: (not written -- nothing to write)"
    )
    if result.vex_embedded:
        vex_line = f"VEX: embedded in SBOM file ({result.sbom_path})"
    elif result.vex_path is not None:
        vex_line = f"VEX: {result.vex_path}"
    else:
        vex_line = "VEX: (not written -- nothing to write)"
    return "\n".join([sbom_line, vex_line])
