"""Fetches and aggregates per-project SBOM documents.

Only projects classified in-scope (Open Source/Container --
see resolvers/base.py) are fetched; others are skipped and logged in
debug mode rather than attempted. A single project's fetch
failure is reported and the run continues by default; --fail-fast
aborts the whole run on the first one instead.

Aggregation (merge_sboms) is implemented for CycloneDX+JSON only -- the
format the aggregate document is built in. XML and SPDX SBOMs are still
fetched, but aggregating them is out of scope for now (each has a
meaningfully different merge story: XML needs its own parser, and SPDX
uses packages/relationships rather than components/dependencies) and is
reported back as a skip reason rather than attempted.

Aggregation does not de-duplicate
components by purl: every component occurrence from every
fetched SBOM is kept, each with its own unique bom-ref, so the same
library appearing in more than one project -- or more than once within
a single project -- appears that many times in the output. VEX
de-duplication of vulnerabilities *across* those occurrences is
vex.py's job, using component_lookup below to find every occurrence a
given project-scoped (name, version) maps to.
"""

from __future__ import annotations

import copy
import json
import logging
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from .progress import Progress
from .errors import ProjectFetchError, SnykCraSbomVexError
from .resolvers.base import ResolvedProject
from .snyk_api.client import SnykClient

logger = logging.getLogger(__name__)

TOOL_NAME = "snyk-generate-cra-sbom-vex"
TOOL_VERSION = "0.1.0"


@dataclass(frozen=True)
class SbomFetchResult:
    project: ResolvedProject
    ok: bool
    document: Optional[bytes] = None
    item_count: Optional[int] = None  # components (CycloneDX) or packages (SPDX), if countable
    error: Optional[str] = None


def _count_items(raw: bytes, sbom_format: str) -> Optional[int]:
    if "+json" not in sbom_format:
        return None  # XML formats aren't parsed here; fetch-only, not merge
    try:
        document = json.loads(raw)
    except ValueError:
        return None
    key = "packages" if sbom_format.startswith("spdx") else "components"
    items = document.get(key)
    return len(items) if isinstance(items, list) else None


def fetch_sboms(
    client: SnykClient,
    projects: List[ResolvedProject],
    sbom_format: str,
    fail_fast: bool = False,
    show_progress: bool = False,
) -> List[SbomFetchResult]:
    """Fetches the SBOM for every in-scope project in `projects`.

    Raises ProjectFetchError immediately if fail_fast is set and a fetch
    fails; otherwise records the failure in the returned list and moves
    on to the next project. With show_progress, a status bar tracks
    completed fetches against the number of in-scope projects.
    """
    results: List[SbomFetchResult] = []
    total = sum(1 for p in projects if p.in_scope)
    with Progress("Generating SBOMs", total, enabled=show_progress) as bar:
        _fetch_all(client, projects, sbom_format, fail_fast, results, bar)
    return results


def _fetch_all(client, projects, sbom_format, fail_fast, results, bar) -> None:
    for project in projects:
        if not project.in_scope:
            logger.debug(
                "skipping SBOM fetch for %s/%s (type=%s, not Open Source/Container)",
                project.org_id,
                project.project_id,
                project.project_type,
            )
            continue

        try:
            document = client.get_project_sbom(project.org_id, project.project_id, sbom_format)
        except SnykCraSbomVexError as exc:
            document = None
            error = str(exc)
        else:
            error = None if document is not None else "Snyk SBOM API returned 404 for this project"
        bar.advance()

        if error is not None:
            logger.error(
                "SBOM fetch failed for %s/%s (%s): %s",
                project.org_id,
                project.project_id,
                project.name,
                error,
            )
            if fail_fast:
                raise ProjectFetchError(
                    f"SBOM fetch failed for {project.org_id}/{project.project_id}: {error}"
                )
            results.append(SbomFetchResult(project=project, ok=False, error=error))
            continue

        item_count = _count_items(document, sbom_format)
        logger.debug(
            "fetched SBOM for %s/%s (%s): %d bytes%s",
            project.org_id,
            project.project_id,
            project.name,
            len(document),
            f", {item_count} item(s)" if item_count is not None else "",
        )
        results.append(SbomFetchResult(project=project, ok=True, document=document, item_count=item_count))


# -- aggregate ---------------------------------------------------------

_CYCLONEDX_JSON_FORMAT_RE = re.compile(r"^cyclonedx(?P<spec_version>\d+\.\d+)\+json$")


@dataclass(frozen=True)
class MergeResult:
    document: Optional[Dict[str, Any]]
    component_count: int  # every occurrence kept -- no purl-level de-duplication
    dependency_count: int
    # (org_id, project_id, package_name, package_version) -> every occurrence's
    # bom-ref within that project (usually one, but a package is allowed to
    # appear more than once within a single project too), so vex.py can find
    # every affected occurrence for the VEX affects array without re-deriving
    # _component_identity itself.
    component_lookup: Dict[Tuple[str, str, str, str], List[str]] = field(default_factory=dict)
    skipped_reason: Optional[str] = None


def _component_identity(component: Dict[str, Any]) -> str:
    """The identity used to build a readable bom-ref: a component's purl, or a
    structural fallback.

    Not every component carries a purl -- a Container project's root
    `metadata.component` (the scanned image itself) typically doesn't --
    so those fall back to (type, group, name, version). This is no
    longer a de-duplication key (every occurrence is kept); it only
    makes each occurrence's bom-ref traceable back to what it is.
    """
    purl = component.get("purl")
    if purl:
        return purl
    parts = (
        component.get("type", ""),
        component.get("group", ""),
        component.get("name", ""),
        component.get("version", ""),
    )
    return "no-purl:" + "|".join(parts)


def merge_sboms(fetch_results: List[SbomFetchResult], sbom_format: str) -> MergeResult:
    """Aggregates every successfully fetched SBOM into one CycloneDX document.

    Components are *not* de-duplicated: every occurrence from
    every source document is kept, each assigned its own unique bom-ref
    (identity + source project + an incrementing per-project occurrence
    count, so even the same component appearing twice within one
    project's own SBOM gets two distinct refs). The dependency graph is
    rebuilt on top of that same remapping, since each source document's
    bom-refs are only locally unique (two projects can both label their
    nth component "n-<name>@<version>", which would silently corrupt the
    aggregate edges if left unmapped).
    """
    format_match = _CYCLONEDX_JSON_FORMAT_RE.match(sbom_format)
    if format_match is None:
        return MergeResult(
            document=None,
            component_count=0,
            dependency_count=0,
            component_lookup={},
            skipped_reason=(
                f"aggregation is only implemented for CycloneDX+JSON formats; the "
                f"{sbom_format} SBOMs already fetched were not aggregated."
            ),
        )

    successful = [r for r in fetch_results if r.ok and r.document]
    if not successful:
        return MergeResult(
            document=None,
            component_count=0,
            dependency_count=0,
            component_lookup={},
            skipped_reason="no successfully fetched SBOMs to aggregate",
        )

    components: List[Dict[str, Any]] = []
    dependency_edges: Dict[str, Set[str]] = defaultdict(set)
    component_lookup: Dict[Tuple[str, str, str, str], List[str]] = defaultdict(list)

    for result in successful:
        try:
            source_doc = json.loads(result.document)
        except ValueError:
            logger.warning(
                "could not parse SBOM for %s/%s as JSON; excluded from aggregate",
                result.project.org_id,
                result.project.project_id,
            )
            continue

        project = result.project
        local_components = list(source_doc.get("components") or [])
        root_component = (source_doc.get("metadata") or {}).get("component")
        if root_component:
            local_components = [root_component] + local_components

        local_ref_map: Dict[str, str] = {}
        occurrence_counts: Dict[str, int] = defaultdict(int)

        for component in local_components:
            identity = _component_identity(component)
            occurrence_counts[identity] += 1
            # Unique per occurrence: identity, plus the source project,
            # plus this project's own running count for that identity, so
            # duplicates within a single project's SBOM don't collide either.
            occurrence_ref = f"{identity}#{project.org_id}/{project.project_id}#{occurrence_counts[identity]}"

            local_bom_ref = component.get("bom-ref")
            if local_bom_ref:
                local_ref_map[local_bom_ref] = occurrence_ref

            name, version = component.get("name"), component.get("version")
            if name and version:
                component_lookup[(project.org_id, project.project_id, name, version)].append(occurrence_ref)

            occurrence = copy.deepcopy(component)
            occurrence["bom-ref"] = occurrence_ref
            occurrence["properties"] = list(occurrence.get("properties", [])) + [
                {"name": "snyk:sourceProjectId", "value": f"{project.org_id}/{project.project_id}"}
            ]
            components.append(occurrence)

        for dependency in source_doc.get("dependencies") or []:
            ref = local_ref_map.get(dependency.get("ref"), dependency.get("ref"))
            if ref is None:
                continue
            depends_on = {local_ref_map.get(d, d) for d in dependency.get("dependsOn") or []}
            dependency_edges[ref].update(depends_on)

    # Sorted by bom-ref for idempotency (stable ordering across runs
    # against unchanged input), not to collapse anything.
    components.sort(key=lambda c: c["bom-ref"])
    dependencies = [
        {"ref": ref, "dependsOn": sorted(deps)} for ref, deps in sorted(dependency_edges.items())
    ]

    spec_version = format_match.group("spec_version")
    document = {
        "$schema": f"http://cyclonedx.org/schema/bom-{spec_version}.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        # A fresh serialNumber/timestamp per run is normal CycloneDX practice
        # (they identify *this* BOM generation) and doesn't conflict with
        # the idempotency goal, which is about component/dependency
        # *ordering* being stable so diffs stay meaningful -- both are sorted
        # by bom-ref above for exactly that reason.
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"services": [{"provider": {"name": "Snyk"}, "name": TOOL_NAME, "version": TOOL_VERSION}]},
        },
        "components": components,
        "dependencies": dependencies,
    }

    return MergeResult(
        document=document,
        component_count=len(components),
        dependency_count=len(dependencies),
        component_lookup=dict(component_lookup),
    )
