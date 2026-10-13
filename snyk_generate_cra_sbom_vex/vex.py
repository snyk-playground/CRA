"""Derives a CycloneDX VEX document from each project's issue/ignore data (FR-9, FR-3, FR-4).

Open Risk #2 asked which API is authoritative for ignore-reason
metadata. Confirmed against the live OpenAPI spec
(https://api.snyk.io/rest/openapi/{api-version}) while building this
module: the REST issues endpoint's `attributes.ignored` is only a
boolean, and its `relationships.ignore` is an opaque {id, type:
"ignore"} reference with no path in this API version to fetch the
ignore's actual reason/expiry. That detail is only available from the
legacy v1 `GET /v1/org/{org}/project/{project}/ignores` endpoint, keyed
by issue ID, in the reasonType/reason/expires shape FR-3's mapping
table is written against -- so this module reads the vulnerability list
from the REST API and ignore reasons from the legacy v1 API.

VEX entries are cross-referenced to the aggregate SBOM via
MergeResult.component_lookup (built while aggregating, from the same
project-scoped package name/version each issue's `coordinates` report),
so VEX can only be derived once an aggregate SBOM exists (FR-3: "only
CycloneDX+JSON" aggregates have one).

Per FR-9a (v0.6), a vulnerability that affects more than one component
occurrence -- because the same underlying vulnerability surfaces as a
distinct per-project issue in every project a package appears in, and/or
FR-8 now keeps every duplicate occurrence rather than collapsing them --
is de-duplicated to exactly one vulnerability entry, listing every
affected occurrence in its `affects` array and an `snyk:occurrenceCount`
property. Grouping is keyed on the underlying vulnerability identifier
(CVE, or the Snyk vulnerability key as a fallback -- see
_preferred_vuln_id), never the per-project issue ID, since the issue ID
differs project to project for the same flaw (Open Risk #8). If the
resolved per-occurrence analysis states disagree (e.g. ignored in one
project but not another), the least-suppressed state wins (open/
unignored beats any ignored state) and the conflict is reported back to
the caller.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .progress import Progress
from .sbom import MergeResult, SbomFetchResult
from .snyk_api.client import SnykClient

logger = logging.getLogger(__name__)

# CycloneDX's fixed vocabulary for analysis.justification -- it is a code,
# not free text (FR-4 explicitly warns against "guessing a justification
# code"), so a Snyk ignore comment is only used here when it already reads
# as one of these, never paraphrased or inferred.
_VALID_JUSTIFICATION_CODES = {
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
}
_NON_ALNUM_RE = re.compile(r"[\s\-]+")

# FR-9a's "least-suppressed state" ordering: lower rank wins a conflict.
# Plain open/unignored is least suppressed; a wont-fix override is still
# CycloneDX state "exploitable" but is nonetheless a suppression decision,
# so it ranks just below plain-open; not_affected is the most suppressed.
_RANK_OPEN = 0
_RANK_WONT_FIX = 1
_RANK_IN_TRIAGE = 2
_RANK_NOT_AFFECTED = 3
_RANK_OTHER = 4


@dataclass(frozen=True)
class VexBuildResult:
    document: Optional[Dict[str, Any]]
    vulnerability_count: int  # unique vulnerabilities after FR-9a de-duplication
    needs_manual_justification: int  # FR-4: ignores flagged for manual review rather than guessed
    unmatched_count: int  # issues that couldn't be linked to an aggregate SBOM component
    conflicting_state_count: int  # FR-9a: vulnerabilities whose per-occurrence states disagreed
    skipped_reason: Optional[str] = None


@dataclass(frozen=True)
class _Occurrence:
    component_ref: str
    analysis: Dict[str, Any]
    org_id: str
    project_id: str


def _normalize_justification_code(reason_text: str) -> Optional[str]:
    normalized = _NON_ALNUM_RE.sub("_", reason_text.strip().lower())
    return normalized if normalized in _VALID_JUSTIFICATION_CODES else None


def _extract_ignore_details(ignores_for_issue: Optional[List[Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
    """Unwraps the legacy v1 shape: [{path_or_"*": details}, ...] -> details.

    A project can carry more than one ignore rule per issue (e.g. one per
    dependency path); this script isn't dependency-path-granular, so it
    takes the first rule as the project-level determination.
    """
    if not ignores_for_issue:
        return None
    first_entry = ignores_for_issue[0]
    if not isinstance(first_entry, dict) or not first_entry:
        return None
    return next(iter(first_entry.values()), None)


def _preferred_vuln_id(issue_attrs: Dict[str, Any]) -> str:
    for problem in issue_attrs.get("problems") or []:
        if problem.get("source") == "NVD" and str(problem.get("id", "")).startswith("CVE-"):
            return problem["id"]
    return issue_attrs.get("key") or ""


def _build_analysis(ignore_details: Optional[Dict[str, Any]]) -> Tuple[Dict[str, Any], bool]:
    """Returns (analysis block, needs_manual_justification) per FR-3's table / FR-4."""
    if ignore_details is None:
        return {"state": "exploitable"}, False

    reason_type = ignore_details.get("reasonType")
    reason_text = (ignore_details.get("reason") or "").strip()

    if reason_type == "wont-fix":
        analysis = {"state": "exploitable", "response": ["will_not_fix"]}
        if reason_text:
            analysis["detail"] = reason_text
        return analysis, False

    if reason_type == "temporary-ignore":
        # CycloneDX's analysis object has no dedicated "review by" field, so
        # the ignore's expiry (FR-3: "must carry the ignore's expiry/review
        # date") is surfaced as free text in `detail` rather than forced
        # into a semantically mismatched field.
        expires = ignore_details.get("expires")
        detail_parts = [p for p in (f"Scheduled for review by {expires}." if expires else None, reason_text) if p]
        analysis = {"state": "in_triage"}
        if detail_parts:
            analysis["detail"] = " ".join(detail_parts)
        return analysis, False

    if reason_type == "not-vulnerable":
        justification_code = _normalize_justification_code(reason_text) if reason_text else None
        if justification_code is None:
            # FR-4: never fabricate a justification code from free text --
            # fall back to in_triage and flag for manual review instead.
            analysis = {"state": "in_triage"}
            if reason_text:
                analysis["detail"] = reason_text
            return analysis, True
        return {"state": "not_affected", "justification": justification_code, "detail": reason_text}, False

    # An ignore exists but with a reasonType FR-3's table doesn't cover (or
    # the ignore lookup found something structurally unexpected) -- treat
    # conservatively as needing manual review rather than guessing.
    return {"state": "in_triage"}, True


def _suppression_rank(analysis: Dict[str, Any]) -> int:
    """FR-9a's least-suppressed-state ordering; lower wins a conflict."""
    state = analysis.get("state")
    if state == "exploitable":
        return _RANK_WONT_FIX if "will_not_fix" in (analysis.get("response") or []) else _RANK_OPEN
    if state == "in_triage":
        return _RANK_IN_TRIAGE
    if state == "not_affected":
        return _RANK_NOT_AFFECTED
    return _RANK_OTHER


def _match_component_refs(
    issue_attrs: Dict[str, Any],
    component_lookup: Dict[Tuple[str, str, str, str], List[str]],
    org_id: str,
    project_id: str,
) -> List[str]:
    for coordinate in issue_attrs.get("coordinates") or []:
        for representation in coordinate.get("representations") or []:
            dependency = representation.get("dependency") or {}
            name, version = dependency.get("package_name"), dependency.get("package_version")
            if name and version:
                refs = component_lookup.get((org_id, project_id, name, version))
                if refs:
                    return refs
    return []


def derive_vex(
    client: SnykClient,
    fetch_results: List[SbomFetchResult],
    merge_result: MergeResult,
    generate_vex: bool,
    show_progress: bool = False,
) -> VexBuildResult:
    """Builds the aggregate VEX document from every successfully fetched project's issues.

    Raises nothing project-specific: an issue that can't be matched to an
    aggregate component, or an ignore lacking a recognized justification,
    is counted and reported rather than treated as a fatal error (FR-14's
    "continue past a single project's failure" spirit extended to
    per-issue anomalies). Per FR-9a, occurrences of the same underlying
    vulnerability (by vuln ID, across projects and across duplicate
    component occurrences within a project) are grouped into one
    vulnerability entry before the document is built.
    """
    if not generate_vex:
        return VexBuildResult(
            document=None,
            vulnerability_count=0,
            needs_manual_justification=0,
            unmatched_count=0,
            conflicting_state_count=0,
            skipped_reason="VEX generation disabled (--no-vex, or --sbom-format is not CycloneDX+JSON)",
        )

    if merge_result.document is None:
        return VexBuildResult(
            document=None,
            vulnerability_count=0,
            needs_manual_justification=0,
            unmatched_count=0,
            conflicting_state_count=0,
            skipped_reason=(
                "no aggregate SBOM to cross-reference (aggregation was skipped: "
                f"{merge_result.skipped_reason})"
            ),
        )

    occurrences_by_vuln: Dict[str, List[_Occurrence]] = defaultdict(list)
    needs_manual = 0
    unmatched = 0

    ok_results = [r for r in fetch_results if r.ok]
    with Progress("Generating VEX data", len(ok_results), enabled=show_progress) as bar:
        for result in ok_results:
            project = result.project
            issues = client.list_project_issues(project.org_id, project.project_id)
            ignores = client.get_project_ignores(project.org_id, project.project_id)

            for issue in issues:
                attrs = issue.get("attributes") or {}
                if attrs.get("type") != "package_vulnerability":
                    continue  # license/config/code findings aren't SBOM components (FR-1's scope, extended)

                component_refs = _match_component_refs(attrs, merge_result.component_lookup, project.org_id, project.project_id)
                if not component_refs:
                    unmatched += 1
                    logger.debug(
                        "could not match issue %s in %s/%s to an aggregate SBOM component; skipped",
                        attrs.get("key"),
                        project.org_id,
                        project.project_id,
                    )
                    continue

                ignore_details = _extract_ignore_details(ignores.get(attrs.get("key")))
                analysis, needs_review = _build_analysis(ignore_details)
                if needs_review:
                    needs_manual += 1
                    logger.warning(
                        "manual justification required for %s in %s/%s: the ignore's reason "
                        "doesn't map to a recognized justification code, so in_triage was "
                        "emitted instead of not_affected (FR-4)",
                        attrs.get("key"),
                        project.org_id,
                        project.project_id,
                    )

                vuln_id = _preferred_vuln_id(attrs)
                for component_ref in component_refs:
                    occurrences_by_vuln[vuln_id].append(
                        _Occurrence(
                            component_ref=component_ref,
                            analysis=analysis,
                            org_id=project.org_id,
                            project_id=project.project_id,
                        )
                    )

            bar.advance()

    vulnerabilities: List[Dict[str, Any]] = []
    conflicting_states = 0

    for vuln_id in sorted(occurrences_by_vuln):
        occurrences = occurrences_by_vuln[vuln_id]
        affects = sorted({o.component_ref for o in occurrences})

        ranks = {_suppression_rank(o.analysis) for o in occurrences}
        if len(ranks) > 1:
            conflicting_states += 1
            logger.warning(
                "conflicting per-occurrence VEX state collapsed for %s across %d occurrence(s): "
                "resolved to the least-suppressed state (FR-9a)",
                vuln_id,
                len(occurrences),
            )
        winning_analysis = min(occurrences, key=lambda o: _suppression_rank(o.analysis)).analysis

        vulnerabilities.append(
            {
                "bom-ref": f"vuln-{vuln_id}",
                "id": vuln_id,
                "affects": [{"ref": ref} for ref in affects],
                "analysis": winning_analysis,
                "properties": [{"name": "snyk:occurrenceCount", "value": str(len(affects))}],
            }
        )

    document = {
        "bomFormat": "CycloneDX",
        "specVersion": merge_result.document["specVersion"],
        # Shared with the aggregate SBOM so a VEX consumer can cross-reference
        # the two documents as one unit (FR-3).
        "serialNumber": merge_result.document["serialNumber"],
        "version": 1,
        "vulnerabilities": vulnerabilities,
    }

    return VexBuildResult(
        document=document,
        vulnerability_count=len(vulnerabilities),
        needs_manual_justification=needs_manual,
        unmatched_count=unmatched,
        conflicting_state_count=conflicting_states,
    )
