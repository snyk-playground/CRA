"""Common result type and project-resource mapping shared by every resolver."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

# Best-effort classification of Snyk's per-project `type` attribute into the
# FR-1 scope (Open Source / Container feed the SBOM; everything else -- sast,
# the various *config IaC types, custom -- does not). This list is not
# authoritative: it should be reconciled against Snyk's project-type
# reference before it is used to actually *drop* projects at the SBOM-fetch
# stage. For now it only annotates each discovered project; nothing here is
# filtered out.
_SCA_TYPES = frozenset(
    {
        "npm", "yarn", "pnpm", "gradle", "maven", "sbt", "pip", "poetry", "pipenv",
        "nuget", "paket", "composer", "rubygems", "cocoapods", "gomodules",
        "govendor", "golangdep", "hex", "cran", "swift", "cpp", "conda", "cargo",
    }
)
_CONTAINER_TYPES = frozenset({"dockerfile", "linux", "rpm", "deb", "apk"})


def is_in_scope_type(project_type: str) -> bool:
    """Whether FR-1 would keep a project of this type in the SBOM/VEX output."""
    return (project_type or "").lower() in _SCA_TYPES | _CONTAINER_TYPES


@dataclass(frozen=True)
class ResolvedProject:
    """One (org, project) pair pulled in by a specific source argument (FR-2a)."""

    org_id: str
    project_id: str
    name: str
    project_type: str
    source: str  # e.g. "org:acme-platform", "tag:team=unicorn"
    in_scope: bool


def resolved_from_project_resource(org_id: str, project: Dict[str, Any], source: str) -> ResolvedProject:
    """Builds a ResolvedProject from a Snyk REST `project` resource object."""
    attrs = project.get("attributes") or {}
    project_type = attrs.get("type", "")
    return ResolvedProject(
        org_id=org_id,
        project_id=project["id"],
        name=attrs.get("name", ""),
        project_type=project_type,
        source=source,
        in_scope=is_in_scope_type(project_type),
    )
