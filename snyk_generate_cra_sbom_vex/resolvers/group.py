"""Resolves --group ID to every org in the group, then each org's projects (FR-2a)."""

from __future__ import annotations

from typing import List

from ..errors import SourceNotFoundError
from ..snyk_api.client import SnykClient
from .base import ResolvedProject, resolved_from_project_resource


def resolve(client: SnykClient, group_id: str) -> List[ResolvedProject]:
    orgs = client.list_group_orgs(group_id)
    if orgs is None:
        raise SourceNotFoundError(f"--group {group_id} not found (or not accessible with this token)")
    source = f"group:{group_id}"
    resolved: List[ResolvedProject] = []
    for org in orgs:
        org_id = org["id"]
        projects = client.list_org_projects(org_id) or []
        resolved.extend(resolved_from_project_resource(org_id, p, source) for p in projects)
    return resolved
