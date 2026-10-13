"""Resolves --org ID to every in-scope-or-not project in that org (FR-2a)."""

from __future__ import annotations

from typing import List

from ..errors import SourceNotFoundError
from ..snyk_api.client import SnykClient
from .base import ResolvedProject, resolved_from_project_resource


def resolve(client: SnykClient, org_id: str) -> List[ResolvedProject]:
    projects = client.list_org_projects(org_id)
    if projects is None:
        raise SourceNotFoundError(f"--org {org_id} not found (or not accessible with this token)")
    source = f"org:{org_id}"
    return [resolved_from_project_resource(org_id, p, source) for p in projects]
