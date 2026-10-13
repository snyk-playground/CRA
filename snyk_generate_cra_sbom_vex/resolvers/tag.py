"""Resolves --tag KEY=VALUE across every org the token can access (FR-2a).

A tag isn't scoped to one org (Open Risk #6), so this queries every
accessible org's project listing with the tags filter. Confirmed
against a live tenant while building this resolver (2026-09-22): GET
/rest/orgs/{org}/projects accepts a `tags=key:value` query filter
(colon-separated, url-encoded) -- a REST-API equivalent to the legacy
v1 `tags.includes` filter does exist.

Finding zero matches across every org is a valid outcome (not a
not-found error); the overall "zero projects discovered" check happens
once at the aggregate level in discovery.py.
"""

from __future__ import annotations

from typing import List, Sequence

from ..snyk_api.client import SnykClient
from .base import ResolvedProject, resolved_from_project_resource


def resolve(client: SnykClient, key: str, value: str, all_org_ids: Sequence[str]) -> List[ResolvedProject]:
    source = f"tag:{key}={value}"
    resolved: List[ResolvedProject] = []
    for org_id in all_org_ids:
        projects = client.list_org_projects(org_id, tag=(key, value)) or []
        resolved.extend(resolved_from_project_resource(org_id, p, source) for p in projects)
    return resolved
