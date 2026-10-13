"""Resolves --target ID to the projects under it (FR-2a).

A target ID alone doesn't say which org it belongs to, so this probes
every org the token can access (GET .../targets/{target_id}) until one
of them owns it, then lists that org's projects filtered by target_id.
"""

from __future__ import annotations

from typing import List, Sequence

from ..errors import SourceNotFoundError
from ..snyk_api.client import SnykClient
from .base import ResolvedProject, resolved_from_project_resource


def resolve(client: SnykClient, target_id: str, candidate_org_ids: Sequence[str]) -> List[ResolvedProject]:
    source = f"target:{target_id}"
    for org_id in candidate_org_ids:
        if client.get_target(org_id, target_id) is None:
            continue
        projects = client.list_org_projects(org_id, target_id=target_id) or []
        return [resolved_from_project_resource(org_id, p, source) for p in projects]
    raise SourceNotFoundError(f"--target {target_id} not found in any org accessible with this token")
