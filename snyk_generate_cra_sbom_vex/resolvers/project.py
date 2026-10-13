"""Resolves --project ID directly, with no listing lookup (FR-2a).

A project ID alone doesn't say which org it belongs to either, so --
like --target -- this probes every org the token can access until one
of them owns it.
"""

from __future__ import annotations

from typing import List, Sequence

from ..errors import SourceNotFoundError
from ..snyk_api.client import SnykClient
from .base import ResolvedProject, resolved_from_project_resource


def resolve(client: SnykClient, project_id: str, candidate_org_ids: Sequence[str]) -> List[ResolvedProject]:
    source = f"project:{project_id}"
    for org_id in candidate_org_ids:
        project = client.get_project(org_id, project_id)
        if project is not None:
            return [resolved_from_project_resource(org_id, project, source)]
    raise SourceNotFoundError(f"--project {project_id} not found in any org accessible with this token")
