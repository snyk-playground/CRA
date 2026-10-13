"""Resolves --asset ID to its underlying projects (FR-2a, Open Risk #1).

The requirements doc flagged Asset Inventory API availability as an
open risk: no stable, documented endpoint for "list projects under an
asset ID" was confirmed during research. A live-tenant check while
building this resolver (2026-09-22) found
GET /rest/orgs/{org}/inventory/assets(/{asset}[/relationships/projects])
working, so --asset is implemented against it rather than descoped.
This endpoint is not yet documented as GA at https://apidocs.snyk.io as
of this writing -- re-verify before relying on it long-term.

Like --target and --project, an asset ID alone doesn't say which org it
belongs to (an asset can even span multiple orgs), so this probes every
org the token can access until one of them owns it. The relationship
endpoint returns project stubs without a name, so each is re-fetched
via get_project to get the full project resource (name, type) that
every other resolver returns.
"""

from __future__ import annotations

from typing import List, Sequence

from ..errors import SourceNotFoundError
from ..snyk_api.client import SnykClient
from .base import ResolvedProject, resolved_from_project_resource


def resolve(client: SnykClient, asset_id: str, candidate_org_ids: Sequence[str]) -> List[ResolvedProject]:
    source = f"asset:{asset_id}"
    for org_id in candidate_org_ids:
        if client.get_asset(org_id, asset_id) is None:
            continue
        stubs = client.list_asset_projects(org_id, asset_id) or []
        resolved: List[ResolvedProject] = []
        for stub in stubs:
            project = client.get_project(org_id, stub["id"])
            if project is None:
                continue
            resolved.append(resolved_from_project_resource(org_id, project, source))
        return resolved
    raise SourceNotFoundError(f"--asset {asset_id} not found in any org accessible with this token")
