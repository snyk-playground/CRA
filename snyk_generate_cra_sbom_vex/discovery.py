"""Unions every resolver's output and de-duplicates by (org, project) (FR-2a, FR-6).

FR-1's Open Source/Container scoping is annotated on each ResolvedProject
(see resolvers/base.py) but not yet enforced here by dropping rows --
that gate belongs to the SBOM-fetch stage, not yet implemented.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Dict, List, Optional, Tuple

from .config import SourceSelection
from .errors import NoProjectsDiscoveredError
from .resolvers import asset as asset_resolver
from .resolvers import group as group_resolver
from .resolvers import org as org_resolver
from .resolvers import project as project_resolver
from .resolvers import tag as tag_resolver
from .resolvers import target as target_resolver
from .resolvers.base import ResolvedProject
from .snyk_api.client import SnykClient

logger = logging.getLogger(__name__)


def discover(client: SnykClient, sources: SourceSelection) -> List[ResolvedProject]:
    """Resolves every supplied source and returns the de-duplicated union.

    Raises NoProjectsDiscoveredError if the union is empty, and whatever
    SourceNotFoundError/AuthenticationError a resolver raises for an
    individual source (FR-14: these are unrecoverable, not per-project,
    failures).
    """
    org_ids_cache: Optional[List[str]] = None

    def known_org_ids() -> List[str]:
        # --target/--project/--asset/--tag don't come with a known org, so
        # they search across every org the token can access. Fetched once
        # and reused, since the set doesn't change mid-run.
        nonlocal org_ids_cache
        if org_ids_cache is None:
            org_ids_cache = [org["id"] for org in client.list_orgs()]
            logger.debug("token can access %d org(s): %s", len(org_ids_cache), org_ids_cache)
        return org_ids_cache

    resolved: List[ResolvedProject] = []

    for org_id in sources.orgs:
        found = org_resolver.resolve(client, org_id)
        logger.debug("--org %s resolved to %d project(s)", org_id, len(found))
        resolved.extend(found)

    for group_id in sources.groups:
        found = group_resolver.resolve(client, group_id)
        logger.debug("--group %s resolved to %d project(s)", group_id, len(found))
        resolved.extend(found)

    for target_id in sources.targets:
        found = target_resolver.resolve(client, target_id, known_org_ids())
        logger.debug("--target %s resolved to %d project(s)", target_id, len(found))
        resolved.extend(found)

    for project_id in sources.projects:
        found = project_resolver.resolve(client, project_id, known_org_ids())
        logger.debug("--project %s resolved to %d project(s)", project_id, len(found))
        resolved.extend(found)

    for asset_id in sources.assets:
        found = asset_resolver.resolve(client, asset_id, known_org_ids())
        logger.debug("--asset %s resolved to %d project(s)", asset_id, len(found))
        resolved.extend(found)

    for key, value in sources.tags:
        found = tag_resolver.resolve(client, key, value, known_org_ids())
        logger.debug("--tag %s=%s resolved to %d project(s)", key, value, len(found))
        resolved.extend(found)

    deduped = _deduplicate(resolved)
    if not deduped:
        raise NoProjectsDiscoveredError(
            "zero projects discovered after resolving and unioning all supplied sources"
        )
    return deduped


def _deduplicate(resolved: List[ResolvedProject]) -> List[ResolvedProject]:
    """Collapses to one entry per (org, project), combining the source labels
    of every argument that pulled it in, and sorts for stable output (NFR-2).
    """
    by_key: Dict[Tuple[str, str], ResolvedProject] = {}
    sources_by_key: Dict[Tuple[str, str], List[str]] = {}
    for item in resolved:
        key = (item.org_id, item.project_id)
        if key not in by_key:
            by_key[key] = item
            sources_by_key[key] = [item.source]
        elif item.source not in sources_by_key[key]:
            sources_by_key[key].append(item.source)

    result = []
    for key, item in by_key.items():
        combined_source = ", ".join(sources_by_key[key])
        result.append(replace(item, source=combined_source) if combined_source != item.source else item)

    result.sort(key=lambda p: (p.org_id, p.project_id))
    return result
