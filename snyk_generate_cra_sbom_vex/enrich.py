"""Optional enrichment of aggregate SBOM components from Maven Central.

Snyk's SBOM API doesn't report a component's supplier, content hash,
filename or distribution/source URIs, all of which BSI TR-03183-2
expects for a CRA-aligned SBOM. For `pkg:maven` components this module
fills them in from Maven Central:

- hashes: SHA-512 of the published jar, computed here from the
  downloaded bytes (Central doesn't publish .sha512 files for most
  artifacts, and a hash we compute is verifiable);
- supplier: the POM's <organization> (name and url), looked up through
  the <parent> chain when the artifact's own POM omits it;
- externalReferences: `distribution` (the jar URL) and `vcs` (POM <scm>);
- the `bsi:component:filename` property.

Only data Central actually returns is written -- a supplier is never
guessed from the groupId -- and values already present on a component
are left alone. Components that aren't `pkg:maven`, or whose jar isn't on
Central (e.g. pom-only artifacts), are counted and left unchanged.
Lookups are made once per unique group:artifact:version, however many
occurrences the aggregate SBOM holds.
"""

from __future__ import annotations

import hashlib
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from .progress import Progress

logger = logging.getLogger(__name__)

MAVEN_CENTRAL_URL = "https://repo1.maven.org/maven2"
FILENAME_PROPERTY = "bsi:component:filename"
_PURL_RE = re.compile(r"^pkg:maven/([^/@?#]+)/([^/@?#]+)@([^?#]+)")
_MAX_PARENT_DEPTH = 5
_WORKERS = 8
_CHUNK = 1 << 16

# fetch(url) -> an iterator of byte chunks, or None when the URL is absent (404).
Fetcher = Callable[[str], Optional[Any]]
Coordinate = Tuple[str, str, str]


@dataclass(frozen=True)
class EnrichResult:
    component_count: int = 0
    unique_artifacts: int = 0
    hashed: int = 0  # components given a hash
    supplier: int = 0  # components given a supplier
    skipped_non_maven: int = 0
    not_found: int = 0  # unique artifacts with no jar on Central


@dataclass(frozen=True)
class _Artifact:
    jar_url: Optional[str] = None
    filename: Optional[str] = None
    sha512: Optional[str] = None
    supplier: Optional[Dict[str, Any]] = None
    scm_url: Optional[str] = None


def http_fetch(url: str, timeout: float = 60.0) -> Optional[Any]:
    """Streams a URL's body in chunks; None on 404."""
    request = urllib.request.Request(url, headers={"User-Agent": "snyk-generate-cra-sbom-vex"})
    try:
        response = urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        exc.close()
        if exc.code == 404:
            return None
        raise
    return _stream(response)


def _stream(response: Any) -> Any:
    with response:
        while True:
            chunk = response.read(_CHUNK)
            if not chunk:
                return
            yield chunk


def parse_maven_purl(purl: Optional[str]) -> Optional[Coordinate]:
    match = _PURL_RE.match(purl or "")
    if not match:
        return None
    return tuple(urllib.parse.unquote(g) for g in match.groups())  # type: ignore[return-value]


def _base(coord: Coordinate, base_url: str) -> str:
    group, artifact, version = coord
    return f"{base_url}/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}"


def _read(fetch: Fetcher, url: str) -> Optional[bytes]:
    stream = fetch(url)
    return None if stream is None else b"".join(stream)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(element: Optional[ET.Element], name: str) -> Optional[ET.Element]:
    if element is None:
        return None
    return next((c for c in element if _local(c.tag) == name), None)


def _text(element: Optional[ET.Element], name: str) -> Optional[str]:
    node = _child(element, name)
    value = node.text.strip() if node is not None and node.text else ""
    return value or None


def _pom_metadata(coord: Coordinate, fetch: Fetcher, base_url: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """(supplier, scm url) from the POM, following <parent> for what it omits."""
    supplier: Optional[Dict[str, Any]] = None
    scm_url: Optional[str] = None
    current: Optional[Coordinate] = coord
    for _ in range(_MAX_PARENT_DEPTH):
        if current is None:
            break
        try:
            data = _read(fetch, _base(current, base_url) + ".pom")
            root = ET.fromstring(data) if data else None
        except (urllib.error.URLError, OSError, ET.ParseError) as exc:
            logger.debug("could not read POM for %s: %s", ":".join(current), exc)
            break
        if root is None:
            break
        if supplier is None:
            org = _child(root, "organization")
            name = _text(org, "name")
            if name:
                supplier = {"name": name}
                url = _text(org, "url")
                if url:
                    supplier["url"] = [url]
        if scm_url is None:
            scm_url = _text(_child(root, "scm"), "url")
        if supplier and scm_url:
            break
        parent = _child(root, "parent")
        parts = [_text(parent, k) for k in ("groupId", "artifactId", "version")]
        current = (parts[0], parts[1], parts[2]) if all(parts) else None  # type: ignore[assignment]
    return supplier, scm_url


def _lookup(coord: Coordinate, fetch: Fetcher, base_url: str) -> _Artifact:
    jar_url = _base(coord, base_url) + ".jar"
    sha512: Optional[str] = None
    try:
        stream = fetch(jar_url)
        if stream is not None:
            digest = hashlib.sha512()
            for chunk in stream:
                digest.update(chunk)
            sha512 = digest.hexdigest()
    except (urllib.error.URLError, OSError) as exc:
        logger.warning("could not download %s: %s", jar_url, exc)
    supplier, scm_url = _pom_metadata(coord, fetch, base_url)
    return _Artifact(
        jar_url=jar_url if sha512 else None,
        filename=f"{coord[1]}-{coord[2]}.jar" if sha512 else None,
        sha512=sha512,
        supplier=supplier,
        scm_url=scm_url,
    )


def _apply(component: Dict[str, Any], art: _Artifact) -> Tuple[bool, bool]:
    """Adds missing fields; returns (hash added, supplier added)."""
    hashed = supplied = False
    if art.sha512 and not component.get("hashes"):
        component["hashes"] = [{"alg": "SHA-512", "content": art.sha512}]
        hashed = True
    if art.supplier and not component.get("supplier"):
        component["supplier"] = dict(art.supplier)
        supplied = True
    refs = component.setdefault("externalReferences", [])
    existing = {r.get("type") for r in refs}
    if art.jar_url and "distribution" not in existing:
        refs.append({"type": "distribution", "url": art.jar_url})
    if art.scm_url and "vcs" not in existing:
        refs.append({"type": "vcs", "url": art.scm_url})
    if not refs:
        del component["externalReferences"]
    if art.filename:
        props = component.setdefault("properties", [])
        if not any(p.get("name") == FILENAME_PROPERTY for p in props):
            props.append({"name": FILENAME_PROPERTY, "value": art.filename})
    return hashed, supplied


def enrich_maven_components(
    document: Dict[str, Any],
    fetch: Fetcher = http_fetch,
    base_url: str = MAVEN_CENTRAL_URL,
    show_progress: bool = False,
) -> EnrichResult:
    """Enriches `document`'s components in place from Maven Central."""
    components: List[Dict[str, Any]] = document.get("components") or []
    by_coord: Dict[Coordinate, List[Dict[str, Any]]] = {}
    skipped = 0
    for component in components:
        coord = parse_maven_purl(component.get("purl"))
        if coord is None:
            skipped += 1
        else:
            by_coord.setdefault(coord, []).append(component)

    artifacts: Dict[Coordinate, _Artifact] = {}
    with Progress("Enriching from Maven Central", len(by_coord), enabled=show_progress) as bar:
        with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            futures = {pool.submit(_lookup, c, fetch, base_url): c for c in sorted(by_coord)}
            for future in as_completed(futures):
                coord = futures[future]
                try:
                    artifacts[coord] = future.result()
                except Exception as exc:  # one artifact's failure must not abort the run
                    logger.warning("enrichment failed for %s: %s", ":".join(coord), exc)
                    artifacts[coord] = _Artifact()
                bar.advance()

    hashed = supplied = 0
    for coord, comps in by_coord.items():
        for component in comps:
            h, s = _apply(component, artifacts[coord])
            hashed += h
            supplied += s
    return EnrichResult(
        component_count=len(components),
        unique_artifacts=len(by_coord),
        hashed=hashed,
        supplier=supplied,
        skipped_non_maven=skipped,
        not_found=sum(1 for a in artifacts.values() if not a.sha512),
    )
