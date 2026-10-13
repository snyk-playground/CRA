"""Snyk REST API client: authentication, pagination, and rate-limit handling.

Per the requirements doc §8.3, all outbound Snyk API access is
centralized here -- no other module is permitted to issue HTTP requests
directly.

The endpoints below were confirmed against a live tenant while building
this client (2026-09-22, api-version 2024-10-15):
  - GET /rest/orgs                                             (list, paginated)
  - GET /rest/orgs/{org}/projects                               (list, paginated;
        accepts target_id=<id> and tags=<key>:<value> filters -- the tags
        filter resolves Open Risk #6, which flagged this as unconfirmed)
  - GET /rest/orgs/{org}/projects/{project}                     (get)
  - GET /rest/orgs/{org}/projects/{project}/sbom                 (get; ?format=
        is required -- confirmed the literal "+" in a value like
        "cyclonedx1.6+json" must be percent-encoded as %2B, since an
        unencoded "+" in a query string decodes as a space and fails the
        API's enum validation. Response is the raw SBOM document itself,
        not a JSON:API envelope)
  - GET /rest/groups/{group}/orgs                                (list, paginated)
  - GET /rest/orgs/{org}/targets                                 (list, paginated)
  - GET /rest/orgs/{org}/targets/{target}                        (get)
  - GET /rest/orgs/{org}/inventory/assets                        (list, paginated)
  - GET /rest/orgs/{org}/inventory/assets/{asset}                (get)
  - GET /rest/orgs/{org}/inventory/assets/{asset}/relationships/projects
                                                                  (list, paginated)
The asset endpoints resolve Open Risk #1, which could not confirm a
stable endpoint at spec-writing time -- they are not yet documented as
GA at https://apidocs.snyk.io as of this writing, so re-verify before
relying on them long-term.

  - GET /rest/orgs/{org}/issues?scan_item.id=&scan_item.type=project
                                                                  (list, paginated)
  - GET /v1/org/{org}/project/{project}/ignores                  (get; legacy
        v1 API, not JSON:API -- no envelope, no ?version=)
Confirmed against the live OpenAPI spec at
https://api.snyk.io/rest/openapi/{api-version} while building FR-9
(Open Risk #2): the REST issues endpoint's `attributes.ignored` is only
a boolean, and its `relationships.ignore` is an opaque
{id, type: "ignore"} reference with no path in this API version to
fetch the ignore's actual reason/justification/expiry. That detail is
only available from the legacy v1 ignores endpoint, keyed by issue ID,
in the reasonType/reason/expires shape FR-3's mapping table is written
against -- so issues and ignore reasons are deliberately read from two
different API generations.

A 404 on a "get" or first-page "list" call is treated as "not found"
and surfaces as None to the caller, which lets resolvers try the next
candidate org rather than failing outright (needed for --target,
--project, and --asset, none of which come with a known org).
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from ..errors import AuthenticationError, SnykCraSbomVexError
from .rate_limit import RetryPolicy

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.snyk.io"
PAGE_LIMIT = 100


class SnykApiError(SnykCraSbomVexError):
    """A non-2xx response from the Snyk API that isn't auth- or not-found-specific."""

    exit_code = 1

    def __init__(self, status: int, detail: str, method: str, path: str) -> None:
        super().__init__(f"{method} {path} -> HTTP {status}: {detail}")
        self.status = status
        self.detail = detail


def _error_detail(body: bytes) -> str:
    try:
        payload = json.loads(body) if body else {}
    except ValueError:
        return body.decode("utf-8", errors="replace") if body else ""
    errors = payload.get("errors") or []
    if errors:
        first = errors[0]
        # The API has been observed using both "detail" and "details" for the
        # same purpose depending on the error path -- check both.
        return first.get("detail") or first.get("details") or first.get("title") or str(first)
    return str(payload)


class SnykClient:
    """Thin wrapper over the Snyk REST API used by the source resolvers."""

    def __init__(
        self,
        token: str,
        api_version: str,
        base_url: str = DEFAULT_BASE_URL,
        retry_policy: Optional[RetryPolicy] = None,
        timeout: float = 30.0,
    ) -> None:
        self._token = token
        self._api_version = api_version
        self._base_url = base_url.rstrip("/")
        self._retry_policy = retry_policy or RetryPolicy()
        self._timeout = timeout

    # -- low-level HTTP -----------------------------------------------------

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"token {self._token}",
            "Accept": "application/vnd.api+json",
        }

    def _build_url(self, path: str, params: Optional[Dict[str, Any]]) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if "?" in path:
            # A `links.next`/`links.first` value from a prior page already
            # carries its own full query string.
            return f"{self._base_url}{path}"
        query = dict(params or {})
        query.setdefault("version", self._api_version)
        qs = urllib.parse.urlencode(query)
        return f"{self._base_url}{path}?{qs}" if qs else f"{self._base_url}{path}"

    def _send_get(self, url: str, headers: Dict[str, str], error_path: str) -> Optional[bytes]:
        """GETs one URL and returns the raw response body, or None on HTTP 404.

        Shared by every other GET method here (JSON:API and legacy v1
        alike) so retry/backoff (FR-15) and error mapping live in one
        place. `error_path` is only used for error messages -- it need
        not match `url` exactly (e.g. it can be the unversioned path).
        """
        attempt = 0
        while True:
            request = urllib.request.Request(url, method="GET", headers=headers)
            logger.debug("GET %s", url)
            try:
                with urllib.request.urlopen(request, timeout=self._timeout) as response:
                    body = response.read()
                    logger.debug("-> HTTP %s", response.status)
                    return body
            except urllib.error.HTTPError as exc:
                body = exc.read()
                detail = _error_detail(body)
                logger.debug("-> HTTP %s: %s", exc.code, detail)
                if exc.code == 429 and attempt < self._retry_policy.max_retries:
                    delay = self._retry_policy.delay_seconds(attempt, exc.headers.get("Retry-After"))
                    logger.debug(
                        "rate limited; retrying in %.1fs (attempt %d/%d)",
                        delay,
                        attempt + 1,
                        self._retry_policy.max_retries,
                    )
                    time.sleep(delay)
                    attempt += 1
                    continue
                if exc.code == 401:
                    raise AuthenticationError(
                        f"Snyk API rejected the supplied token (GET {error_path}): {detail}"
                    )
                if exc.code == 404:
                    return None
                raise SnykApiError(exc.code, detail, "GET", error_path)
            except urllib.error.URLError as exc:
                if attempt < self._retry_policy.max_retries:
                    delay = self._retry_policy.delay_seconds(attempt)
                    logger.debug("network error (%s); retrying in %.1fs", exc, delay)
                    time.sleep(delay)
                    attempt += 1
                    continue
                raise SnykApiError(0, str(exc), "GET", error_path) from exc

    def _request_bytes(self, path: str, params: Optional[Dict[str, Any]] = None) -> Optional[bytes]:
        """GETs one REST API URL and returns the raw response body, or None on HTTP 404.

        Used both by _get (which parses the body as JSON:API) and
        get_project_sbom (whose response is a raw CycloneDX/SPDX document,
        not a JSON:API envelope, and may not even be JSON for an XML
        --sbom-format).
        """
        return self._send_get(self._build_url(path, params), self._headers(), path)

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """GETs one page as JSON:API. Returns the parsed body, or None on HTTP 404."""
        body = self._request_bytes(path, params)
        if body is None:
            return None
        return json.loads(body) if body else {}

    def _v1_headers(self) -> Dict[str, str]:
        return {"Authorization": f"token {self._token}", "Content-Type": "application/json"}

    def _get_v1(self, path: str) -> Optional[Dict[str, Any]]:
        """GETs a legacy v1 API path: no ?version=, no JSON:API envelope."""
        body = self._send_get(f"{self._base_url}{path}", self._v1_headers(), path)
        if body is None:
            return None
        return json.loads(body) if body else {}

    def _get_resource(self, path: str) -> Optional[Dict[str, Any]]:
        """GETs a single-resource endpoint and unwraps its top-level `data` object.

        (Distinct from _get: a JSON:API single-resource response wraps the
        resource in `data`, whereas a list response wraps an array in `data`
        alongside `links` -- _paginate handles that shape instead.)
        """
        payload = self._get(path)
        return payload.get("data") if payload is not None else None

    def _paginate(
        self, path: str, params: Optional[Dict[str, Any]] = None
    ) -> Optional[List[Dict[str, Any]]]:
        """Follows `links.next` across every page. Returns None if the first page 404s."""
        params = dict(params or {})
        params.setdefault("limit", PAGE_LIMIT)
        items: List[Dict[str, Any]] = []
        current_path, current_params = path, params
        while True:
            payload = self._get(current_path, current_params)
            if payload is None:
                return None if not items else items
            items.extend(payload.get("data") or [])
            next_link = (payload.get("links") or {}).get("next")
            if not next_link:
                return items
            current_path, current_params = next_link, None

    # -- orgs / groups --------------------------------------------------------

    def list_orgs(self) -> List[Dict[str, Any]]:
        """Every org the token can access. Never 404s, so always a list."""
        return self._paginate("/rest/orgs") or []

    def list_group_orgs(self, group_id: str) -> Optional[List[Dict[str, Any]]]:
        return self._paginate(f"/rest/groups/{group_id}/orgs")

    # -- projects ---------------------------------------------------------

    def list_org_projects(
        self,
        org_id: str,
        target_id: Optional[str] = None,
        tag: Optional[Tuple[str, str]] = None,
    ) -> Optional[List[Dict[str, Any]]]:
        params: Dict[str, Any] = {}
        if target_id:
            params["target_id"] = target_id
        if tag:
            key, value = tag
            # Confirmed against a live tenant: the projects listing accepts a
            # `tags` filter of "key:value" (colon-separated; url-encoded).
            params["tags"] = f"{key}:{value}"
        return self._paginate(f"/rest/orgs/{org_id}/projects", params)

    def get_project(self, org_id: str, project_id: str) -> Optional[Dict[str, Any]]:
        return self._get_resource(f"/rest/orgs/{org_id}/projects/{project_id}")

    def get_project_sbom(self, org_id: str, project_id: str, sbom_format: str) -> Optional[bytes]:
        """Fetches one project's SBOM document (FR-7).

        Returns the raw response bytes -- the document is CycloneDX or
        SPDX, not a JSON:API resource, and may be XML rather than JSON
        depending on sbom_format -- or None on HTTP 404 (e.g. a project
        type the SBOM API doesn't actually support despite looking
        in-scope).
        """
        return self._request_bytes(
            f"/rest/orgs/{org_id}/projects/{project_id}/sbom", {"format": sbom_format}
        )

    # -- targets ------------------------------------------------------------

    def list_org_targets(self, org_id: str) -> Optional[List[Dict[str, Any]]]:
        return self._paginate(f"/rest/orgs/{org_id}/targets")

    def get_target(self, org_id: str, target_id: str) -> Optional[Dict[str, Any]]:
        return self._get_resource(f"/rest/orgs/{org_id}/targets/{target_id}")

    # -- assets (Open Risk #1) -----------------------------------------------

    def get_asset(self, org_id: str, asset_id: str) -> Optional[Dict[str, Any]]:
        return self._get_resource(f"/rest/orgs/{org_id}/inventory/assets/{asset_id}")

    def list_asset_projects(self, org_id: str, asset_id: str) -> Optional[List[Dict[str, Any]]]:
        return self._paginate(f"/rest/orgs/{org_id}/inventory/assets/{asset_id}/relationships/projects")

    # -- issues / ignores (FR-9) ---------------------------------------------

    def list_project_issues(self, org_id: str, project_id: str) -> List[Dict[str, Any]]:
        """A project's current issues (FR-9). Never 404s for a project that exists."""
        params = {"scan_item.id": project_id, "scan_item.type": "project"}
        return self._paginate(f"/rest/orgs/{org_id}/issues", params) or []

    def get_project_ignores(self, org_id: str, project_id: str) -> Dict[str, Any]:
        """A project's ignore reasons, keyed by issue ID (FR-9, Open Risk #2).

        Legacy v1 API: {issue_id: [{path_or_"*": {reason, reasonType,
        expires, created, ignoredBy, ...}}, ...]}. Returns {} both when
        the project has no ignores and on 404, since an absent ignore
        list is a normal, not an error, state.
        """
        return self._get_v1(f"/v1/org/{org_id}/project/{project_id}/ignores") or {}
