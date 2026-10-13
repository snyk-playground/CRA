import io
import json
import unittest
import urllib.error
from email.message import Message
from unittest.mock import patch

from snyk_generate_cra_sbom_vex.errors import AuthenticationError
from snyk_generate_cra_sbom_vex.snyk_api.client import SnykApiError, SnykClient


def _response(payload):
    body = json.dumps(payload).encode("utf-8")

    class _Resp:
        status = 200

        def read(self):
            return body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    return _Resp()


def _http_error(code, payload):
    body = json.dumps(payload).encode("utf-8")
    return urllib.error.HTTPError(
        url="https://api.snyk.io/x", code=code, msg="err", hdrs=Message(), fp=io.BytesIO(body)
    )


class ClientPaginationTests(unittest.TestCase):
    def test_follows_links_next_across_pages(self):
        page1 = {"data": [{"id": "p1"}], "links": {"next": "/rest/orgs/o1/projects?page=2"}}
        page2 = {"data": [{"id": "p2"}], "links": {}}

        client = SnykClient(token="t", api_version="2024-10-15")
        with patch("urllib.request.urlopen", side_effect=[_response(page1), _response(page2)]):
            result = client.list_org_projects("o1")

        self.assertEqual([p["id"] for p in result], ["p1", "p2"])

    def test_404_on_first_page_returns_none(self):
        client = SnykClient(token="t", api_version="2024-10-15")
        with patch("urllib.request.urlopen", side_effect=_http_error(404, {"errors": [{"detail": "Not Found"}]})):
            result = client.list_org_projects("missing-org")
        self.assertIsNone(result)

    def test_get_project_unwraps_data(self):
        payload = {"data": {"type": "project", "id": "p1", "attributes": {"name": "n", "type": "maven"}}}
        client = SnykClient(token="t", api_version="2024-10-15")
        with patch("urllib.request.urlopen", return_value=_response(payload)):
            result = client.get_project("o1", "p1")
        self.assertEqual(result["id"], "p1")
        self.assertEqual(result["attributes"]["name"], "n")

    def test_get_project_404_returns_none(self):
        client = SnykClient(token="t", api_version="2024-10-15")
        with patch("urllib.request.urlopen", side_effect=_http_error(404, {"errors": [{"detail": "not found"}]})):
            result = client.get_project("o1", "missing")
        self.assertIsNone(result)


class ClientSbomTests(unittest.TestCase):
    def test_returns_raw_bytes_and_encodes_format_plus(self):
        raw = b'{"bomFormat": "CycloneDX", "components": []}'

        class _RawResp:
            status = 200

            def read(self):
                return raw

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        client = SnykClient(token="t", api_version="2024-10-15")
        with patch("urllib.request.urlopen", return_value=_RawResp()) as mock_urlopen:
            result = client.get_project_sbom("o1", "p1", "cyclonedx1.6+json")

        self.assertEqual(result, raw)
        called_url = mock_urlopen.call_args[0][0].full_url
        # A literal "+" must be percent-encoded (%2B), not left as "+" (which
        # decodes as a space and fails the API's format enum validation --
        # confirmed against a live tenant while building this client).
        self.assertIn("format=cyclonedx1.6%2Bjson", called_url)

    def test_404_returns_none(self):
        client = SnykClient(token="t", api_version="2024-10-15")
        with patch(
            "urllib.request.urlopen",
            side_effect=_http_error(404, {"errors": [{"detail": "not found"}]}),
        ):
            result = client.get_project_sbom("o1", "missing", "cyclonedx1.6+json")
        self.assertIsNone(result)


class ClientErrorHandlingTests(unittest.TestCase):
    def test_401_raises_authentication_error(self):
        client = SnykClient(token="bad", api_version="2024-10-15")
        with patch("urllib.request.urlopen", side_effect=_http_error(401, {"errors": [{"details": "Unauthorized"}]})):
            with self.assertRaises(AuthenticationError):
                client.list_orgs()

    def test_other_error_raises_snyk_api_error(self):
        client = SnykClient(token="t", api_version="2024-10-15")
        with patch("urllib.request.urlopen", side_effect=_http_error(500, {"errors": [{"detail": "boom"}]})):
            with self.assertRaises(SnykApiError):
                client.list_orgs()

    def test_429_retries_then_succeeds(self):
        client = SnykClient(token="t", api_version="2024-10-15")
        success = {"data": [{"id": "p1"}], "links": {}}
        with patch("time.sleep"):
            with patch(
                "urllib.request.urlopen",
                side_effect=[_http_error(429, {"errors": [{"detail": "slow down"}]}), _response(success)],
            ):
                result = client.list_orgs()
        self.assertEqual([o["id"] for o in result], ["p1"])


if __name__ == "__main__":
    unittest.main()
