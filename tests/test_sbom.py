import json
import unittest

from snyk_generate_cra_sbom_vex import sbom
from snyk_generate_cra_sbom_vex.errors import ProjectFetchError
from snyk_generate_cra_sbom_vex.resolvers.base import ResolvedProject
from snyk_generate_cra_sbom_vex.snyk_api.client import SnykApiError
from tests.fakes import FakeSnykClient


def resolved(org_id="org-1", project_id="p1", project_type="maven", in_scope=True):
    return ResolvedProject(
        org_id=org_id,
        project_id=project_id,
        name=f"{project_id}-name",
        project_type=project_type,
        source="org:org-1",
        in_scope=in_scope,
    )


class FetchSbomsTests(unittest.TestCase):
    def test_fetches_in_scope_projects_and_counts_components(self):
        doc = json.dumps({"components": [{"purl": "pkg:a"}, {"purl": "pkg:b"}]}).encode()
        client = FakeSnykClient(sboms={("org-1", "p1"): doc})
        results = sbom.fetch_sboms(client, [resolved()], "cyclonedx1.6+json")

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].ok)
        self.assertEqual(results[0].item_count, 2)
        self.assertEqual(results[0].document, doc)

    def test_counts_spdx_packages_not_components(self):
        doc = json.dumps({"packages": [{"name": "a"}]}).encode()
        client = FakeSnykClient(sboms={("org-1", "p1"): doc})
        results = sbom.fetch_sboms(client, [resolved()], "spdx2.3+json")
        self.assertEqual(results[0].item_count, 1)

    def test_xml_format_does_not_attempt_to_count(self):
        client = FakeSnykClient(sboms={("org-1", "p1"): b"<bom></bom>"})
        results = sbom.fetch_sboms(client, [resolved()], "cyclonedx1.6+xml")
        self.assertTrue(results[0].ok)
        self.assertIsNone(results[0].item_count)

    def test_malformed_json_does_not_crash(self):
        client = FakeSnykClient(sboms={("org-1", "p1"): b"not json"})
        results = sbom.fetch_sboms(client, [resolved()], "cyclonedx1.6+json")
        self.assertTrue(results[0].ok)
        self.assertIsNone(results[0].item_count)

    def test_skips_out_of_scope_projects_without_calling_client(self):
        client = FakeSnykClient()
        results = sbom.fetch_sboms(client, [resolved(project_type="k8sconfig", in_scope=False)], "cyclonedx1.6+json")
        self.assertEqual(results, [])
        self.assertEqual(client.sbom_fetch_calls, [])

    def test_404_recorded_as_failure_and_run_continues(self):
        client = FakeSnykClient(sboms={})  # no entry -> get_project_sbom returns None
        projects = [resolved(project_id="p1"), resolved(project_id="p2")]
        client.sboms[("org-1", "p2")] = b"{}"
        results = sbom.fetch_sboms(client, projects, "cyclonedx1.6+json")

        self.assertEqual(len(results), 2)
        self.assertFalse(results[0].ok)
        self.assertIn("404", results[0].error)
        self.assertTrue(results[1].ok)

    def test_api_error_recorded_as_failure_and_run_continues(self):
        client = FakeSnykClient(sbom_errors={("org-1", "p1"): SnykApiError(500, "boom", "GET", "/x")})
        projects = [resolved(project_id="p1"), resolved(project_id="p2")]
        client.sboms[("org-1", "p2")] = b"{}"
        results = sbom.fetch_sboms(client, projects, "cyclonedx1.6+json")

        self.assertFalse(results[0].ok)
        self.assertIn("boom", results[0].error)
        self.assertTrue(results[1].ok)

    def test_fail_fast_raises_and_stops_before_next_project(self):
        client = FakeSnykClient(sbom_errors={("org-1", "p1"): SnykApiError(500, "boom", "GET", "/x")})
        projects = [resolved(project_id="p1"), resolved(project_id="p2")]

        with self.assertRaises(ProjectFetchError):
            sbom.fetch_sboms(client, projects, "cyclonedx1.6+json", fail_fast=True)

        self.assertEqual(client.sbom_fetch_calls, [("org-1", "p1", "cyclonedx1.6+json")])


if __name__ == "__main__":
    unittest.main()
