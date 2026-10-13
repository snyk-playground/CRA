import unittest

from snyk_generate_cra_sbom_vex import discovery
from snyk_generate_cra_sbom_vex.config import SourceSelection
from snyk_generate_cra_sbom_vex.errors import NoProjectsDiscoveredError, SourceNotFoundError
from tests.fakes import FakeSnykClient, project

EMPTY = SourceSelection(orgs=(), targets=(), assets=(), projects=(), groups=(), tags=())


def selection(**kwargs):
    return EMPTY.__class__(**{**EMPTY.__dict__, **kwargs})


class DiscoverOrgTests(unittest.TestCase):
    def test_resolves_org_projects(self):
        client = FakeSnykClient(
            org_projects={"org-1": [project("p1", "Proj One", "maven"), project("p2", "Proj Two", "k8sconfig")]}
        )
        result = discovery.discover(client, selection(orgs=("org-1",)))
        self.assertEqual([p.project_id for p in result], ["p1", "p2"])
        self.assertTrue(result[0].in_scope)  # maven -> SCA
        self.assertFalse(result[1].in_scope)  # k8sconfig -> IaC, not SBOM-eligible

    def test_unknown_org_raises_source_not_found(self):
        client = FakeSnykClient(org_projects={})
        with self.assertRaises(SourceNotFoundError):
            discovery.discover(client, selection(orgs=("nope",)))


class DiscoverGroupTests(unittest.TestCase):
    def test_resolves_every_org_in_group(self):
        client = FakeSnykClient(
            group_orgs={"grp": ["org-a", "org-b"]},
            org_projects={
                "org-a": [project("p1", "A1", "npm")],
                "org-b": [project("p2", "B1", "pip")],
            },
        )
        result = discovery.discover(client, selection(groups=("grp",)))
        self.assertEqual(sorted(p.project_id for p in result), ["p1", "p2"])

    def test_unknown_group_raises_source_not_found(self):
        client = FakeSnykClient(group_orgs={})
        with self.assertRaises(SourceNotFoundError):
            discovery.discover(client, selection(groups=("nope",)))


class DiscoverTargetTests(unittest.TestCase):
    def test_searches_across_orgs_for_target(self):
        client = FakeSnykClient(
            orgs=["org-a", "org-b"],
            org_targets={"org-b": ["t1"]},
            org_projects={"org-b": [project("p1", "P1", "maven"), project("p2", "P2", "npm")]},
            project_targets={("org-b", "p1"): "t1"},
        )
        result = discovery.discover(client, selection(targets=("t1",)))
        self.assertEqual([p.project_id for p in result], ["p1"])

    def test_target_not_found_in_any_org(self):
        client = FakeSnykClient(orgs=["org-a"], org_targets={"org-a": []})
        with self.assertRaises(SourceNotFoundError):
            discovery.discover(client, selection(targets=("missing",)))


class DiscoverProjectTests(unittest.TestCase):
    def test_searches_across_orgs_for_project(self):
        client = FakeSnykClient(
            orgs=["org-a", "org-b"],
            org_projects={"org-b": [project("p1", "P1", "maven")]},
        )
        result = discovery.discover(client, selection(projects=("p1",)))
        self.assertEqual([p.org_id for p in result], ["org-b"])

    def test_project_not_found_in_any_org(self):
        client = FakeSnykClient(orgs=["org-a"], org_projects={"org-a": []})
        with self.assertRaises(SourceNotFoundError):
            discovery.discover(client, selection(projects=("missing",)))


class DiscoverAssetTests(unittest.TestCase):
    def test_resolves_asset_projects_and_refetches_full_resource(self):
        client = FakeSnykClient(
            orgs=["org-a"],
            org_assets={"org-a": ["asset-1"]},
            asset_projects={("org-a", "asset-1"): ["p1"]},
            org_projects={"org-a": [project("p1", "Base Image", "rpm")]},
        )
        result = discovery.discover(client, selection(assets=("asset-1",)))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].name, "Base Image")
        self.assertTrue(result[0].in_scope)  # rpm -> Container

    def test_asset_not_found_in_any_org(self):
        client = FakeSnykClient(orgs=["org-a"], org_assets={"org-a": []})
        with self.assertRaises(SourceNotFoundError):
            discovery.discover(client, selection(assets=("missing",)))


class DiscoverTagTests(unittest.TestCase):
    def test_resolves_across_every_org(self):
        client = FakeSnykClient(
            orgs=["org-a", "org-b"],
            org_projects={
                "org-a": [project("p1", "P1", "npm")],
                "org-b": [project("p2", "P2", "npm")],
            },
            project_tags={("org-a", "p1"): [("team", "unicorn")]},
        )
        result = discovery.discover(client, selection(tags=(("team", "unicorn"),)))
        self.assertEqual([p.project_id for p in result], ["p1"])

    def test_no_matches_across_all_sources_raises_no_projects(self):
        client = FakeSnykClient(orgs=["org-a"], org_projects={"org-a": [project("p1", "P1", "npm")]})
        with self.assertRaises(NoProjectsDiscoveredError):
            discovery.discover(client, selection(tags=(("team", "nonexistent"),)))


class DeduplicationTests(unittest.TestCase):
    def test_same_project_via_two_sources_combines_labels_once(self):
        client = FakeSnykClient(
            orgs=["org-a"],
            org_targets={"org-a": ["t1"]},
            org_projects={"org-a": [project("p1", "P1", "maven")]},
            project_targets={("org-a", "p1"): "t1"},
        )
        result = discovery.discover(client, selection(orgs=("org-a",), targets=("t1",)))
        self.assertEqual(len(result), 1)
        self.assertIn("org:org-a", result[0].source)
        self.assertIn("target:t1", result[0].source)

    def test_output_sorted_by_org_then_project(self):
        client = FakeSnykClient(
            org_projects={
                "org-b": [project("p2", "P2", "npm")],
                "org-a": [project("p1", "P1", "npm")],
            }
        )
        result = discovery.discover(client, selection(orgs=("org-b", "org-a")))
        self.assertEqual([(p.org_id, p.project_id) for p in result], [("org-a", "p1"), ("org-b", "p2")])


if __name__ == "__main__":
    unittest.main()
