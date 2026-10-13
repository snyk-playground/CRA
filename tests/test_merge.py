import json
import unittest

from snyk_generate_cra_sbom_vex import sbom
from snyk_generate_cra_sbom_vex.resolvers.base import ResolvedProject


def resolved(org_id, project_id):
    return ResolvedProject(
        org_id=org_id,
        project_id=project_id,
        name=f"{org_id}/{project_id}",
        project_type="maven",
        source=f"org:{org_id}",
        in_scope=True,
    )


def fetch_ok(org_id, project_id, doc):
    return sbom.SbomFetchResult(
        project=resolved(org_id, project_id), ok=True, document=json.dumps(doc).encode()
    )


class MergeSbomsTests(unittest.TestCase):
    def test_keeps_every_duplicate_occurrence_across_projects(self):
        doc_a = {
            "metadata": {"component": {"bom-ref": "root", "type": "application", "name": "a", "purl": "pkg:app/a"}},
            "components": [{"bom-ref": "1-shared", "purl": "pkg:maven/shared@1.0", "name": "shared"}],
            "dependencies": [{"ref": "root", "dependsOn": ["1-shared"]}],
        }
        doc_b = {
            "metadata": {"component": {"bom-ref": "root", "type": "application", "name": "b", "purl": "pkg:app/b"}},
            "components": [{"bom-ref": "1-shared", "purl": "pkg:maven/shared@1.0", "name": "shared"}],
            "dependencies": [{"ref": "root", "dependsOn": ["1-shared"]}],
        }
        results = [fetch_ok("org-1", "p1", doc_a), fetch_ok("org-1", "p2", doc_b)]

        merged = sbom.merge_sboms(results, "cyclonedx1.6+json")

        self.assertIsNone(merged.skipped_reason)
        # 2 root components (pkg:app/a, pkg:app/b) + 2 separate "shared" occurrences (FR-8: not collapsed)
        self.assertEqual(merged.component_count, 4)

        shared_occurrences = [c for c in merged.document["components"] if c["purl"] == "pkg:maven/shared@1.0"]
        self.assertEqual(len(shared_occurrences), 2)
        source_ids = {
            p["value"]
            for c in shared_occurrences
            for p in c["properties"]
            if p["name"] == "snyk:sourceProjectId"
        }
        self.assertEqual(source_ids, {"org-1/p1", "org-1/p2"})
        # Each occurrence gets its own unique bom-ref (FR-8).
        refs = {c["bom-ref"] for c in shared_occurrences}
        self.assertEqual(len(refs), 2)

    def test_keeps_every_duplicate_occurrence_within_a_single_project(self):
        doc = {
            "components": [
                {"bom-ref": "1-x", "purl": "pkg:maven/shared@1.0", "name": "shared", "version": "1.0"},
                {"bom-ref": "2-x", "purl": "pkg:maven/shared@1.0", "name": "shared", "version": "1.0"},
            ],
            "dependencies": [],
        }
        results = [fetch_ok("org-1", "p1", doc)]
        merged = sbom.merge_sboms(results, "cyclonedx1.6+json")

        self.assertEqual(merged.component_count, 2)
        refs = [c["bom-ref"] for c in merged.document["components"]]
        self.assertEqual(len(set(refs)), 2)  # unique despite identical identity+project

    def test_component_lookup_maps_project_scoped_name_version_to_every_occurrence_ref(self):
        doc = {
            "components": [
                {"bom-ref": "1-x", "purl": "pkg:maven/shared@1.0", "name": "shared", "version": "1.0"},
                {"bom-ref": "2-x", "purl": "pkg:maven/shared@1.0", "name": "shared", "version": "1.0"},
            ],
            "dependencies": [],
        }
        results = [fetch_ok("org-1", "p1", doc)]
        merged = sbom.merge_sboms(results, "cyclonedx1.6+json")
        refs = merged.component_lookup[("org-1", "p1", "shared", "1.0")]
        self.assertEqual(len(refs), 2)
        self.assertEqual(set(refs), {c["bom-ref"] for c in merged.document["components"]})

    def test_remaps_dependency_edges_within_each_project(self):
        # Both documents label their component "1-x", but they're different
        # purls -- a naive ref union would corrupt the graph if not remapped.
        doc_a = {
            "components": [
                {"bom-ref": "1-x", "purl": "pkg:maven/left@1.0"},
                {"bom-ref": "2-y", "purl": "pkg:maven/shared@1.0"},
            ],
            "dependencies": [{"ref": "1-x", "dependsOn": ["2-y"]}],
        }
        doc_b = {
            "components": [
                {"bom-ref": "1-x", "purl": "pkg:maven/right@1.0"},
                {"bom-ref": "2-y", "purl": "pkg:maven/shared@1.0"},
            ],
            "dependencies": [{"ref": "1-x", "dependsOn": ["2-y"]}],
        }
        results = [fetch_ok("org-1", "p1", doc_a), fetch_ok("org-1", "p2", doc_b)]

        merged = sbom.merge_sboms(results, "cyclonedx1.6+json")

        deps_by_ref = {d["ref"]: d["dependsOn"] for d in merged.document["dependencies"]}
        left_ref = next(c["bom-ref"] for c in merged.document["components"] if c["purl"] == "pkg:maven/left@1.0")
        right_ref = next(c["bom-ref"] for c in merged.document["components"] if c["purl"] == "pkg:maven/right@1.0")
        self.assertEqual(len(deps_by_ref[left_ref]), 1)
        self.assertEqual(len(deps_by_ref[right_ref]), 1)
        # Each project's "shared" occurrence is distinct, and the edge points at its own project's occurrence.
        left_dep_ref = next(iter(deps_by_ref[left_ref]))
        right_dep_ref = next(iter(deps_by_ref[right_ref]))
        self.assertNotEqual(left_dep_ref, right_dep_ref)

    def test_components_without_purl_fall_back_to_identity(self):
        doc = {
            "components": [
                {"bom-ref": "1-img", "type": "container", "name": "img", "version": "1.0"},
            ],
            "dependencies": [],
        }
        results = [fetch_ok("org-1", "p1", doc)]
        merged = sbom.merge_sboms(results, "cyclonedx1.6+json")
        self.assertEqual(merged.component_count, 1)
        self.assertEqual(
            merged.document["components"][0]["bom-ref"], "no-purl:container||img|1.0#org-1/p1#1"
        )

    def test_skips_non_cyclonedx_json_format(self):
        results = [fetch_ok("org-1", "p1", {"components": []})]
        merged = sbom.merge_sboms(results, "spdx2.3+json")
        self.assertIsNone(merged.document)
        self.assertIn("CycloneDX+JSON", merged.skipped_reason)

    def test_skips_xml_format(self):
        results = [fetch_ok("org-1", "p1", {"components": []})]
        merged = sbom.merge_sboms(results, "cyclonedx1.6+xml")
        self.assertIsNone(merged.document)

    def test_no_successful_fetches_skips_with_reason(self):
        failed = sbom.SbomFetchResult(project=resolved("org-1", "p1"), ok=False, error="boom")
        merged = sbom.merge_sboms([failed], "cyclonedx1.6+json")
        self.assertIsNone(merged.document)
        self.assertIn("no successfully fetched", merged.skipped_reason)

    def test_ignores_unparseable_document_without_crashing(self):
        bad = sbom.SbomFetchResult(project=resolved("org-1", "p1"), ok=True, document=b"not json")
        good = fetch_ok("org-2", "p2", {"components": [{"purl": "pkg:x@1"}], "dependencies": []})
        merged = sbom.merge_sboms([bad, good], "cyclonedx1.6+json")
        self.assertEqual(merged.component_count, 1)

    def test_output_ordering_is_deterministic(self):
        doc_a = {"components": [{"purl": "pkg:z@1"}, {"purl": "pkg:a@1"}], "dependencies": []}
        results = [fetch_ok("org-1", "p1", doc_a)]
        m1 = sbom.merge_sboms(results, "cyclonedx1.6+json")
        m2 = sbom.merge_sboms(results, "cyclonedx1.6+json")
        refs1 = [c["bom-ref"] for c in m1.document["components"]]
        refs2 = [c["bom-ref"] for c in m2.document["components"]]
        self.assertEqual(refs1, refs2)
        self.assertEqual(refs1, sorted(refs1))


if __name__ == "__main__":
    unittest.main()
