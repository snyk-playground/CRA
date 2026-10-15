import json
import unittest

from snyk_generate_cra_sbom_vex import sbom, vex
from snyk_generate_cra_sbom_vex.resolvers.base import ResolvedProject
from tests.fakes import FakeSnykClient, ignore_entry, issue


def resolved(org_id="org-1", project_id="p1"):
    return ResolvedProject(
        org_id=org_id, project_id=project_id, name=f"{org_id}/{project_id}",
        project_type="maven", source=f"org:{org_id}", in_scope=True,
    )


def build_merge(org_id, project_id, package_name, package_version, purl):
    doc = {
        "components": [
            {"bom-ref": "1-x", "purl": purl, "name": package_name, "version": package_version}
        ],
        "dependencies": [],
    }
    fetch_result = sbom.SbomFetchResult(
        project=resolved(org_id, project_id), ok=True, document=json.dumps(doc).encode()
    )
    merge_result = sbom.merge_sboms([fetch_result], "cyclonedx1.6+json")
    return fetch_result, merge_result


def build_merge_multi(entries):
    """entries: [(org_id, project_id, package_name, package_version, purl), ...]"""
    fetch_results = []
    for org_id, project_id, package_name, package_version, purl in entries:
        doc = {
            "components": [
                {"bom-ref": "1-x", "purl": purl, "name": package_name, "version": package_version}
            ],
            "dependencies": [],
        }
        fetch_results.append(
            sbom.SbomFetchResult(project=resolved(org_id, project_id), ok=True, document=json.dumps(doc).encode())
        )
    merge_result = sbom.merge_sboms(fetch_results, "cyclonedx1.6+json")
    return fetch_results, merge_result


class BuildAnalysisTests(unittest.TestCase):
    def test_open_unignored_is_exploitable(self):
        analysis, needs_review = vex._build_analysis(None)
        self.assertEqual(analysis, {"state": "exploitable"})
        self.assertFalse(needs_review)

    def test_wont_fix_is_exploitable_with_response(self):
        analysis, needs_review = vex._build_analysis({"reasonType": "wont-fix", "reason": "accepted risk"})
        self.assertEqual(analysis["state"], "exploitable")
        self.assertEqual(analysis["response"], ["will_not_fix"])
        self.assertEqual(analysis["detail"], "accepted risk")
        self.assertFalse(needs_review)

    def test_temporary_ignore_is_in_triage_with_expiry_detail(self):
        analysis, needs_review = vex._build_analysis(
            {"reasonType": "temporary-ignore", "reason": "waiting on upstream", "expires": "2026-12-01T00:00:00Z"}
        )
        self.assertEqual(analysis["state"], "in_triage")
        self.assertIn("2026-12-01T00:00:00Z", analysis["detail"])
        self.assertIn("waiting on upstream", analysis["detail"])
        self.assertFalse(needs_review)

    def test_not_vulnerable_with_recognized_code_is_not_affected(self):
        analysis, needs_review = vex._build_analysis({"reasonType": "not-vulnerable", "reason": "code not reachable"})
        self.assertEqual(analysis["state"], "not_affected")
        self.assertEqual(analysis["justification"], "code_not_reachable")
        self.assertFalse(needs_review)

    def test_not_vulnerable_with_unrecognized_text_flags_for_manual_review(self):
        analysis, needs_review = vex._build_analysis({"reasonType": "not-vulnerable", "reason": "looks fine to me"})
        self.assertEqual(analysis["state"], "in_triage")
        self.assertNotIn("justification", analysis)
        self.assertTrue(needs_review)

    def test_not_vulnerable_with_no_reason_never_fabricates_justification(self):
        analysis, needs_review = vex._build_analysis({"reasonType": "not-vulnerable", "reason": ""})
        self.assertEqual(analysis["state"], "in_triage")
        self.assertNotIn("justification", analysis)
        self.assertTrue(needs_review)

    def test_unknown_reason_type_flags_for_manual_review(self):
        analysis, needs_review = vex._build_analysis({"reasonType": "something-new"})
        self.assertEqual(analysis["state"], "in_triage")
        self.assertTrue(needs_review)


class NormalizeJustificationTests(unittest.TestCase):
    def test_matches_with_spaces_and_dashes(self):
        self.assertEqual(vex._normalize_justification_code("code not reachable"), "code_not_reachable")
        self.assertEqual(vex._normalize_justification_code("code-not-reachable"), "code_not_reachable")

    def test_no_match_returns_none(self):
        self.assertIsNone(vex._normalize_justification_code("we checked and it's fine"))


class DeriveVexTests(unittest.TestCase):
    def test_matches_issue_to_merged_component_and_defaults_exploitable(self):
        fetch_result, merge_result = build_merge("org-1", "p1", "shared", "1.0", "pkg:maven/shared@1.0")
        client = FakeSnykClient(
            project_issues={("org-1", "p1"): [issue("i1", "SNYK-1", "shared", "1.0", cve="CVE-2020-0001")]},
        )
        result = vex.derive_vex(client, [fetch_result], merge_result, generate_vex=True)

        self.assertEqual(result.vulnerability_count, 1)
        v = result.document["vulnerabilities"][0]
        self.assertEqual(v["id"], "CVE-2020-0001")
        component_ref = merge_result.component_lookup[("org-1", "p1", "shared", "1.0")][0]
        self.assertEqual(v["affects"], [{"ref": component_ref}])
        self.assertEqual(v["analysis"], {"state": "exploitable"})
        occurrence_count = next(p["value"] for p in v["properties"] if p["name"] == "snyk:occurrenceCount")
        self.assertEqual(occurrence_count, "1")

    def test_falls_back_to_snyk_key_when_no_cve(self):
        fetch_result, merge_result = build_merge("org-1", "p1", "shared", "1.0", "pkg:maven/shared@1.0")
        client = FakeSnykClient(
            project_issues={("org-1", "p1"): [issue("i1", "SNYK-JAVA-X-1", "shared", "1.0")]},
        )
        result = vex.derive_vex(client, [fetch_result], merge_result, generate_vex=True)
        self.assertEqual(result.document["vulnerabilities"][0]["id"], "SNYK-JAVA-X-1")

    def test_applies_ignore_reason_from_v1_api(self):
        fetch_result, merge_result = build_merge("org-1", "p1", "shared", "1.0", "pkg:maven/shared@1.0")
        client = FakeSnykClient(
            project_issues={("org-1", "p1"): [issue("i1", "SNYK-1", "shared", "1.0")]},
            project_ignores={("org-1", "p1"): {"SNYK-1": ignore_entry("not-vulnerable", "code not present")}},
        )
        result = vex.derive_vex(client, [fetch_result], merge_result, generate_vex=True)
        analysis = result.document["vulnerabilities"][0]["analysis"]
        self.assertEqual(analysis["state"], "not_affected")
        self.assertEqual(analysis["justification"], "code_not_present")
        self.assertEqual(result.needs_manual_justification, 0)

    def test_counts_manual_justification_needed(self):
        fetch_result, merge_result = build_merge("org-1", "p1", "shared", "1.0", "pkg:maven/shared@1.0")
        client = FakeSnykClient(
            project_issues={("org-1", "p1"): [issue("i1", "SNYK-1", "shared", "1.0")]},
            project_ignores={("org-1", "p1"): {"SNYK-1": ignore_entry("not-vulnerable", "")}},
        )
        result = vex.derive_vex(client, [fetch_result], merge_result, generate_vex=True)
        self.assertEqual(result.needs_manual_justification, 1)
        self.assertEqual(result.document["vulnerabilities"][0]["analysis"]["state"], "in_triage")

    def test_unmatched_issue_is_counted_and_excluded(self):
        fetch_result, merge_result = build_merge("org-1", "p1", "shared", "1.0", "pkg:maven/shared@1.0")
        client = FakeSnykClient(
            project_issues={("org-1", "p1"): [issue("i1", "SNYK-1", "other-package", "9.9")]},
        )
        result = vex.derive_vex(client, [fetch_result], merge_result, generate_vex=True)
        self.assertEqual(result.vulnerability_count, 0)
        self.assertEqual(result.unmatched_count, 1)

    def test_non_vulnerability_issue_types_are_excluded(self):
        fetch_result, merge_result = build_merge("org-1", "p1", "shared", "1.0", "pkg:maven/shared@1.0")
        client = FakeSnykClient(
            project_issues={("org-1", "p1"): [issue("i1", "SNYK-1", "shared", "1.0", issue_type="license")]},
        )
        result = vex.derive_vex(client, [fetch_result], merge_result, generate_vex=True)
        self.assertEqual(result.vulnerability_count, 0)
        self.assertEqual(result.unmatched_count, 0)

    def test_failed_fetch_projects_are_skipped(self):
        failed = sbom.SbomFetchResult(project=resolved(), ok=False, error="boom")
        _, merge_result = build_merge("org-1", "p1", "shared", "1.0", "pkg:maven/shared@1.0")
        client = FakeSnykClient(project_issues={("org-1", "p1"): [issue("i1", "SNYK-1", "shared", "1.0")]})
        result = vex.derive_vex(client, [failed], merge_result, generate_vex=True)
        self.assertEqual(result.vulnerability_count, 0)

    def test_disabled_by_flag_is_skipped(self):
        fetch_result, merge_result = build_merge("org-1", "p1", "shared", "1.0", "pkg:maven/shared@1.0")
        client = FakeSnykClient()
        result = vex.derive_vex(client, [fetch_result], merge_result, generate_vex=False)
        self.assertIsNone(result.document)
        self.assertIsNotNone(result.skipped_reason)

    def test_skipped_when_no_aggregate_sbom(self):
        fetch_result = sbom.SbomFetchResult(project=resolved(), ok=True, document=b'{"components": []}')
        empty_merge = sbom.merge_sboms([], "cyclonedx1.6+json")  # nothing successful -> skipped
        client = FakeSnykClient()
        result = vex.derive_vex(client, [fetch_result], empty_merge, generate_vex=True)
        self.assertIsNone(result.document)
        self.assertIn("aggregation was skipped", result.skipped_reason)

    def test_output_ordering_is_deterministic(self):
        fetch_result, merge_result = build_merge("org-1", "p1", "shared", "1.0", "pkg:maven/shared@1.0")
        client = FakeSnykClient(
            project_issues={
                ("org-1", "p1"): [
                    issue("i2", "SNYK-2", "shared", "1.0", cve="CVE-2020-0002"),
                    issue("i1", "SNYK-1", "shared", "1.0", cve="CVE-2020-0001"),
                ]
            },
        )
        result = vex.derive_vex(client, [fetch_result], merge_result, generate_vex=True)
        ids = [v["id"] for v in result.document["vulnerabilities"]]
        self.assertEqual(ids, sorted(ids))

    def test_shares_serial_number_with_aggregate_sbom(self):
        fetch_result, merge_result = build_merge("org-1", "p1", "shared", "1.0", "pkg:maven/shared@1.0")
        client = FakeSnykClient(project_issues={("org-1", "p1"): [issue("i1", "SNYK-1", "shared", "1.0")]})
        result = vex.derive_vex(client, [fetch_result], merge_result, generate_vex=True)
        self.assertEqual(result.document["serialNumber"], merge_result.document["serialNumber"])

    def test_dedups_same_vulnerability_across_project_occurrences_via_affects_array(self):
        # The same underlying vulnerability (by CVE) surfaces as a
        # distinct per-project issue ID in each project -- it must still
        # collapse to one vulnerability entry listing every occurrence.
        fetch_results, merge_result = build_merge_multi(
            [
                ("org-1", "p1", "shared", "1.0", "pkg:maven/shared@1.0"),
                ("org-2", "p2", "shared", "1.0", "pkg:maven/shared@1.0"),
            ]
        )
        client = FakeSnykClient(
            project_issues={
                ("org-1", "p1"): [issue("i1", "SNYK-1", "shared", "1.0", cve="CVE-2020-0001")],
                ("org-2", "p2"): [issue("i2", "SNYK-2", "shared", "1.0", cve="CVE-2020-0001")],
            },
        )
        result = vex.derive_vex(client, fetch_results, merge_result, generate_vex=True)

        self.assertEqual(result.vulnerability_count, 1)
        v = result.document["vulnerabilities"][0]
        self.assertEqual(v["id"], "CVE-2020-0001")
        self.assertEqual(len(v["affects"]), 2)
        occurrence_count = next(p["value"] for p in v["properties"] if p["name"] == "snyk:occurrenceCount")
        self.assertEqual(occurrence_count, "2")
        self.assertEqual(result.conflicting_state_count, 0)

    def test_conflicting_states_resolve_to_least_suppressed_and_are_flagged(self):
        # Open/unignored in one project, ignored (not-vulnerable) in another:
        # the least-suppressed state (exploitable) must win, and the
        # conflict must be reported.
        fetch_results, merge_result = build_merge_multi(
            [
                ("org-1", "p1", "shared", "1.0", "pkg:maven/shared@1.0"),
                ("org-2", "p2", "shared", "1.0", "pkg:maven/shared@1.0"),
            ]
        )
        client = FakeSnykClient(
            project_issues={
                ("org-1", "p1"): [issue("i1", "SNYK-1", "shared", "1.0", cve="CVE-2020-0001")],
                ("org-2", "p2"): [issue("i2", "SNYK-1", "shared", "1.0", cve="CVE-2020-0001")],
            },
            project_ignores={
                ("org-2", "p2"): {"SNYK-1": ignore_entry("not-vulnerable", "code not present")},
            },
        )
        result = vex.derive_vex(client, fetch_results, merge_result, generate_vex=True)

        self.assertEqual(result.vulnerability_count, 1)
        v = result.document["vulnerabilities"][0]
        self.assertEqual(v["analysis"], {"state": "exploitable"})
        self.assertEqual(result.conflicting_state_count, 1)

    def test_no_conflict_when_all_occurrences_agree(self):
        fetch_results, merge_result = build_merge_multi(
            [
                ("org-1", "p1", "shared", "1.0", "pkg:maven/shared@1.0"),
                ("org-2", "p2", "shared", "1.0", "pkg:maven/shared@1.0"),
            ]
        )
        client = FakeSnykClient(
            project_issues={
                ("org-1", "p1"): [issue("i1", "SNYK-1", "shared", "1.0", cve="CVE-2020-0001")],
                ("org-2", "p2"): [issue("i2", "SNYK-1", "shared", "1.0", cve="CVE-2020-0001")],
            },
        )
        result = vex.derive_vex(client, fetch_results, merge_result, generate_vex=True)
        self.assertEqual(result.conflicting_state_count, 0)


class DescriptiveFieldsTests(unittest.TestCase):
    EXTRA = {
        "title": "Deserialization of Untrusted Data",
        "description": "Long description.",
        "severities": [
            {"source": "Snyk", "level": "critical", "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            {"source": "NVD", "level": "weird", "score": 7.5, "vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
        ],
        "classes": [{"id": "CWE-502", "type": "weakness"}, {"id": "other", "type": "x"}],
        "coordinates": [
            {
                "created_at": "2024-02-01T00:00:00Z",
                "updated_at": "2024-03-01T00:00:00Z",
                "reachability": "reachable",
                "remedies": [{"description": "Upgrade to 1.4.6", "type": "indeterminate"}],
                "representations": [{"dependency": {"package_name": "shared", "package_version": "1.0"}}],
            }
        ],
        "exploit_details": {"maturity_levels": [{"format": "CVSSv3", "level": "proof of concept"}]},
    }

    def _vuln(self, extra, cve="CVE-2020-0001"):
        fetch_result, merge_result = build_merge("org-1", "p1", "shared", "1.0", "pkg:maven/shared@1.0")
        client = FakeSnykClient(project_issues={("org-1", "p1"): [issue("i1", "SNYK-1", "shared", "1.0", cve=cve, extra=extra)]})
        return vex.derive_vex(client, [fetch_result], merge_result, generate_vex=True).document["vulnerabilities"][0]

    def test_emits_descriptive_fields(self):
        v = self._vuln(self.EXTRA)
        self.assertEqual(v["source"], {"name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-0001"})
        self.assertEqual(v["description"], "Deserialization of Untrusted Data")
        self.assertEqual(v["detail"], "Long description.")
        self.assertEqual(v["cwes"], [502])
        self.assertEqual(v["recommendation"], "Upgrade to 1.4.6")
        self.assertEqual(
            [a["url"] for a in v["advisories"]],
            ["https://nvd.nist.gov/vuln/detail/CVE-2020-0001", "https://security.snyk.io/vuln/SNYK-1"],
        )
        self.assertEqual(v["analysis"]["firstIssued"], "2024-02-01T00:00:00Z")
        self.assertEqual(v["analysis"]["lastUpdated"], "2024-03-01T00:00:00Z")
        props = {p["name"]: p["value"] for p in v["properties"]}
        self.assertEqual(props["snyk:exploitMaturity"], "proof of concept")
        self.assertEqual(props["snyk:reachability"], "reachable")

    def test_ratings_map_method_and_unknown_severity(self):
        r = self._vuln(self.EXTRA)["ratings"]
        self.assertEqual(r[0], {"source": {"name": "Snyk"}, "score": 9.8, "severity": "critical",
                                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "method": "CVSSv31"})
        self.assertEqual((r[1]["severity"], r[1]["method"]), ("unknown", "CVSSv2"))

    def test_dates_from_problem(self):
        extra = {"problems": [{"id": "CVE-2020-0001", "source": "NVD", "type": "vulnerability",
                               "disclosed_at": "2020-01-01T00:00:00Z", "discovered_at": "2019-12-01T00:00:00Z",
                               "updated_at": "2020-02-01T00:00:00Z"}]}
        v = self._vuln(extra)
        self.assertEqual((v["published"], v["created"], v["updated"]),
                         ("2020-01-01T00:00:00Z", "2019-12-01T00:00:00Z", "2020-02-01T00:00:00Z"))

    def test_recommendation_built_from_fixed_in_versions(self):
        extra = {"coordinates": [{
            "remedies": [{"type": "indeterminate", "meta": {"data": {"fixed_in": ["1.4.7", "1.4.11"]}}}],
            "representations": [{"dependency": {"package_name": "shared", "package_version": "1.0"}}],
        }]}
        self.assertEqual(self._vuln(extra)["recommendation"], "Upgrade shared to 1.4.7 or 1.4.11.")

    def test_recommendation_without_fixed_in_uses_description_or_is_absent(self):
        coord = {"representations": [{"dependency": {"package_name": "shared", "package_version": "1.0"}}]}
        with_text = {"coordinates": [{**coord, "remedies": [{"description": "Apply patch X"}]}]}
        self.assertEqual(self._vuln(with_text)["recommendation"], "Apply patch X")
        no_fix = {"coordinates": [{**coord, "remedies": [{"type": "indeterminate", "meta": {"data": {}}}]}]}
        self.assertNotIn("recommendation", self._vuln(no_fix))

    def test_absent_data_adds_no_keys(self):
        v = self._vuln(None)
        for key in ("ratings", "cwes", "description", "detail", "recommendation", "published"):
            self.assertNotIn(key, v)
        self.assertEqual(v["analysis"], {"state": "exploitable"})


if __name__ == "__main__":
    unittest.main()
