import json
import tempfile
import unittest
from pathlib import Path

from snyk_generate_cra_sbom_vex import cra_check

GOOD_COMPONENT = {
    "name": "lib", "version": "1", "purl": "pkg:maven/g/lib@1", "supplier": {"name": "Acme"},
    "hashes": [{"alg": "SHA-512", "content": "ab"}], "licenses": [{"expression": "MIT"}],
    "properties": [{"name": "bsi:component:filename", "value": "lib-1.jar"}],
    "externalReferences": [{"type": "distribution", "url": "u"}, {"type": "vcs", "url": "v"}],
}


def by_field(findings, scope, field):
    return next(f for f in findings if f.scope == scope and f.field == field)


class CheckDocumentTests(unittest.TestCase):
    def test_flags_missing_component_fields_with_counts(self):
        doc = {"components": [GOOD_COMPONENT, {"name": "bare", "version": "1"}]}
        findings = cra_check.check_document(doc)
        self.assertEqual(by_field(findings, "component", "hash (SHA-512)").missing, 1)
        self.assertEqual(by_field(findings, "component", "hash (SHA-512)").total, 2)
        self.assertTrue(by_field(findings, "component", "name").ok)

    def test_sha1_does_not_count_as_a_hash(self):
        doc = {"components": [{**GOOD_COMPONENT, "hashes": [{"alg": "SHA-1", "content": "ab"}]}]}
        self.assertEqual(by_field(cra_check.check_document(doc), "component", "hash (SHA-512)").missing, 1)

    def test_sbom_and_product_level_checks(self):
        doc = {
            "metadata": {"timestamp": "t", "authors": [{"email": "a@b"}], "lifecycles": [{"phase": "pre-build"}],
                         "manufacturer": {"name": "Acme"}, "component": {"name": "App"}},
            "compositions": [{"aggregate": "unknown"}],
        }
        f = cra_check.check_document(doc)
        for field in ("timestamp", "SBOM creator contact (authors or manufacturer)", "lifecycle phase",
                      "completeness statement (compositions)"):
            self.assertTrue(by_field(f, "SBOM", field).ok, field)
        self.assertTrue(by_field(f, "product", "creator (manufacturer/supplier)").ok)
        self.assertFalse(by_field(f, "product", "version").ok)

    def test_not_affected_requires_justification(self):
        v = {"id": "CVE-1", "analysis": {"state": "not_affected"}}
        f = cra_check.check_document({"vulnerabilities": [v]})
        self.assertEqual(by_field(f, "vulnerability", "analysis.justification (when not_affected)").missing, 1)

    def test_report_and_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "x.json"
            path.write_text(json.dumps({"components": [{"name": "bare"}]}))
            report = cra_check.render_report(cra_check.check_file(path))
        self.assertIn("MISSING on 1/1", report)
        self.assertIn("have gaps", report)


if __name__ == "__main__":
    unittest.main()
