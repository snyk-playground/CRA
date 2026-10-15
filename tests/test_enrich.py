import hashlib
import unittest

from snyk_generate_cra_sbom_vex import enrich

BASE = "http://central.test"
JAR = b"jar-bytes"
POM = b"""<project xmlns="http://maven.apache.org/POM/4.0.0">
  <organization><name>Acme Inc.</name><url>https://acme.example</url></organization>
  <scm><url>https://github.com/acme/lib</url></scm>
</project>"""
CHILD_POM = b"""<project><parent><groupId>org.acme</groupId><artifactId>parent</artifactId><version>1</version></parent></project>"""


def fake_fetch(files, calls=None):
    def fetch(url):
        if calls is not None:
            calls.append(url)
        data = files.get(url)
        return None if data is None else iter([data[:3], data[3:]])
    return fetch


def doc(*purls):
    return {"components": [{"bom-ref": f"r{i}", "name": "x", "purl": p} for i, p in enumerate(purls)]}


class EnrichTests(unittest.TestCase):
    PREFIX = BASE + "/org/acme/lib/1.0/lib-1.0"

    def files(self):
        return {self.PREFIX + ".jar": JAR, self.PREFIX + ".pom": POM}

    def test_adds_hash_supplier_refs_and_filename(self):
        d = doc("pkg:maven/org.acme/lib@1.0")
        r = enrich.enrich_maven_components(d, fake_fetch(self.files()), BASE)
        c = d["components"][0]
        self.assertEqual(c["hashes"], [{"alg": "SHA-512", "content": hashlib.sha512(JAR).hexdigest()}])
        self.assertEqual(c["supplier"], {"name": "Acme Inc.", "url": ["https://acme.example"]})
        self.assertEqual(c["externalReferences"], [
            {"type": "distribution", "url": self.PREFIX + ".jar"},
            {"type": "vcs", "url": "https://github.com/acme/lib"},
        ])
        self.assertIn({"name": "bsi:component:filename", "value": "lib-1.0.jar"}, c["properties"])
        self.assertEqual((r.hashed, r.supplier, r.not_found), (1, 1, 0))

    def test_looks_up_each_unique_artifact_once(self):
        calls = []
        d = doc("pkg:maven/org.acme/lib@1.0", "pkg:maven/org.acme/lib@1.0")
        r = enrich.enrich_maven_components(d, fake_fetch(self.files(), calls), BASE)
        self.assertEqual(r.unique_artifacts, 1)
        self.assertEqual(r.hashed, 2)
        self.assertEqual(sorted(calls), [self.PREFIX + ".jar", self.PREFIX + ".pom"])

    def test_supplier_inherited_from_parent_pom(self):
        files = {
            self.PREFIX + ".jar": JAR,
            self.PREFIX + ".pom": CHILD_POM,
            BASE + "/org/acme/parent/1/parent-1.pom": POM,
        }
        d = doc("pkg:maven/org.acme/lib@1.0")
        enrich.enrich_maven_components(d, fake_fetch(files), BASE)
        self.assertEqual(d["components"][0]["supplier"]["name"], "Acme Inc.")

    def test_never_guesses_supplier_and_skips_missing_jar(self):
        files = {self.PREFIX + ".pom": b"<project/>"}
        d = doc("pkg:maven/org.acme/lib@1.0")
        r = enrich.enrich_maven_components(d, fake_fetch(files), BASE)
        c = d["components"][0]
        for key in ("supplier", "hashes", "externalReferences", "properties"):
            self.assertNotIn(key, c)
        self.assertEqual((r.hashed, r.supplier, r.not_found), (0, 0, 1))

    def test_keeps_existing_values_and_skips_non_maven(self):
        d = doc("pkg:maven/org.acme/lib@1.0", "pkg:npm/left-pad@1.0")
        d["components"][0]["supplier"] = {"name": "Mine"}
        d["components"][0]["hashes"] = [{"alg": "SHA-512", "content": "abc"}]
        r = enrich.enrich_maven_components(d, fake_fetch(self.files()), BASE)
        self.assertEqual(d["components"][0]["supplier"], {"name": "Mine"})
        self.assertEqual(d["components"][0]["hashes"][0]["content"], "abc")
        self.assertEqual(r.skipped_non_maven, 1)

    def test_one_failing_artifact_does_not_abort(self):
        def fetch(url):
            raise OSError("boom")
        d = doc("pkg:maven/org.acme/lib@1.0")
        r = enrich.enrich_maven_components(d, fetch, BASE)
        self.assertEqual(r.not_found, 1)

    def test_parse_maven_purl(self):
        self.assertEqual(enrich.parse_maven_purl("pkg:maven/org.acme/lib@1.0?type=jar"), ("org.acme", "lib", "1.0"))
        self.assertIsNone(enrich.parse_maven_purl("pkg:npm/x@1"))
        self.assertIsNone(enrich.parse_maven_purl(None))


if __name__ == "__main__":
    unittest.main()
