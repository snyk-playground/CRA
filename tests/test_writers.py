import json
import os
import tempfile
import unittest
from pathlib import Path

from snyk_generate_cra_sbom_vex import writers


class WriteOutputsTests(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp()
        os.chdir(self._tmp)

    def tearDown(self):
        os.chdir(self._cwd)

    # -- CycloneDX: one merged file (FR-10) ----------------------------------

    def test_cyclonedx_writes_one_file_with_vex_embedded(self):
        sbom_doc = {"bomFormat": "CycloneDX", "components": []}
        vex_doc = {"bomFormat": "CycloneDX", "vulnerabilities": [{"id": "CVE-2020-0001"}]}
        result = writers.write_outputs(sbom_doc, vex_doc, "cyclonedx1.6+json", output_prefix=None)

        self.assertEqual(result.sbom_path, Path("sbom.cdx.json"))
        self.assertIsNone(result.vex_path)
        self.assertTrue(result.vex_embedded)

        written = json.loads(Path("sbom.cdx.json").read_text())
        self.assertEqual(written["components"], [])
        self.assertEqual(written["vulnerabilities"], [{"id": "CVE-2020-0001"}])

    def test_cyclonedx_output_prefix_replaces_default_basename(self):
        result = writers.write_outputs({"components": []}, None, "cyclonedx1.6+json", output_prefix="myrun")
        self.assertEqual(result.sbom_path, Path("myrun.cdx.json"))
        self.assertTrue(result.sbom_path.exists())

    def test_cyclonedx_without_vex_writes_sbom_only(self):
        result = writers.write_outputs({"components": []}, None, "cyclonedx1.6+json", output_prefix=None)
        self.assertEqual(result.sbom_path, Path("sbom.cdx.json"))
        self.assertIsNone(result.vex_path)
        self.assertFalse(result.vex_embedded)

    # -- SPDX: two separate files (FR-10) ------------------------------------

    def test_spdx_writes_two_separate_files(self):
        sbom_doc = {"spdxVersion": "SPDX-2.3"}
        vex_doc = {"bomFormat": "CycloneDX", "vulnerabilities": []}
        result = writers.write_outputs(sbom_doc, vex_doc, "spdx2.3+json", output_prefix=None)

        self.assertEqual(result.sbom_path, Path("sbom.spdx.json"))
        self.assertEqual(result.vex_path, Path("vex.cdx.json"))
        self.assertFalse(result.vex_embedded)
        self.assertEqual(json.loads(Path("sbom.spdx.json").read_text()), sbom_doc)
        self.assertEqual(json.loads(Path("vex.cdx.json").read_text()), vex_doc)

    def test_spdx_output_prefix_is_used_as_filename_stem_for_both_files(self):
        result = writers.write_outputs({"a": 1}, {"b": 2}, "spdx2.3+json", output_prefix="myrun")
        self.assertEqual(result.sbom_path, Path("myrun.sbom.spdx.json"))
        self.assertEqual(result.vex_path, Path("myrun.vex.cdx.json"))
        self.assertTrue(result.sbom_path.exists())
        self.assertTrue(result.vex_path.exists())

    def test_spdx_without_vex_writes_sbom_only(self):
        result = writers.write_outputs({"a": 1}, None, "spdx2.3+json", output_prefix=None)
        self.assertIsNotNone(result.sbom_path)
        self.assertIsNone(result.vex_path)
        self.assertFalse(Path("vex.cdx.json").exists())

    # -- shared behavior ------------------------------------------------------

    def test_none_sbom_document_writes_nothing(self):
        result = writers.write_outputs(None, {"b": 2}, "cyclonedx1.6+json", output_prefix=None)
        self.assertIsNone(result.sbom_path)
        self.assertIsNone(result.vex_path)
        self.assertFalse(Path("sbom.cdx.json").exists())


if __name__ == "__main__":
    unittest.main()
