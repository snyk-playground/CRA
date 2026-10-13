"""Writes the aggregate SBOM and VEX documents to disk (FR-10).

Only CycloneDX+JSON documents exist to write today, since merge_sboms/
derive_vex only produce one for that format combination -- an XML or
SPDX --sbom-format run has nothing here to write yet (its skip reason
was already reported by the merge/VEX steps).

Per v0.6 (FR-10, FR-11), where VEX content lands depends on the selected
SBOM format:

- CycloneDX: SBOM and VEX are written to a single file -- the VEX
  vulnerabilities/analysis content is embedded directly into the
  aggregate SBOM document (FR-3) -- named from --output-prefix plus the
  format's native extension (default: sbom.cdx.json).
- SPDX: written as two separate files, the SPDX SBOM and a standalone
  CycloneDX VEX document (the bom variant containing only a
  vulnerabilities array), cross-referenced via a shared serialNumber and
  matching component identifiers, both named from --output-prefix
  (default: sbom/vex in the working directory).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

DEFAULT_SBOM_BASENAME = "sbom"
DEFAULT_VEX_BASENAME = "vex"
_VEX_EXTENSION = "cdx.json"  # the standalone VEX document is always CycloneDX (FR-3)


@dataclass(frozen=True)
class WriteResult:
    sbom_path: Optional[Path] = None
    vex_path: Optional[Path] = None
    # True when VEX content was embedded into sbom_path rather than written
    # to its own file (the CycloneDX case) -- distinguishes that from "no
    # VEX was produced at all" for reporting.py's summary.
    vex_embedded: bool = False


def _native_extension(sbom_format: str) -> str:
    """The on-disk extension for a --sbom-format value (FR-10)."""
    if sbom_format.startswith("cyclonedx"):
        return "cdx.xml" if sbom_format.endswith("+xml") else "cdx.json"
    if sbom_format.startswith("spdx"):
        return "spdx.json"
    return "json"


def _two_file_path(output_prefix: Optional[str], basename: str, extension: str) -> Path:
    """SPDX layout: "both named from --output-prefix ... (default: sbom/vex
    in the working directory)".

    Without --output-prefix, files are literally "sbom.<ext>"/"vex.<ext>"
    in the cwd. With one, e.g. --output-prefix ./out/run1, files become
    "./out/run1.sbom.<ext>"/"./out/run1.vex.<ext>" -- the prefix is a
    filename stem (its own directory must already exist), not just a
    directory.
    """
    if not output_prefix:
        return Path(f"{basename}.{extension}")
    return Path(f"{output_prefix}.{basename}.{extension}")


def _single_file_path(output_prefix: Optional[str], extension: str) -> Path:
    """CycloneDX layout: one file, "named from ... --output-prefix ...
    (default: sbom in the working directory, e.g. sbom.cdx.json)".

    Without --output-prefix, the file is "sbom.<ext>". With one, e.g.
    --output-prefix ./out/run1, the prefix itself is the filename stem:
    "./out/run1.<ext>".
    """
    if not output_prefix:
        return Path(f"{DEFAULT_SBOM_BASENAME}.{extension}")
    return Path(f"{output_prefix}.{extension}")


def _write_json(path: Path, document: Dict[str, Any]) -> None:
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def write_outputs(
    sbom_document: Optional[Dict[str, Any]],
    vex_document: Optional[Dict[str, Any]],
    sbom_format: str,
    output_prefix: Optional[str],
) -> WriteResult:
    """Writes whichever of the aggregate SBOM/VEX documents were produced.

    A document that wasn't produced (aggregation/VEX skipped for this
    run's format or state) is simply not written -- this function never
    fabricates a placeholder file.
    """
    if sbom_document is None:
        return WriteResult()

    extension = _native_extension(sbom_format)

    if sbom_format.startswith("cyclonedx"):
        document = sbom_document
        embedded = False
        if vex_document is not None:
            document = dict(sbom_document)
            document["vulnerabilities"] = vex_document["vulnerabilities"]
            embedded = True
        sbom_path = _single_file_path(output_prefix, extension)
        _write_json(sbom_path, document)
        logger.debug("wrote aggregate SBOM%s to %s", " + embedded VEX" if embedded else "", sbom_path)
        return WriteResult(sbom_path=sbom_path, vex_path=None, vex_embedded=embedded)

    # SPDX (or any other non-CycloneDX format): two separate files.
    sbom_path = _two_file_path(output_prefix, DEFAULT_SBOM_BASENAME, extension)
    _write_json(sbom_path, sbom_document)
    logger.debug("wrote aggregate SBOM to %s", sbom_path)

    vex_path = None
    if vex_document is not None:
        vex_path = _two_file_path(output_prefix, DEFAULT_VEX_BASENAME, _VEX_EXTENSION)
        _write_json(vex_path, vex_document)
        logger.debug("wrote standalone VEX to %s", vex_path)

    return WriteResult(sbom_path=sbom_path, vex_path=vex_path, vex_embedded=False)
