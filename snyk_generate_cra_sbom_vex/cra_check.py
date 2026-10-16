"""Reports which CRA-relevant fields a CycloneDX SBOM/VEX document lacks.

The checklist follows BSI TR-03183-2 (SBOM) and TR-03183-3 (VEX), the
technical guidelines usually used to put the CRA's SBOM and
vulnerability-handling duties (Annex I Part II) into concrete fields.
It is a field-presence check on one document: it can't tell whether a
value is *correct*, and it doesn't cover obligations that live outside
the SBOM (support period, declaration of conformity, ...).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Sequence

from .enrich import FILENAME_PROPERTY

Predicate = Callable[[Dict[str, Any]], bool]


@dataclass(frozen=True)
class Finding:
    scope: str  # "SBOM", "product", "component" or "vulnerability"
    field: str
    missing: int
    total: int

    @property
    def ok(self) -> bool:
        return self.missing == 0


def _has_hash(c: Dict[str, Any]) -> bool:
    return any(h.get("alg") == "SHA-512" and h.get("content") for h in c.get("hashes") or [])


def _has_creator(c: Dict[str, Any]) -> bool:
    return bool(c.get("supplier") or c.get("manufacturer") or c.get("author") or c.get("authors"))


def _has_ref(*types: str) -> Predicate:
    return lambda c: any(r.get("type") in types for r in c.get("externalReferences") or [])


def _has_property(name: str) -> Predicate:
    return lambda c: any(p.get("name") == name for p in c.get("properties") or [])


_PRODUCT_CHECKS: Sequence[Any] = (
    ("name", lambda c: bool(c.get("name"))),
    ("version", lambda c: bool(c.get("version"))),
    ("creator (manufacturer/supplier)", _has_creator),
    ("hash (SHA-512)", _has_hash),
    ("license", lambda c: bool(c.get("licenses"))),
    ("security contact / advisories reference", _has_ref("security-contact", "advisories")),
)

_COMPONENT_CHECKS: Sequence[Any] = (
    ("name", lambda c: bool(c.get("name"))),
    ("version", lambda c: bool(c.get("version"))),
    ("creator (supplier/manufacturer/author)", _has_creator),
    ("unique identifier (purl/cpe/swid)", lambda c: bool(c.get("purl") or c.get("cpe") or c.get("swid"))),
    ("hash (SHA-512)", _has_hash),
    ("license", lambda c: bool(c.get("licenses"))),
    ("filename", _has_property(FILENAME_PROPERTY)),
    ("distribution URL", _has_ref("distribution")),
    ("source code URL", _has_ref("vcs")),
)


def _vulnerability_checks() -> Sequence[Any]:
    def justified(v: Dict[str, Any]) -> bool:
        a = v.get("analysis") or {}
        return a.get("state") != "not_affected" or bool(a.get("justification"))

    return (
        ("id", lambda v: bool(v.get("id"))),
        ("source", lambda v: bool((v.get("source") or {}).get("name"))),
        ("ratings", lambda v: bool(v.get("ratings"))),
        ("affects", lambda v: bool(v.get("affects"))),
        ("analysis.state", lambda v: bool((v.get("analysis") or {}).get("state"))),
        ("analysis.justification (when not_affected)", justified),
        ("description", lambda v: bool(v.get("description"))),
        ("recommendation", lambda v: bool(v.get("recommendation"))),
        ("advisories", lambda v: bool(v.get("advisories"))),
    )


def check_document(doc: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    metadata = doc.get("metadata") or {}

    sbom_checks = (
        ("timestamp", bool(metadata.get("timestamp"))),
        (
            "SBOM creator contact (authors or manufacturer)",
            any(a.get("email") or a.get("name") for a in metadata.get("authors") or [])
            or bool(metadata.get("manufacturer") or metadata.get("manufacture")),
        ),
        ("lifecycle phase", bool(metadata.get("lifecycles"))),
        ("completeness statement (compositions)", bool(doc.get("compositions"))),
    )
    for name, present in sbom_checks:
        findings.append(Finding("SBOM", name, 0 if present else 1, 1))

    product = dict(metadata.get("component") or {})
    # The manufacturer lives on metadata, not on the product component itself.
    if metadata.get("manufacturer") or metadata.get("manufacture"):
        product.setdefault("manufacturer", metadata.get("manufacturer") or metadata.get("manufacture"))
    for name, check in _PRODUCT_CHECKS:
        findings.append(Finding("product", name, 0 if product and check(product) else 1, 1))

    components = doc.get("components") or []
    for name, check in _COMPONENT_CHECKS:
        findings.append(Finding("component", name, sum(1 for c in components if not check(c)), len(components)))

    vulns = doc.get("vulnerabilities") or []
    for name, check in _vulnerability_checks():
        findings.append(Finding("vulnerability", name, sum(1 for v in vulns if not check(v)), len(vulns)))
    return findings


def render_report(findings: Sequence[Finding]) -> str:
    gaps = [f for f in findings if not f.ok]
    lines = ["CRA field check (BSI TR-03183-2/-3 based; presence only)"]
    scope = None
    for f in findings:
        if f.scope != scope:
            scope = f.scope
            lines.append(f"  {scope}:")
        if f.total == 0:
            status = "n/a (none present)"
        elif f.ok:
            status = "ok"
        else:
            status = f"MISSING on {f.missing}/{f.total}" if f.scope in ("component", "vulnerability") else "MISSING"
        lines.append(f"    {f.field:<46} {status}")
    lines.append(f"{len(gaps)} of {len(findings)} check(s) have gaps.")
    return "\n".join(lines)


def check_file(path: Path) -> List[Finding]:
    return check_document(json.loads(path.read_text(encoding="utf-8")))
