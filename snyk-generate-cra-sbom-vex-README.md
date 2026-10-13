# Snyk CRA SBOM/VEX Generator

Generates an aggregate, EU CRA-aligned Software Bill of Materials (SBOM) and a
companion Vulnerability Exploitability eXchange (VEX) document from Snyk Open
Source and Container project data, across any combination of Snyk
organizations, targets, assets, projects, groups, and tags.

See `snyk-cra-sbom-vex-requirements.md.pdf` for the full requirements this
implements.

## Requirements

- Python 3.9 or later
- No third-party packages required (standard library only)
- A Snyk API token with access to the orgs/projects you want to include

## Setup

Provide your Snyk API token either as an environment variable or a flag
(`--token` takes precedence if both are set):

```bash
export SNYK_TOKEN=<your-snyk-api-token>
```

The Snyk REST API version to call defaults to a pinned date string
(`2024-10-15` as of this writing). If Snyk deprecates that version before
this script is updated, override it without a code change via
`SNYK_API_VERSION`, or per-run via `--api-version` (which takes precedence
over both):

```bash
export SNYK_API_VERSION=2025-06-01
```

## Running it

Run all commands from the repository root. The entry point is the top-level
script:

```bash
python3 snyk-generate-cra-sbom-vex.py --org <org-id>
```

At least one source flag is required. All six are repeatable and freely
combinable in a single run:

```bash
python3 snyk-generate-cra-sbom-vex.py \
  --org acme-platform \
  --target 3f9c... --target 7a21... \
  --project 55e0... \
  --group ee19... \
  --tag team=platform-security
```

Run `python3 snyk-generate-cra-sbom-vex.py --help` for the full flag
reference. The most commonly used ones:

| Flag | Purpose |
| --- | --- |
| `--org`, `--target`, `--asset`, `--project`, `--group`, `--tag` | Source selection (repeatable, at least one required) |
| `--token` | Snyk API token (overrides `$SNYK_TOKEN`) |
| `--sbom-format` | SBOM format (default `cyclonedx1.6+json`); see note below |
| `--output-prefix` | Filename stem for the output file(s) (default: `sbom` in the current directory for CycloneDX, `sbom`/`vex` for SPDX -- see below) |
| `--no-vex` | Write the SBOM only, skip VEX generation |
| `--fail-fast` | Abort on the first project-level failure instead of continuing |
| `--debug` / `-v` | Verbose logging (HTTP requests, pagination, per-project status) |

## What it does

For the resolved, de-duplicated set of projects:

1. Fetches each in-scope (Open Source/Container) project's SBOM.
2. Aggregates them into one CycloneDX document, keeping every component
   occurrence rather than de-duplicating by package URL: the same library
   appearing in more than one project -- or more than once within a single
   project -- appears that many times in the output, each occurrence with
   its own `bom-ref` and a `snyk:sourceProjectId` property for traceability.
3. Derives a CycloneDX VEX document from each project's vulnerability and
   ignore data. Unlike the SBOM, VEX content *is* de-duplicated: a
   vulnerability affecting several component occurrences (the same flaw
   surfaces as a separate issue in every project it's found in) collapses to
   one vulnerability entry listing every affected occurrence in its
   `affects` array, with a `snyk:occurrenceCount` property recording the
   count. If the ignore/triage state differs across occurrences, the
   least-suppressed state wins (open/unignored beats any ignored state) and
   the run summary reports the conflict.
4. Writes the output. Where VEX content lands depends on the SBOM format:
   - **CycloneDX** (the default): SBOM and VEX are written to a single file,
     e.g. `sbom.cdx.json` -- VEX is embedded directly in the aggregate SBOM
     document.
   - **SPDX**: written as two separate files, e.g. `sbom.spdx.json` and
     `vex.cdx.json` -- a standalone CycloneDX VEX document cross-referenced
     to the SPDX SBOM via a shared `serialNumber`, since SPDX has no
     VEX-equivalent field.

With `--output-prefix myrun`, the CycloneDX case produces `myrun.cdx.json`;
the SPDX case produces `myrun.sbom.spdx.json` and `myrun.vex.cdx.json`.

**Current limitation:** aggregation and VEX derivation are only implemented
for the default CycloneDX+JSON format. Choosing an XML or SPDX
`--sbom-format` still fetches per-project SBOMs, but the aggregate SBOM/VEX
files are not produced for those formats (the run will say so).

## Running the tests

```bash
python3 -m unittest discover -s tests -t .
```

## Production considerations

This script is intended for production use, but be aware of the following
before relying on it as your sole source of CRA compliance evidence:

- Aggregation and VEX derivation only support the default CycloneDX+JSON
  format (see the limitation noted above).
- VEX de-duplication (FR-9a) groups occurrences by CVE, falling back to
  Snyk's own vulnerability key when no CVE is present. Whether that key is
  reliably stable for "the same vulnerability" across different projects has
  not been confirmed against the live Issues API -- see Open Risk #8 in the
  requirements doc.
- The `--asset` source depends on a Snyk endpoint
  (`/rest/orgs/{org}/inventory/assets`) that is not yet documented as GA at
  https://apidocs.snyk.io — reverify before relying on it long-term.
- The API version defaults to a pinned date string, still not verified
  automatically against Snyk's changelog at startup. If Snyk deprecates it,
  override the effective default via `SNYK_API_VERSION` (or pin one
  explicitly per run via `--api-version`) rather than waiting on a code
  change.
- Rate-limit retry count/backoff are currently fixed, not yet configurable
  via flags.
- Each run produces a point-in-time snapshot; there is no historical
  diffing between runs.

## Disclaimer

This script is intended for production use. It is provided "as is," without
warranty of any kind, express or implied, including but not limited to
fitness for a particular purpose. The author assumes no responsibility or
liability for any damage, data loss, compliance outcome, or other
consequences resulting from its use — including from the Snyk API calls it
makes, the accuracy or completeness of the generated SBOM/VEX documents, or
any action taken based on their contents. Review the generated output and
validate it against your own organization's compliance requirements before
relying on it as CRA evidence.
