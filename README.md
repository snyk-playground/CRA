# Snyk CRA SBOM/VEX Generator

A Python script that uses the Snyk API to generate an aggregate Software Bill of
Materials (SBOM) and a companion Vulnerability Exploitability eXchange (VEX)
document, aligned with the EU Cyber Resilience Act (CRA), from Snyk Open Source
and Container projects.

> **Disclaimer — educational and demonstration use**
>
> This script is primarily intended for **educational and demonstration
> purposes**. Use it with caution in production environments. It is provided
> "as is", without warranty of any kind, express or implied. The author cannot
> be held responsible for any unintended outcomes resulting from its use,
> including the Snyk API calls it makes, the accuracy or completeness of the
> generated SBOM/VEX documents, or any action taken based on their contents.
> Review the output and validate it against your own compliance requirements
> before relying on it.

## Features

- Select projects by organization, target, asset, project, group, or tag, in any
  combination (results are de-duplicated).
- Fetches each project's SBOM and aggregates them into one CycloneDX document.
- Derives a VEX document from each project's issue and ignore data.
- Shows a progress bar (percent complete, items done and total) while SBOMs and
  VEX data are generated.
- Writes the output to a single CycloneDX file, or an SBOM/VEX pair for SPDX.

## Requirements

- Python 3.9 or later (standard library only, no third-party packages)
- A Snyk API token with access to the projects you want to include

## Quick start

```bash
export SNYK_TOKEN=<your-snyk-api-token>
python3 snyk-generate-cra-sbom-vex.py --org <org-id>
```

This writes `sbom.cdx.json` to the current directory. Use `--output-prefix` to
choose the path and filename stem (missing directories are created), and run
`python3 snyk-generate-cra-sbom-vex.py --help` for all options.

For the full usage guide, known limitations, and output formats, see
[snyk-generate-cra-sbom-vex-README.md](snyk-generate-cra-sbom-vex-README.md).

## Running the tests

```bash
python3 -m unittest discover -s tests -t .
```

## Known limitations

- Aggregation and VEX derivation only support the default CycloneDX+JSON format.
- The `--asset` source relies on a Snyk endpoint that is not documented as GA.
- Each run is a point-in-time snapshot; there is no diffing between runs.

## License

No license has been specified for this repository.
