# Demo 07 - Emit a CycloneDX SBOM for supply-chain transparency

## Where the data came from

A small CLI tool (Click/Typer/Rich plus a couple of utility libs). You need to
publish a Software Bill of Materials so downstream consumers and compliance
reviewers can see exactly what ships and under which license.

## What to expect

`licenselens sbom` produces a **CycloneDX 1.5** JSON document. Every dependency
becomes a `component` with a `purl` (e.g. `pkg:pypi/click@8.1.7`) and its
normalized SPDX license id. The `metadata.tools` block records the tool name
and version. The `sbom` subcommand always exits **0** — it is a reporting
command, not a gate.

## Run it

```sh
# Full CycloneDX JSON (pipe to a file to attach as a CI artifact):
python -m licenselens --format json sbom demos/07-sbom-export/requirements.txt > sbom.json

# Quick human-readable component list:
python -m licenselens sbom demos/07-sbom-export/requirements.txt

# Validate the shape with jq:
python -m licenselens --format json sbom demos/07-sbom-export/requirements.txt \
  | jq '.bomFormat, (.components | length)'
```

Expected: `bomFormat: "CycloneDX"`, `specVersion: "1.5"`, 5 components, exit `0`.

## How to act

Attach `sbom.json` as a build artifact, or upload it to your SBOM registry /
dependency-track instance. Pair it with a `scan` step (see demos 04/06) so the
same dependency set is both gated and documented in one pipeline.
