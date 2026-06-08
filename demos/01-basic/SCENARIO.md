# Demo 01 - Basic license gate

A project pins seven dependencies in `requirements.txt`. Most carry permissive
licenses, but two are problematic:

- `pycopyleft` declares `GPL-3.0` (forbidden by the default policy).
- `mysterylib` ships no resolvable license (UNKNOWN -> treated as a risk).

License data is resolved in priority order:

1. Inline override comment (`# license: MIT`) on the requirement line.
2. Locally installed package metadata (`*.dist-info/METADATA`).
3. Otherwise `UNKNOWN`.

## Run it

```sh
# Human-readable gate (table is the default format)
python -m licenselens scan demos/01-basic/requirements.txt

# Machine-readable for CI
python -m licenselens --format json scan demos/01-basic/requirements.txt

# Emit an SBOM
python -m licenselens --format json sbom demos/01-basic/requirements.txt
```

## Expected outcome

The `scan` command prints a risk-sorted table, reports `1 forbidden` and
`1 unknown`, prints `gate: FAIL`, and exits with code **1** - which fails the
CI job. Remove or re-license `pycopyleft` and add a license override for
`mysterylib` to make the gate pass (exit `0`).

The `sbom` command always exits `0` and produces a CycloneDX 1.5 document
listing every component with its normalized SPDX license id.
