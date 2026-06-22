# Demo 08 - SARIF export for GitHub code-scanning

## Where the data came from

A Django web app wired to GitHub code-scanning. We want license problems to
show up as inline PR annotations and in the repo Security tab, which means we
need **SARIF 2.1.0** output. The dependency set deliberately spans all three
non-compliant buckets:

- `paramiko` declared **LGPL-2.1** -> `warn` -> SARIF level **warning**.
- `mysql-connector` declared **GPL-2.0** -> `forbid` -> SARIF level **error**.
- `internal-widgets` has no resolvable license -> `unknown` -> SARIF **error**.

(LGPL-2.1 for paramiko and GPL-2.0 for the MySQL connector are real SPDX license
values for those projects; the names of placeholder packages are illustrative.)

## What it does

`licenselens --format sarif scan` emits a SARIF log with one `run` whose
`tool.driver` advertises the four `LIC-*` rules and their default levels.
Allow-listed dependencies are intentionally **omitted** so the code-scanning UI
is not flooded with compliant packages — only the three findings appear.

## Run it

```sh
# Emit SARIF and save it for upload:
python -m licenselens --format sarif scan demos/08-sarif-codescan/requirements.txt > licenselens.sarif

# In GitHub Actions, hand it to the code-scanning uploader:
#   - uses: github/codeql-action/upload-sarif@v3
#     with: { sarif_file: licenselens.sarif }
```

Expected: a SARIF 2.1.0 document with **3** results
(`LIC-WARN` warning, `LIC-FORBID` error, `LIC-UNKNOWN` error). The scan step
also exits **1** because the gate fails, so the CI job fails too.

## How to act

Open the PR: each finding is annotated on the requirements file. Fix the
forbidden + unknown dependencies (see demo 06 and demo 09 for the patterns),
then re-run. When only `allow`/`warn` remain, the SARIF run has zero `error`
results and the gate passes.
