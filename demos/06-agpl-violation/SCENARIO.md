# Demo 06 - Network-copyleft violation: the gate fails the build

## Where the data came from

A closed-source SaaS backend (Flask + gunicorn + requests). Policy forbids
**strong/network copyleft** because the product ships as a hosted service and
the company does not want AGPL's network-use obligation to apply to its
proprietary code. Two problem dependencies have crept in:

- `grafana-client` declared **AGPL-3.0** — pulled in transitively for metrics.
- `acme-reporting` declared **Proprietary** — a vendored commercial module with
  no redistribution rights.

(Package names other than the well-known Flask/gunicorn/requests are
placeholders for the scenario; the license ids are real SPDX values. No CVEs,
hashes, or fingerprints are involved in this tool.)

## What to expect

Both forbidden licenses sort to the top of the table as `FAIL`. The summary
reports `2 forbidden`, the gate prints `gate: FAIL`, and the command exits with
code **1** — which fails the CI job.

## Run it

```sh
python -m licenselens scan demos/06-agpl-violation/requirements.txt
# machine-readable for a bot / dashboard:
python -m licenselens --format json scan demos/06-agpl-violation/requirements.txt
```

Expected: `3 allowed, 0 warn, 2 forbidden, 0 unknown`, `gate: FAIL`, exit `1`.

## How to act

Replace `grafana-client` with a permissively-licensed metrics client (or move
the AGPL component behind a process boundary / network API so it is not linked
into your distributed code, with legal sign-off). Remove `acme-reporting` or
obtain a redistribution license. Re-run until the gate exits `0`.
