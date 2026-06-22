# Demo 09 - Unresolvable licenses: why UNKNOWN fails the gate

## Where the data came from

A legacy service's `requirements.txt` listing internal/vendored packages with
**no** inline `# license:` override and **no** installed package metadata
(`*.dist-info/METADATA`) anywhere in the project tree. This is the common
"nobody ever recorded the license" situation.

## What to expect

`licenselens` resolves licenses in priority order: override comment, then local
metadata, then `UNKNOWN`. Here every dependency falls through to `UNKNOWN`
(`source: unresolved`). The default policy treats an unaudited license as a real
legal risk, so all four count as `unknown`, the gate prints `gate: FAIL`, and
the command exits **1**.

## Run it

```sh
python -m licenselens scan demos/09-unpinned-unknowns/requirements.txt
```

Expected: `0 allowed, 0 warn, 0 forbidden, 4 unknown`, `gate: FAIL`, exit `1`.

## How to act

Resolve each unknown one of two ways:

1. **Install the package** so its metadata is present, then re-scan — the source
   becomes `metadata` automatically.
2. **Pin the license explicitly** with an override comment once you have
   confirmed it, e.g. `internal-auth-sdk  # license: Proprietary`. (Pinning it
   to a *forbidden* license still fails the gate — that is the point: it forces a
   real decision instead of leaving the license undocumented.)
