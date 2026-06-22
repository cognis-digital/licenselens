# Demo 10 - Resolve licenses from installed package metadata (no overrides)

## Where the data came from

A release candidate where the dependencies are actually installed. Instead of
hand-pinning licenses with `# license:` comments, this demo ships real
`*.dist-info/METADATA` files under `./site-packages` — the same PEP 566 metadata
pip writes when it installs a package. The `requirements.txt` has **no**
override comments, so `licenselens` must fall through to its second resolution
tier and read the license out of the installed metadata.

```
10-policy-clean-release/
  requirements.txt
  site-packages/
    requests-2.32.3.dist-info/METADATA   (Apache-2.0)
    click-8.1.7.dist-info/METADATA       (BSD-3-Clause)
    colorama-0.4.6.dist-info/METADATA    (BSD-3-Clause)
```

## What to expect

Each finding's **source is `metadata`** (not `override`), proving the metadata
walker resolved the license from the `.dist-info` directory. All three are
permissive, so the gate passes with exit code **0**. The license values are read
from the Trove `Classifier: License :: ...` lines, which the tool prefers over
the free-form `License:` field.

## Run it

```sh
python -m licenselens scan demos/10-policy-clean-release/requirements.txt
```

Expected: 3 findings all `OK` with `source = metadata`,
`3 allowed, 0 warn, 0 forbidden, 0 unknown`, `gate: PASS`, exit `0`.

## How to act

This is the resolution mode to prefer in a fully-installed environment: it needs
no manual override bookkeeping and stays correct as versions change. Run the
scan after `pip install -r requirements.txt` in the same job so the metadata is
present for the walker to find.
