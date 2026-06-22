# Demo 05 - Data-science stack: the clean "happy path"

## Where the data came from

A representative training/notebook environment: the NumPy/pandas/SciPy core,
scikit-learn and XGBoost for modelling, matplotlib for plotting, JupyterLab for
the interface, and pyarrow + joblib for IO and serialization. Every one of
these is permissively licensed (BSD-3-Clause, Apache-2.0, or the PSF license).

## What to expect

All nine dependencies land in the `allow` bucket. The gate passes cleanly with
**no** warn / forbid / unknown findings, exit code **0**. This is the result a
healthy project should produce on every commit, so it makes a good positive
control for wiring the gate into CI.

## Run it

```sh
python -m licenselens scan demos/05-data-science/requirements.txt
```

Expected: `9 allowed, 0 warn, 0 forbidden, 0 unknown`, `gate: PASS`, exit `0`.

## How to act

Nothing to fix. Use this scenario to verify your CI step is actually invoked
and that a green run produces exit `0` (so the pipeline does not silently treat
every run as a pass).
