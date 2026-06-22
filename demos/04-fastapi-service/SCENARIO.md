# Demo 04 - FastAPI service: a passing gate with one license to review

## Where the data came from

This is the pinned runtime `requirements.txt` of a typical production FastAPI
web service: the web framework, ASGI server, validation, an HTTP client, an
ORM, a Postgres driver, a Redis client, and a JWT library. License ids are
pinned with inline `# license:` overrides so the result is identical on any CI
runner regardless of whether the packages happen to be installed.

## What to expect

The whole permissive stack (MIT / BSD-3-Clause) is on the allow list. The one
exception is **`psycopg2-binary`**, whose license is **LGPL-3.0**. The default
policy puts LGPL in the `warn` bucket: it is reported and surfaced, but it does
**not** fail the gate. So the scan exits `0` (gate PASS) while still flagging
the dependency for a human to review.

## Run it

```sh
python -m licenselens scan demos/04-fastapi-service/requirements.txt
```

Expected: a risk-sorted table, `8 allowed, 1 warn, 0 forbidden, 0 unknown`,
`gate: PASS`, exit code **0**.

## How to act

LGPL dynamic linking is usually fine for a server-side application that does
not redistribute the library, but the warn line is your prompt to confirm that
with whoever owns license policy. If you want LGPL to hard-fail instead, move
`LGPL-3.0` from the `warn` bucket into `forbid` in your policy.
