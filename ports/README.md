# Ports of licenselens

The primary `licenselens scan` surface, ported across languages so you can drop
the **dependency license gate** into any stack or ship a single static binary.

Every port implements the same core pipeline as the Python reference:

1. parse a `requirements.txt`-style file (with inline `# license:` overrides),
2. normalize each license string to a canonical **SPDX id**,
3. classify it against the default **allow / warn / forbid** policy, and
4. gate the build with exit codes — `0` pass, `1` violation (forbid/unknown), `2` IO error.

They share the JSON output shape (`{tool, findings:[{name,version,license,risk}], counts, passed}`)
so results are interchangeable across languages.

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | `../licenselens/` | `licenselens scan requirements.txt` | `pytest` |
| JavaScript / Node | `javascript/` | `node index.js requirements.txt` | `node --test` |
| Go | `go/` | `go run . requirements.txt` | `go test ./...` |
| Rust | `rust/` | `cargo run -- requirements.txt` | `cargo test` |

Each port carries its own smoke test, and the [`ports.yml`](../.github/workflows/ports.yml)
workflow builds and tests **all three** ports on every push that touches `ports/`
— so the binaries are real and verifiable, not vaporware.

### Example (any port)

```bash
$ printf 'requests==2.31.0  # license: Apache-2.0\nbad==1.0  # license: GPL-3.0\nmystery==2.0\n' > req.txt
$ node ports/javascript/index.js req.txt
ALLOW   requests             2.31.0       Apache-2.0
FORBID  bad                  1.0          GPL-3.0
UNKNOWN mystery              2.0          UNKNOWN
gate: FAIL          # exit code 1
```

> Note: the ports resolve licenses from inline `# license:` overrides only; the
> Python reference additionally resolves from installed `*.dist-info/METADATA`
> and ships the offline `vulncheck` / `cve` vulnerability subcommands.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see ../CONTRIBUTING.md.
