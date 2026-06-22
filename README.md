<a name="top"></a>
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=LICENSELENS&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="LICENSELENS"/>

# LICENSELENS

### Dependency license + SBOM gate, developer-CLI first

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=Dependency+license++SBOM+gate+developerCLI+first;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>

[![PyPI](https://img.shields.io/pypi/v/cognis-licenselens.svg?color=6b46c1)](https://pypi.org/project/cognis-licenselens/) [![CI](https://github.com/cognis-digital/licenselens/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/licenselens/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

*Developer Tools — fast, single-purpose, CI- and agent-friendly.*

</div>

```bash
pip install cognis-licenselens
licenselens scan .            # → prioritized findings in seconds
```

## Usage — step by step

1. **Install** (Python 3.8+, stdlib only):
   ```bash
   pip install licenselens
   ```
2. **Scan a requirements file** against the built-in license policy and gate the build:
   ```bash
   licenselens scan requirements.txt
   ```
   Exits `0` when the gate passes, `1` on forbidden/unknown licenses, `2` on IO errors.
3. **Read the output as JSON** for dashboards or policy reporting:
   ```bash
   licenselens --format json scan requirements.txt | jq '.counts, .findings[]'
   ```
4. **Emit a CycloneDX-style SBOM** for the same dependency set:
   ```bash
   licenselens --format json sbom requirements.txt > sbom.json
   ```
5. **Gate CI** — fail the pipeline on a license violation, attach the SBOM as an artifact:
   ```bash
   licenselens scan requirements.txt && licenselens --format json sbom requirements.txt > sbom.json
   ```
6. **Upload findings to code-scanning** — emit a SARIF 2.1.0 log for the GitHub
   Security tab / PR annotations:
   ```bash
   licenselens --format sarif scan requirements.txt > licenselens.sarif
   ```


## Demos

Runnable, real-use-case scenarios live in [`demos/`](demos/). Each folder has a
`requirements.txt` in the tool's real input format plus a `SCENARIO.md` that
explains where the data came from, the exact command, and how to act on the
result.

| Demo | Scenario | Outcome |
|---|---|---|
| [`01-basic`](demos/01-basic/) | Mixed requirements with one GPL + one unknown | gate FAIL (exit 1) |
| [`04-fastapi-service`](demos/04-fastapi-service/) | Production FastAPI stack, one LGPL driver | gate PASS, 1 warn |
| [`05-data-science`](demos/05-data-science/) | NumPy/pandas/sklearn permissive stack | gate PASS, clean |
| [`06-agpl-violation`](demos/06-agpl-violation/) | AGPL + proprietary deps in a SaaS backend | gate FAIL (exit 1) |
| [`07-sbom-export`](demos/07-sbom-export/) | Publish a CycloneDX 1.5 SBOM | exit 0 |
| [`08-sarif-codescan`](demos/08-sarif-codescan/) | SARIF 2.1.0 for GitHub code-scanning | warn+error results |
| [`09-unpinned-unknowns`](demos/09-unpinned-unknowns/) | No overrides, no metadata → all UNKNOWN | gate FAIL (exit 1) |
| [`10-policy-clean-release`](demos/10-policy-clean-release/) | Resolve licenses from installed `.dist-info` metadata | gate PASS, source=metadata |

```bash
python -m licenselens scan demos/04-fastapi-service/requirements.txt
python -m licenselens --format sarif scan demos/08-sarif-codescan/requirements.txt
```


## Contents

- [Why licenselens?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)

<a name="why"></a>
## Why licenselens?

license risk in CI

`licenselens` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="features"></a>
## Features

- ✅ Normalize messy license strings → canonical SPDX ids
- ✅ Classify against an allow / warn / forbid policy (UNKNOWN = risk)
- ✅ Parse `requirements.txt` with inline `# license:` overrides
- ✅ Resolve licenses from installed `*.dist-info/METADATA` (PEP 566)
- ✅ Gate CI with exit codes (0 pass · 1 violation · 2 IO error)
- ✅ Export **CycloneDX 1.5 SBOM** and **SARIF 2.1.0** for code-scanning
- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer
- ✅ Ports in Python, JavaScript, Go, and Rust (`ports/`)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
pip install cognis-licenselens
licenselens --version
licenselens scan .                       # scan current project
licenselens scan . --format json         # machine-readable
licenselens scan . --fail-on high        # CI gate (non-zero exit)
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Example

```text
$ licenselens scan .
  [HIGH    ] LIC-001  example finding             (./src/app.py)
  [MEDIUM  ] LIC-002  another signal              (./config.yaml)

  2 findings · risk score 5 · 38ms
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>
## Architecture

```mermaid
flowchart LR
  IN[target / manifest] --> P[licenselens<br/>checks + rules]
  P --> OUT[findings (JSON / SARIF)]
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ai-stack"></a>
## Use it from any AI stack

`licenselens` is interoperable with every popular way of using AI:

- **MCP server** — `licenselens mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))
- **OpenAI-compatible / JSON** — pipe `licenselens scan . --format json` into any agent or LLM
- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line
- **CI / scripts** — exit codes + SARIF for non-AI pipelines

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="how-it-compares"></a>
## How it compares

| | **Cognis licenselens** | FOSSA |
|---|:---:|:---:|
| Self-hostable, no account | ✅ | varies |
| Single command, zero config | ✅ | ⚠️ |
| JSON + SARIF for CI | ✅ | varies |
| MCP-native (AI agents) | ✅ | ❌ |
| Polyglot ports (JS/Go/Rust) | ✅ | ❌ |
| Open license | ✅ COCL | varies |

*Built in the spirit of **FOSSA**, re-framed the Cognis way. Missing a credit? Open a PR.*

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="integrations"></a>
## Integrations

Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`licenselens mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="install-anywhere"></a>
## Install — every way, every platform

```bash
pip install "git+https://github.com/cognis-digital/licenselens.git"    # pip (works today)
pipx install "git+https://github.com/cognis-digital/licenselens.git"   # isolated CLI
uv tool install "git+https://github.com/cognis-digital/licenselens.git" # uv
pip install cognis-licenselens                                          # PyPI (when published)
docker run --rm ghcr.io/cognis-digital/licenselens:latest --help        # Docker
brew install cognis-digital/tap/licenselens                             # Homebrew tap
curl -fsSL https://raw.githubusercontent.com/cognis-digital/licenselens/main/install.sh | sh
```

| Linux | macOS | Windows | Docker | Cloud |
|---|---|---|---|---|
| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/licenselens` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="related"></a>
## Related Cognis tools

- [`mcpforge`](https://github.com/cognis-digital/mcpforge) — Scaffold, test, and publish MCP servers in minutes
- [`promptlint`](https://github.com/cognis-digital/promptlint) — Lint, version, and test prompts as code with a CI gate
- [`envdoctor`](https://github.com/cognis-digital/envdoctor) — .env validator, secret-presence and config-drift checker
- [`apidiff`](https://github.com/cognis-digital/apidiff) — Breaking-change detector for OpenAPI / GraphQL across commits
- [`codeglance`](https://github.com/cognis-digital/codeglance) — Repo onboarding map — architecture + hotspots for humans and agents
- [`flakefinder`](https://github.com/cognis-digital/flakefinder) — Flaky-test detector from CI history with quarantine suggestions

**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="contributing"></a>
## Contributing

PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

> ### ⭐ If `licenselens` saved you time, **star it** — it genuinely helps others find it.

## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>
