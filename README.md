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
licenselens scan requirements.txt          # license gate — prioritized findings in seconds
licenselens vulncheck requirements.txt     # + offline CVE enrichment vs 262k bundled OSV vulns
```

**What it does, concretely:** point it at a `requirements.txt`, and `licenselens`
(1) resolves every dependency's license to a canonical SPDX id, (2) gates the
build on an allow/warn/forbid policy, (3) emits a **CycloneDX 1.5 SBOM** and
**SARIF 2.1.0** for code-scanning, and (4) cross-references each package against
a **bundled, offline, ~262,000-record OSV vulnerability database** — no API key,
no network, works air-gapped.

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
7. **Check for known vulnerabilities** — cross-reference every dependency against
   the bundled offline OSV database (no network, no key):
   ```bash
   licenselens vulncheck requirements.txt                 # report
   licenselens vulncheck requirements.txt --fail-on high  # gate CI on high/critical
   licenselens --format json vulncheck requirements.txt | jq '.severity_counts'
   ```
8. **Resolve a single CVE / GHSA / OSV id** straight from the offline DB:
   ```bash
   licenselens cve CVE-2021-44228
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

- [Why licenselens?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Architecture](#architecture) · [Vulnerability enrichment](#vulncheck) · [Edge / air-gap](#edge) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)

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
- ✅ **Offline vulnerability enrichment** — match deps against a bundled **~262k-record OSV DB** (`vulncheck` / `cve`), no network, no key
- ✅ **Edge / air-gap ready** — refresh the corpus from NVD/OSV/GHSA when online, then sneakernet the cache to a disconnected enclave
- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer
- ✅ Ports in Python, JavaScript, Go, and Rust (`ports/`), each CI-built

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
pip install cognis-licenselens
licenselens --version
licenselens scan requirements.txt                  # license gate (table)
licenselens --format json scan requirements.txt    # machine-readable
licenselens --format sarif scan requirements.txt   # SARIF for code-scanning
licenselens vulncheck requirements.txt             # offline CVE enrichment
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Example — worked output

### License gate

```text
$ licenselens scan requirements.txt
RISK  NAME          VERSION  LICENSE      SOURCE
----------------------------------------------------
FAIL  pycopyleft    3.1.0    GPL-3.0      override
????  mysterylib    1.0.0    UNKNOWN      unresolved
OK    requests      2.31.0   Apache-2.0   metadata
OK    click         8.1.7    BSD-3-Clause metadata

summary: 2 allowed, 0 warn, 1 forbidden, 1 unknown
gate: FAIL
$ echo $?
1
```

### Offline vulnerability enrichment

```text
$ licenselens vulncheck requirements.txt --ecosystem PyPI
SEV   NAME        VULNS  LICENSE     TOP CVE / ADVISORY
-------------------------------------------------------
MOD   requests       13  Apache-2.0  CVE-2014-1830: Exposure of sensitive information ...
----  click           0  BSD-3-Clause

db: 262351 records (offline) · 1 vulnerable package(s) · 13 total vuln(s)
severity: 0 critical, 0 high, 1 moderate, 6 low, 6 unknown
```

### Single CVE lookup (offline)

```text
$ licenselens cve CVE-2021-44228
GHSA-jfh8-c2jp-5v3q  [Maven]  severity=critical
  aliases: CVE-2021-44228
  packages: org.apache.logging.log4j:log4j-core, ...
  summary: Remote code injection in Log4j
  published: 2021-12-10T00:40:56Z
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>
## Architecture

```mermaid
flowchart LR
  REQ[requirements.txt<br/>+ # license overrides] --> PARSE[parse + resolve]
  META[installed *.dist-info<br/>METADATA / PKG-INFO] --> PARSE
  PARSE --> NORM[normalize → SPDX]
  NORM --> POL[policy: allow / warn / forbid]
  POL --> GATE[exit code gate]
  POL --> SBOM[CycloneDX 1.5]
  POL --> SARIF[SARIF 2.1.0]
  PARSE --> VDB[(bundled OSV DB<br/>~262k vulns, offline)]
  VDB --> VULN[vulncheck / cve]
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="vulncheck"></a>
## Offline vulnerability enrichment

A license gate only answers half of a supply-chain review. `licenselens` ships
the other half **in the box**: `cognis_vulndb.jsonl.gz`, a consolidated, compact
**OSV corpus of ~262,000 real vulnerabilities** across PyPI, npm, Go, Maven,
RubyGems, crates.io and NuGet — each record carrying id, CVE/GHSA aliases,
ecosystem, summary, severity, affected packages, and publish/modify dates.

```bash
licenselens vulncheck requirements.txt                      # report
licenselens vulncheck requirements.txt --ecosystem Maven    # match another ecosystem
licenselens vulncheck requirements.txt --fail-on critical   # CI gate floor
licenselens cve CVE-2021-44228                              # resolve one id
licenselens --format json vulncheck requirements.txt        # machine-readable
```

- **Fully offline / air-gapped** — no API key, no network call, ever. The DB is
  the moment-of-clone baseline.
- **Namespace-tolerant matching** — a bare `log4j-core` resolves the Maven
  `org.apache.logging.log4j:log4j-core` record without inventing data.
- **No fabricated data** — a package with no real record reports **zero** vulns.
- **Severity-floor gate** — `--fail-on {off,any,low,moderate,high,critical}`
  (default `off` = report-only).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="edge"></a>
## Edge / air-gap refresh

The bundled DB is the offline baseline. When you *do* have connectivity, refresh
and extend it from upstream, then carry the cache to a disconnected enclave with
`licenselens.datafeeds` (`licenselens-feeds`):

```bash
# online side: pull from CISA-KEV / EPSS / OSV / NVD / GHSA (keyless, HTTPS)
licenselens-feeds list --domain vuln
licenselens-feeds update cisa-kev epss osv
licenselens-feeds snapshot-export feeds.tar.gz   # tar the cache (sneakernet)

# air-gapped side: import the snapshot; everything then serves from disk
licenselens-feeds snapshot-import feeds.tar.gz
licenselens-feeds get cisa-kev --offline
```

The catalog (`data_feeds_2026.json`) is real, recent, mostly-keyless intelligence
feeds. `offline=True` serves cache only and never touches the network. Bulk CVE
harvest (`licenselens-feeds bulk nvd-cve`) paginates NVD 2.0 / GHSA to grow the
corpus well past the bundled baseline.

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

## Scope, authorization & safety

`licenselens` is a **passive, offline, defensive** tool. It reads manifests and
package metadata on disk and matches them against a **bundled** vulnerability
database. It performs **no active scanning, no network probing, and no exploit
behavior** — `scan`, `vulncheck` and `cve` never touch the network. The optional
`licenselens-feeds` refresher only fetches **public, authorized intelligence
feeds** over HTTPS to update your local cache, and supports an explicit
`--offline` mode that serves the cache exclusively. No data is fabricated: every
vulnerability shown is a real OSV/CVE/GHSA record from the bundled corpus.

Use it on code and dependency manifests **you own or are authorized to audit**.

<div align="right"><a href="#top">↑ back to top</a></div>

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>
