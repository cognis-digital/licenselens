# Sources

## Vulnerability & license data (used by `vulncheck` / `cve`)

`licenselens` ships and refreshes from **real, public** data only — no fabricated
records.

- **Bundled OSV corpus** — `licenselens/cognis_vulndb.jsonl.gz`, a consolidated
  ~262,000-record snapshot of [OSV.dev](https://osv.dev) advisories across PyPI,
  npm, Go, Maven, RubyGems, crates.io and NuGet. Loaded **fully offline**.
- **License data** — resolved from inline `# license:` overrides and installed
  `*.dist-info/METADATA` (PEP 566), normalized to canonical SPDX ids.
- **Edge/air-gap refresh feeds** (`licenselens-feeds`, keyless HTTPS):
  - CISA Known Exploited Vulnerabilities (KEV)
  - FIRST EPSS exploit-probability scores
  - OSV.dev query + bulk ecosystem exports
  - NIST NVD CVE API 2.0
  - GitHub Security Advisories (GHSA)

See [`data_feeds_2026.json`](licenselens/data_feeds_2026.json) for the full,
domain-tagged catalog.

<!-- cognis-2026-live-sources -->

## Live 2026 sources (auto-expanded)

_Always-current feeds, live web-search queries, and keyless APIs for real-time monitoring. Ingest at runtime with `livesearch.py`._

### Ai
- **feed** · https://huggingface.co/blog/feed.xml
- **feed** · https://openai.com/news/rss.xml
- **feed** · https://www.anthropic.com/rss.xml
- **feed** · https://export.arxiv.org/rss/cs.AI
- **feed** · https://export.arxiv.org/rss/cs.LG
- **live search** · `frontier AI model release 2026`
- **live search** · `AI agent benchmark state of the art`
- **live search** · `open-weight LLM release`
- **live search** · `AI policy regulation 2026`
- **api** · http://export.arxiv.org/api/query (arXiv, free)
- **api** · https://api.github.com/search/repositories?q=stars (trending repos, free)
- **api** · https://hn.algolia.com/api (Hacker News, free)

### Supply Chain
- **feed** · https://www.supplychaindive.com/feeds/news/
- **feed** · https://www.freightwaves.com/news/feed
- **live search** · `port congestion shipping delay 2026`
- **live search** · `tariff supply chain disruption`
- **live search** · `semiconductor export control`
- **api** · https://comtradeapi.un.org (UN Comtrade, free key)

### Space
- **feed** · https://spacenews.com/feed/
- **feed** · https://www.nasaspaceflight.com/feed/
- **live search** · `satellite launch 2026 LEO constellation`
- **live search** · `SAR imagery commercial space`
- **api** · https://www.space-track.org (orbital catalog, free account)
- **api** · https://celestrak.org/NORAD/elements/ (TLE, free)

