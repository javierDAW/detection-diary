# RUNBOOK — daily publish + post-processing

Operational run order for the detection-diary tooling. Run from the repo root
(`detection-diary/`). All commands assume Python 3 with PyYAML.

> **Write-tool truncation gotcha:** the editor truncates long files (~300 lines)
> mid-write — the same artifact documented for SVGs. **Generate or edit the
> `tools/*.py` scripts via the shell (heredoc), not the file editor.**

## Order of operations (after the day's case files are written)

The day folder (`days/YYYY/MM/YYYY-MM-DD_<slug>/`) must already contain its
README, kill_chain.svg, sigma/ kql/ yara/ suricata/ hunts/ and iocs.csv, and
must have passed the language + structural + SVG gates.

```bash
# 1. Structural / rule validation — require FAIL=0 errors=0
python3 tools/validate_all.py

# 2. CISA KEV cross-reference — SCOPED TO CURRENT MONTH ONLY (incremental).
#    Writes days/.../kev.md per case + merges feeds/kev_overlay.csv.
#    Default scope = current month; it does NOT rescan all history.
python3 tools/generate_kev_overlay.py

# 3. Indexes (INDEX.md + README gallery block + byActor/byTechnique/byPlatform)
python3 tools/generate_index.py

# 4. Pages gallery (docs/) — now with category colour accent + actor overlay
python3 tools/generate_site.py

# 5. Aggregated IOC feed (cumulative — whole tree, but fast)
#    feeds/iocs_all.csv + STIX 2.1 bundle + blocklists/*.txt
python3 tools/generate_ioc_feed.py

# 6. ATT&CK Navigator layers (cumulative)
#    navigator/coverage-enterprise.json + coverage-ics.json + cases/<slug>.json
python3 tools/generate_navigator.py
```

## Scoped vs cumulative — what rescans what

| Tool | Scope | Why |
|---|---|---|
| `generate_kev_overlay.py` | **Current month only** (default) | Avoids re-touching / git-churning old cases every day; KEV status of old CVEs rarely changes within a run, and a monthly re-pass picks up newly-cataloged CVEs. Use `--month YYYY/MM` or `--all` for an explicit backfill. |
| `generate_index.py` | Whole tree | Index must list every case. |
| `generate_site.py` | Whole tree | Gallery must show every case. |
| `generate_ioc_feed.py` | Whole tree | The feed is a single cumulative artifact; rebuild is cheap and IDs are deterministic. |
| `generate_navigator.py` | Whole tree | Cumulative heatmap = coverage across all cases. |

## KEV monthly rollover

`generate_kev_overlay.py` derives the month from the system date, so on the 1st
of a new month it automatically targets the new `days/YYYY/MM/`. To re-stamp a
finished month once (e.g. catch CVEs newly added to KEV), run it explicitly:

```bash
python3 tools/generate_kev_overlay.py --month 2026/05
```

## Per-case README integration (author step)

When writing a case that has CVEs:
* add a `kev.md` row to the **## What's in this folder** table:
  `| kev.md | CISA KEV cross-reference for this case's CVEs. | [kev.md](./kev.md) |`
* in **## IOCs**, add one line summarising KEV status (e.g. "CVE-XXXX is on CISA
  KEV, remediation due YYYY-MM-DD, known ransomware use"). Pull it from kev.md
  after running step 2.

## Commit

Include in the commit/bundle: the day folder (incl. `kev.md`), `feeds/`,
`navigator/`, `docs/`, `INDEX.md`, `README.md`, the by* facets. `tools/kev_cache/`
is a local fetch cache — it may be committed (small) or gitignored; either is fine.
