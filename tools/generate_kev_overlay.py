#!/usr/bin/env python3
"""
tools/generate_kev_overlay.py — cross-reference the CVEs in each case against
the CISA Known Exploited Vulnerabilities (KEV) catalog.

KEV tells you which CVEs are *confirmed exploited in the wild*, when CISA added
them, the federal remediation due date, and whether they are known to be used in
ransomware campaigns. Cross-referencing turns "interesting CVE" into a hard
prioritization signal.

Scope (IMPORTANT — incremental by design)
-----------------------------------------
By DEFAULT this scans only the CURRENT MONTH's case folder
(`days/YYYY/MM/`), NOT the whole history. This keeps daily runs fast and avoids
re-touching (git-churning) older cases. Override with:

    python3 tools/generate_kev_overlay.py                 # current month (default)
    python3 tools/generate_kev_overlay.py --month 2026/05 # a specific month
    python3 tools/generate_kev_overlay.py --day 2026-06-26_<slug>   # one case
    python3 tools/generate_kev_overlay.py --all           # full backfill (rare)

Outputs
-------
    days/.../<case>/kev.md     per-case KEV status table (English; only if the case has CVEs)
    feeds/kev_overlay.csv      cumulative overlay (incrementally merged, never fully rebuilt
                               unless --all): one row per (case, CVE)

KEV source
----------
Fetches https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
and caches it under tools/kev_cache/. If the network is unavailable, it falls
back to the cached copy so the daily flow never hard-fails.

Author: Jarmi
"""

from __future__ import annotations
import sys, re, csv, json, argparse, urllib.request
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
DAYS = ROOT / "days"
FEEDS = ROOT / "feeds"
CACHE_DIR = ROOT / "tools" / "kev_cache"
CACHE = CACHE_DIR / "known_exploited_vulnerabilities.json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
OVERLAY = FEEDS / "kev_overlay.csv"
OVERLAY_COLS = ["case", "date", "cve", "in_kev", "kev_date_added", "kev_due_date",
                "known_ransomware_use", "vulnerability_name", "vendor_project", "product"]


def load_kev():
    """Return {CVE_UPPER: entry}. Fetch fresh, cache, fall back to cache."""
    data = None
    try:
        req = urllib.request.Request(KEV_URL, headers={"User-Agent": "detection-diary/kev"})
        with urllib.request.urlopen(req, timeout=25) as r:
            data = json.loads(r.read().decode("utf-8"))
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        CACHE.write_text(json.dumps(data), encoding="utf-8")
        src = f"live (catalogVersion {data.get('catalogVersion','?')})"
    except Exception as e:
        if CACHE.is_file():
            data = json.loads(CACHE.read_text(encoding="utf-8"))
            src = f"cache (fetch failed: {e})"
        else:
            print(f"FATAL: cannot fetch KEV and no cache at {CACHE}: {e}", file=sys.stderr)
            sys.exit(2)
    kev = {}
    for v in data.get("vulnerabilities", []):
        kev[v["cveID"].upper()] = v
    return kev, src


def scope_dirs(args):
    if args.all:
        return sorted(p.parent for p in DAYS.rglob("README.md"))
    if args.day:
        hits = [p.parent for p in DAYS.rglob("README.md")
                if p.parent.name == args.day or args.day in p.parent.name]
        if not hits:
            print(f"no case folder matching --day {args.day}", file=sys.stderr); sys.exit(1)
        return sorted(set(hits))
    month = args.month or datetime.now(timezone.utc).strftime("%Y/%m")
    base = DAYS / month
    if not base.is_dir():
        print(f"month folder not found: {base.relative_to(ROOT)} (use --month YYYY/MM)", file=sys.stderr)
        return []
    return sorted(p.parent for p in base.rglob("README.md"))


def case_cves(folder: Path):
    cves = set()
    ioc = folder / "iocs.csv"
    if ioc.is_file():
        for r in csv.DictReader(ioc.open(encoding="utf-8")):
            if (r.get("type") or "").strip().lower() == "cve":
                for m in CVE_RE.findall(r.get("value") or ""):
                    cves.add(m.upper())
    readme = folder / "README.md"
    if readme.is_file():
        for m in CVE_RE.findall(readme.read_text(encoding="utf-8")):
            cves.add(m.upper())
    return sorted(cves)


def case_date(folder: Path):
    m = re.match(r"(\d{4}-\d{2}-\d{2})", folder.name)
    return m.group(1) if m else ""


def write_case_kev(folder: Path, rows, kev_src):
    """rows: list of dicts (OVERLAY_COLS subset). Returns path or None."""
    if not rows:
        # no CVEs in this case — remove a stale kev.md if present, write nothing
        stale = folder / "kev.md"
        if stale.is_file():
            stale.unlink()
        return None
    in_kev = [r for r in rows if r["in_kev"] == "yes"]
    lines = []
    lines.append(f"# CISA KEV status — {folder.name}")
    lines.append("")
    lines.append(f"_Cross-referenced against the CISA Known Exploited Vulnerabilities catalog "
                 f"({kev_src}). Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d')}._")
    lines.append("")
    lines.append(f"**{len(in_kev)} of {len(rows)} CVE(s) in this case are on the CISA KEV list "
                 f"(confirmed exploited in the wild).**")
    lines.append("")
    lines.append("| CVE | On KEV | Added | Remediation due | Ransomware use | Vulnerability |")
    lines.append("|---|---|---|---|---|---|")
    for r in rows:
        mark = "**yes**" if r["in_kev"] == "yes" else "no"
        lines.append(f"| {r['cve']} | {mark} | {r['kev_date_added'] or '—'} | "
                     f"{r['kev_due_date'] or '—'} | {r['known_ransomware_use'] or '—'} | "
                     f"{(r['vulnerability_name'] or '—')[:60]} |")
    lines.append("")
    if in_kev:
        lines.append("> KEV-listed CVEs are mandated for remediation in US federal agencies by the "
                     "due date above; treat them as patch-now priorities, not theoretical risk.")
    else:
        lines.append("> None of this case's CVEs are on KEV yet. That can mean newly disclosed, "
                     "vendor-confirmed-but-not-yet-cataloged, or not (publicly) mass-exploited.")
    lines.append("")
    path = folder / "kev.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def merge_overlay(scope_cases, new_rows, full_rebuild):
    FEEDS.mkdir(parents=True, exist_ok=True)
    existing = []
    if OVERLAY.is_file() and not full_rebuild:
        existing = [r for r in csv.DictReader(OVERLAY.open(encoding="utf-8"))
                    if r.get("case") not in scope_cases]  # drop in-scope, keep the rest
    rows = existing + new_rows
    rows.sort(key=lambda r: (r.get("date", ""), r.get("case", ""), r.get("cve", "")))
    with OVERLAY.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=OVERLAY_COLS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in OVERLAY_COLS})
    return len(rows)


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--month", help="YYYY/MM (default: current month)")
    g.add_argument("--day", help="case folder name or substring")
    g.add_argument("--all", action="store_true", help="scan entire history (backfill)")
    args = ap.parse_args()

    kev, src = load_kev()
    print(f"KEV loaded: {len(kev)} entries — {src}")

    dirs = scope_dirs(args)
    if not dirs:
        print("no cases in scope."); return 0
    scope_cases = {d.name for d in dirs}

    new_rows = []
    n_cases_with_cve = 0
    n_in_kev = 0
    written = 0
    for folder in dirs:
        cves = case_cves(folder)
        date = case_date(folder)
        case_rows = []
        for cve in cves:
            e = kev.get(cve)
            row = {
                "case": folder.name, "date": date, "cve": cve,
                "in_kev": "yes" if e else "no",
                "kev_date_added": e.get("dateAdded", "") if e else "",
                "kev_due_date": e.get("dueDate", "") if e else "",
                "known_ransomware_use": e.get("knownRansomwareCampaignUse", "") if e else "",
                "vulnerability_name": e.get("vulnerabilityName", "") if e else "",
                "vendor_project": e.get("vendorProject", "") if e else "",
                "product": e.get("product", "") if e else "",
            }
            case_rows.append(row)
            if e:
                n_in_kev += 1
        if cves:
            n_cases_with_cve += 1
        new_rows.extend(case_rows)
        if write_case_kev(folder, case_rows, src):
            written += 1

    total = merge_overlay(scope_cases, new_rows, full_rebuild=args.all)
    scope_name = "ALL history" if args.all else (args.day or args.month or datetime.now(timezone.utc).strftime("%Y/%m"))
    print(f"Scope: {scope_name} — {len(dirs)} case(s), {n_cases_with_cve} with CVEs.")
    print(f"  {len(new_rows)} CVE references, {n_in_kev} on KEV.")
    print(f"  Wrote {written} kev.md file(s); feeds/kev_overlay.csv now has {total} row(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
