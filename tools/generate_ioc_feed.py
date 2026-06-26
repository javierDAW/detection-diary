#!/usr/bin/env python3
"""
tools/generate_ioc_feed.py — aggregate every day's iocs.csv into a single,
platform-agnostic threat-intel feed.

Outputs (under feeds/):
    feeds/iocs_all.csv                       deduped master CSV (first_seen/last_seen, source cases)
    feeds/stix/detection-diary-bundle.json   STIX 2.1 bundle (OpenCTI / MISP / any TIP)
    feeds/blocklists/ipv4.txt                one indicator per line (refanged)
    feeds/blocklists/ipv6.txt
    feeds/blocklists/domains.txt
    feeds/blocklists/urls.txt
    feeds/blocklists/sha256.txt
    feeds/blocklists/sha1.txt
    feeds/blocklists/md5.txt
    feeds/README.md                          usage / import notes

Design notes
------------
* Indicators in the repo are defanged ([.] , hxxp, [:]) — we refang before export.
* The per-day type vocabulary has drifted from the canonical set, so we map
  off-spec types and only emit STIX *patterns* for types that map to a real
  STIX Cyber-observable. Everything else still lands in iocs_all.csv.
* IDs are deterministic (UUIDv5 over type+value) so re-runs are idempotent and
  OpenCTI/MISP de-duplicate on re-import instead of creating churn.

Run from anywhere:
    python3 tools/generate_ioc_feed.py

Author: Jarmi
"""

from __future__ import annotations
import sys, csv, json, re, uuid
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
DAYS = ROOT / "days"
OUT = ROOT / "feeds"
STIX_DIR = OUT / "stix"
BL_DIR = OUT / "blocklists"

# Deterministic namespace for STIX/SCO IDs (stable across runs).
NS = uuid.UUID("b9d5f0e2-7c3a-4e91-8a6d-0f1e2d3c4b5a")

CONFIDENCE_MAP = {"high": 85, "medium": 50, "low": 15}
CONF_RANK = {"high": 3, "medium": 2, "low": 1}

# Map drifted/raw types -> canonical type used for export logic.
TYPE_ALIASES = {
    "ip": "ipv4", "ipv4": "ipv4", "ipv6": "ipv6",
    "domain": "domain", "fqdn": "domain",
    "url": "url", "uri": "url",
    "sha256": "sha256", "sha1": "sha1", "md5": "md5",
    "email": "email", "mutex": "mutex", "regkey": "regkey",
}

# Hash hex-length validation for STIX export.
HASH_LEN = {"sha256": 64, "sha1": 40, "md5": 32}
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def refang(v: str) -> str:
    if not v:
        return v
    v = v.strip()
    v = v.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    v = v.replace("[:]", ":").replace("[@]", "@").replace("[at]", "@")
    v = re.sub(r"\bhxxps\b", "https", v)
    v = re.sub(r"\bhxxp\b", "http", v)
    return v.strip()


def norm_conf(c: str) -> str:
    c = (c or "").strip().lower()
    if c.startswith("high"):
        return "high"
    if c.startswith("med"):
        return "medium"
    if c.startswith("low"):
        return "low"
    return "medium"


def stix_id(kind: str, *parts: str) -> str:
    seed = "|".join(parts)
    return f"{kind}--{uuid.uuid5(NS, kind + '|' + seed)}"


def stix_pattern(ctype: str, value: str):
    """Return (pattern, label) or (None, None) if not STIX-mappable."""
    if ctype == "ipv4":
        return f"[ipv4-addr:value = '{value}']", "ipv4"
    if ctype == "ipv6":
        return f"[ipv6-addr:value = '{value}']", "ipv6"
    if ctype == "domain":
        return f"[domain-name:value = '{value}']", "domain"
    if ctype == "url":
        if not value.lower().startswith(("http://", "https://")):
            return None, None  # bare paths are not valid url observables
        v = value.replace("'", "%27")
        return f"[url:value = '{v}']", "url"
    if ctype in HASH_LEN:
        if "..." in value or len(value) != HASH_LEN[ctype] or not HEX_RE.match(value):
            return None, None
        algo = {"sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5"}[ctype]
        return f"[file:hashes.'{algo}' = '{value.lower()}']", "file-hash"
    if ctype == "email":
        return f"[email-addr:value = '{value}']", "email"
    if ctype == "mutex":
        return f"[mutex:name = '{value}']", "mutex"
    if ctype == "regkey":
        v = value.replace("'", "")
        return f"[windows-registry-key:key = '{v}']", "registry"
    return None, None


def collect():
    """Return ({(ctype,value_lower): record}, n_files)."""
    agg = {}
    files = sorted(DAYS.rglob("iocs.csv"))
    for f in files:
        case = f.parent.name
        m = re.match(r"(\d{4}-\d{2}-\d{2})", case)
        cdate = m.group(1) if m else ""
        try:
            rows = list(csv.DictReader(f.open(encoding="utf-8")))
        except Exception as e:
            print(f"  WARN cannot read {f}: {e}", file=sys.stderr)
            continue
        for r in rows:
            raw_type = (r.get("type") or "").strip().lower()
            value = refang(r.get("value") or "")
            if not raw_type or not value:
                continue
            ctype = TYPE_ALIASES.get(raw_type, raw_type)
            conf = norm_conf(r.get("confidence"))
            ctx = (r.get("context") or "").strip()
            src = (r.get("source") or "").strip()
            key = (ctype, value.lower())
            rec = agg.get(key)
            if rec is None:
                rec = {
                    "type": ctype, "raw_type": raw_type, "value": value,
                    "context": ctx, "confidence": conf,
                    "first_seen": cdate, "last_seen": cdate,
                    "cases": set(), "sources": set(),
                }
                agg[key] = rec
            else:
                if cdate and (not rec["first_seen"] or cdate < rec["first_seen"]):
                    rec["first_seen"] = cdate
                if cdate and cdate > rec["last_seen"]:
                    rec["last_seen"] = cdate
                if CONF_RANK.get(conf, 0) > CONF_RANK.get(rec["confidence"], 0):
                    rec["confidence"] = conf
                if ctx and len(ctx) > len(rec["context"]):
                    rec["context"] = ctx
            if cdate:
                rec["cases"].add(case)
            if src:
                rec["sources"].add(src)
    return agg, len(files)


def write_csv(records):
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / "iocs_all.csv"
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["type", "value", "context", "confidence",
                    "first_seen", "last_seen", "case_count", "cases", "sources"])
        for r in records:
            w.writerow([
                r["type"], r["value"], r["context"], r["confidence"],
                r["first_seen"], r["last_seen"], len(r["cases"]),
                "; ".join(sorted(r["cases"])), " | ".join(sorted(r["sources"])),
            ])
    return path


def write_blocklists(records):
    BL_DIR.mkdir(parents=True, exist_ok=True)
    buckets = {"ipv4": [], "ipv6": [], "domain": [], "url": [],
               "sha256": [], "sha1": [], "md5": []}
    for r in records:
        t = r["type"]
        if t == "url" and not r["value"].lower().startswith(("http://", "https://")):
            continue  # bare paths are not blockable URLs
        if t in buckets:
            buckets[t].append(r["value"])
    name = {"domain": "domains", "url": "urls"}
    written = []
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    for t, vals in buckets.items():
        fn = BL_DIR / f"{name.get(t, t)}.txt"
        header = (f"# detection-diary blocklist — {t}\n"
                  f"# generated {stamp}\n"
                  f"# defensive/educational — validate before blocking; indicators decay\n")
        body = "\n".join(sorted(set(vals)))
        fn.write_text(header + body + ("\n" if body else ""), encoding="utf-8")
        written.append((fn, len(set(vals))))
    return written


def write_stix(records):
    STIX_DIR.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    identity_id = stix_id("identity", "detection-diary", "Jarmi")
    marking_id = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"  # TLP:CLEAR
    objects = [
        {
            "type": "identity", "spec_version": "2.1", "id": identity_id,
            "created": now, "modified": now,
            "name": "detection-diary (Jarmi)",
            "identity_class": "organization",
            "description": "Daily detection-engineering journal — aggregated IOC feed.",
        }
    ]
    n_ind = 0
    n_vuln = 0
    seen_vuln = set()
    for r in records:
        ctype, value = r["type"], r["value"]
        if ctype == "cve":
            name = value.upper()
            if name in seen_vuln:
                continue
            seen_vuln.add(name)
            vid = stix_id("vulnerability", name)
            objects.append({
                "type": "vulnerability", "spec_version": "2.1", "id": vid,
                "created": now, "modified": now, "name": name,
                "description": r["context"],
                "external_references": [{"source_name": "cve", "external_id": name}],
                "created_by_ref": identity_id,
                "object_marking_refs": [marking_id],
            })
            n_vuln += 1
            continue
        pattern, label = stix_pattern(ctype, value)
        if not pattern:
            continue
        valid_from = (r["first_seen"] or "2026-01-01") + "T00:00:00.000Z"
        ind = {
            "type": "indicator", "spec_version": "2.1",
            "id": stix_id("indicator", ctype, value.lower()),
            "created": now, "modified": now,
            "name": f"{label}: {value}",
            "description": r["context"] or f"{label} observed in detection-diary case(s)",
            "indicator_types": ["malicious-activity"],
            "pattern": pattern, "pattern_type": "stix",
            "valid_from": valid_from,
            "confidence": CONFIDENCE_MAP[r["confidence"]],
            "labels": sorted(r["cases"]) or [label],
            "created_by_ref": identity_id,
            "object_marking_refs": [marking_id],
            "external_references": [
                {"source_name": s} for s in sorted(r["sources"])[:5]
            ],
        }
        objects.append(ind)
        n_ind += 1
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    path = STIX_DIR / "detection-diary-bundle.json"
    path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
    return path, n_ind, n_vuln


README = """# IOC feed — detection-diary

Auto-generated by `tools/generate_ioc_feed.py`. **Do not edit by hand** — re-run the script.

Every indicator is aggregated from the per-case `days/**/iocs.csv` files, refanged
(`[.]` -> `.`, `hxxp` -> `http`), de-duplicated, and stamped with `first_seen` /
`last_seen` (the date span over which the indicator appeared in the diary) plus the
source case folders.

## Files

| File | Format | Use it with |
|---|---|---|
| `iocs_all.csv` | CSV | Excel, pandas, simple SIEM lookups, manual review |
| `stix/detection-diary-bundle.json` | STIX 2.1 bundle | **OpenCTI** (Data -> Import), MISP (STIX 2.1 import), Sentinel TI, ThreatConnect, Anomali, any TIP |
| `blocklists/*.txt` | one indicator/line | firewall / proxy / DNS sink blocklists, EDR hash bans |

## OpenCTI import

OpenCTI ingests STIX 2.1 natively. Either drag `stix/detection-diary-bundle.json`
into **Data -> Import**, or point a *Local STIX import* connector / the file-stix
connector at it. IDs are deterministic (UUIDv5), so re-importing an updated bundle
updates existing objects instead of duplicating them.

## MISP import

`Event -> Import from -> STIX 2.1` and select the bundle, or use
`misp-stix` (`misp-stix-import`) on the command line.

## Caveats (read before blocking)

* **Indicators decay.** A C2 IP/domain from weeks ago may be sinkholed, re-assigned,
  or dead. Check `last_seen` and validate before enforcement.
* **TLP:CLEAR**, defensive/educational. Confidence is carried from the diary
  (`high` = 85, `medium` = 50, `low` = 15 in STIX).
* Non-network types (`string`, `path`, `regkey`, `note`, `ttp`, ...) stay in
  `iocs_all.csv` only — they are detection context, not blockable network IOCs.
"""


def main():
    if not DAYS.is_dir():
        print("no days/ directory", file=sys.stderr)
        return 1
    agg, n_files = collect()
    records = sorted(agg.values(), key=lambda r: (r["type"], r["value"].lower()))
    csv_path = write_csv(records)
    bl = write_blocklists(records)
    stix_path, n_ind, n_vuln = write_stix(records)
    (OUT / "README.md").write_text(README, encoding="utf-8")

    by_type = {}
    for r in records:
        by_type[r["type"]] = by_type.get(r["type"], 0) + 1
    print(f"Aggregated {len(records)} unique indicators from {n_files} iocs.csv files.")
    print(f"  CSV   : {csv_path.relative_to(ROOT)}")
    print(f"  STIX  : {stix_path.relative_to(ROOT)}  ({n_ind} indicators, {n_vuln} vulnerabilities)")
    print(f"  Lists : {', '.join(f'{p.name}={n}' for p, n in bl if n)}")
    top = sorted(by_type.items(), key=lambda kv: -kv[1])[:8]
    print("  Types : " + ", ".join(f"{k}={v}" for k, v in top))
    return 0


if __name__ == "__main__":
    sys.exit(main())
