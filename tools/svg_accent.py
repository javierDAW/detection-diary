#!/usr/bin/env python3
"""
tools/svg_accent.py — add/refresh a per-theme colour accent bar in every
kill_chain.svg, WITHOUT touching the frozen geometry or the canonical lane/stage
palette. This is the "minimal accent" approach: one 8px top bar coloured by the
case category, plus the matching `.acc-<category>` class set injected once into
each SVG's <style> block.

Category per case is read from docs/data.json (built by generate_site.py), so run
generate_site.py first. Idempotent: re-running updates the bar colour in place and
never duplicates the class defs.

Each file is written atomically and re-parsed (XML + viewBox bounds) before commit;
a file that would not verify is left untouched and reported.

Run:  python3 tools/generate_site.py && python3 tools/svg_accent.py
Author: Jarmi
"""

from __future__ import annotations
import sys, re, json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
DAYS = ROOT / "days"
DATA = ROOT / "docs" / "data.json"

ACC = {
    "ransomware": "#b03030", "espionage": "#2a4a6a", "supply-chain": "#b07a3a",
    "identity-cloud": "#6a4ca6", "ot-ics": "#2f8f4e", "edge-network": "#1d7a8c",
    "mobile": "#c2569a", "crypto-defi": "#d08a1f", "malware-re": "#556070", "other": "#6a6a6a",
}
CLASS_DEFS = "\n" + "\n".join(f".acc-{k} {{ fill: {v}; }}" for k, v in ACC.items()) \
             + '\n.accLabel { font: 700 11px sans-serif; fill: #ffffff; }\n'

BAR_RE = re.compile(r'\s*<rect class="acc-[\w-]+" x="0" y="0" width="880" height="8"\s*/>')
BG_RE = re.compile(r'(<rect class="bg"[^>]*/>)')
ACC_CLASS_PRESENT = re.compile(r'\.acc-[\w-]+\s*\{')


def verify(data: bytes) -> str:
    try:
        tree = ET.fromstring(data)
    except ET.ParseError as e:
        return f"XML parse: {e}"
    ns = "{http://www.w3.org/2000/svg}"
    vb = tree.attrib.get("viewBox", "").split()
    if len(vb) != 4:
        return "viewBox missing"
    W, H = float(vb[2]), float(vb[3])
    for r in tree.iter(f"{ns}rect"):
        try:
            x, y, w, h = (float(r.attrib[k]) for k in ("x", "y", "width", "height"))
        except Exception:
            continue
        if not (0 <= x and x + w <= W and 0 <= y and y + h <= H):
            return f"rect overflow x={x} y={y} w={w} h={h} vb {W}x{H}"
    return ""


def process(svg: Path, category: str) -> str:
    cat = category if category in ACC else "other"
    s = svg.read_text(encoding="utf-8")
    orig = s

    # 1. ensure the accent class set exists in the <style> CDATA
    if not ACC_CLASS_PRESENT.search(s):
        idx = s.find("]]>")
        if idx < 0:
            idx = s.find("</style>")
        if idx < 0:
            return "no <style> block"
        s = s[:idx] + CLASS_DEFS + s[idx:]

    # 2. refresh or insert the accent bar
    bar = f'\n  <rect class="acc-{cat}" x="0" y="0" width="880" height="8"/>'
    if BAR_RE.search(s):
        s = BAR_RE.sub(bar, s, count=1)
    else:
        m = BG_RE.search(s)
        if m:
            s = s[:m.end()] + bar + s[m.end():]
        else:
            idx = s.rfind("</svg>")
            if idx < 0:
                return "no </svg>"
            s = s[:idx] + bar + "\n" + s[idx:]

    if s == orig:
        return "ok (unchanged)"

    err = verify(s.encode("utf-8"))
    if err:
        return f"FAIL verify: {err} (left untouched)"
    tmp = svg.with_suffix(".svg.tmp")
    tmp.write_bytes(s.rstrip().encode("utf-8") + b"\n")
    if verify(tmp.read_bytes()):
        tmp.unlink(missing_ok=True)
        return "FAIL verify pass2 (left untouched)"
    tmp.replace(svg)
    return f"updated ({cat})"


def main():
    if not DATA.is_file():
        print("docs/data.json missing — run generate_site.py first", file=sys.stderr)
        return 2
    cat_by_slug = {c["slug"]: c.get("category", "other") for c in json.loads(DATA.read_text())}
    updated = failed = 0
    for svg in sorted(DAYS.rglob("kill_chain.svg")):
        slug = svg.parent.name
        res = process(svg, cat_by_slug.get(slug, "other"))
        if res.startswith("FAIL") or res.startswith("no "):
            failed += 1
            print(f"  {slug}: {res}")
        elif res.startswith("updated"):
            updated += 1
    print(f"svg_accent: {updated} updated, {failed} failed, "
          f"{len(list(DAYS.rglob('kill_chain.svg')))} total.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
