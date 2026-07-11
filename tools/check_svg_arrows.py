#!/usr/bin/env python3
# Author: Jarmi
"""tools/check_svg_arrows.py - guard for kill_chain.svg cross-lane (.arrowX) arrows.

The frozen templates fix box geometry numerically but describe arrow endpoints in
prose, so bad arrow coordinates pass the XML/rect/text verifier silently. This guard
enforces the two arrow rules from the SVG standard:

  ERROR  cross-lane .arrowX must start/end on the FACING inner edges of the two lanes:
         left stage right edge x=425  <->  right op left edge x=460 (set {425,460}).
         A start at x=855 (op OUTER edge) draws the arrow THROUGH the op box interior.
  WARN   keep arrow dy < 200 (long diagonal cross-lane links; anchor to a hub instead).

Usage: python3 tools/check_svg_arrows.py [file ...]   (default: all days/**/kill_chain.svg)
Exit 0 if no errors, 2 if any error.
"""
import sys, re, glob

ARROWX = re.compile(r'class="arrowX"[^>]*\bd="M\s*(\d+)[ ,](\d+)\s+L\s*(\d+)[ ,](\d+)"')

def check(path):
    errors, warns = [], []
    txt = open(path, encoding="utf-8").read()
    n = 0
    for m in ARROWX.finditer(txt):
        n += 1
        x1, y1, x2, y2 = map(int, m.groups())
        if {x1, x2} != {425, 460}:
            errors.append(f"arrowX endpoints not on facing lane edges (x1={x1} x2={x2}; expected {{425,460}})")
        if abs(y1 - y2) >= 200:
            warns.append(f"arrowX dy={abs(y1-y2)} >= 200 (long cross-lane link; shorten or anchor to a hub)")
    return n, errors, warns

def main(argv):
    files = argv[1:] or sorted(glob.glob("days/**/kill_chain.svg", recursive=True))
    total_err = 0
    for f in files:
        n, errors, warns = check(f)
        if errors or warns:
            tag = "[FAIL]" if errors else "[warn]"
            print(f"{tag} {f}  ({n} arrowX)")
            for e in errors: print(f"   ERROR: {e}"); total_err += 1
            for w in warns:  print(f"   warn:  {w}")
    print(f"\n=== {len(files)} svg(s); {total_err} error(s)")
    return 0 if total_err == 0 else 2

if __name__ == "__main__":
    sys.exit(main(sys.argv))
