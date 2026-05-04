#!/usr/bin/env python3
"""
tools/sigma_check.py — offline structural validation for detection-diary Sigma rules.

Validates:
  - YAML parses without error and contains no NULL bytes
  - id is a valid UUID v4
  - status / level use enum values
  - date / modified are YYYY/MM/DD
  - logsource has at least one of category/product/service
  - detection has a condition and at least one selection
  - detection.condition only references defined selections (or wildcards)
  - field modifiers are from the known set

Use as a fast pre-commit check that does not require pysigma.
For full backend conversion, run tools/lint_sigma.sh (requires sigma-cli).
"""

from __future__ import annotations
import sys, os, re, glob, uuid
import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

VALID_STATUS = {"experimental","test","stable","deprecated","unsupported"}
VALID_LEVEL  = {"informational","low","medium","high","critical"}
VALID_MODS   = {
    "contains","contains|all","endswith","startswith","cidr",
    "gte","gt","lte","lt","equals","exists","re","regex",
    "base64","base64offset","wide","ascii","all","windash",
    "expand","fieldref","cased","i",
}

def is_uuid_v4(s: str) -> bool:
    try:
        u = uuid.UUID(s)
        return u.version == 4
    except Exception:
        return False

def check_modifiers(key: str, errors: list, where: str):
    parts = key.split("|")[1:]
    if not parts:
        return
    chain = "|".join(parts)
    if chain in VALID_MODS:
        return
    for p in parts:
        if p not in VALID_MODS:
            errors.append(f"{where}: unknown field modifier '|{p}' in '{key}'")

def collect_selection_names(detection: dict):
    return [k for k in detection.keys() if k != "condition"]

def lint_condition(cond: str, sels: list, errors: list, where: str):
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_*]*", cond)
    KEYWORDS = {"and","or","not","of","them","all","1","2","3","4","5","6","7","8","9"}
    for t in tokens:
        if t.lower() in KEYWORDS:
            continue
        if "*" in t:
            base = t.replace("*","")
            if not any(s.startswith(base) for s in sels):
                errors.append(f"{where}: condition wildcard '{t}' matches no selection")
            continue
        if t not in sels:
            errors.append(f"{where}: condition references undefined selection '{t}'")

def check_rule(path):
    errors, warnings = [], []
    with open(path, "rb") as f:
        raw = f.read()
    if b"\x00" in raw:
        errors.append("file contains NULL byte(s) — strip with: tr -d '\\0' < file > file.clean")
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"], []
    if not isinstance(data, dict):
        return ["root is not a mapping"], []

    for k in ("title","id","status","description","logsource","detection","level"):
        if k not in data:
            errors.append(f"missing required field: {k}")

    if "title" in data and not (1 <= len(str(data["title"])) <= 256):
        errors.append("title length out of [1,256]")

    if "id" in data and not is_uuid_v4(str(data["id"])):
        errors.append(f"id is not a valid UUID v4: {data['id']}")

    if "status" in data and data["status"] not in VALID_STATUS:
        errors.append(f"status '{data['status']}' not in {sorted(VALID_STATUS)}")

    if "level" in data and data["level"] not in VALID_LEVEL:
        errors.append(f"level '{data['level']}' not in {sorted(VALID_LEVEL)}")

    for dk in ("date","modified"):
        if dk in data and not re.match(r"^\d{4}/\d{2}/\d{2}$", str(data[dk])):
            warnings.append(f"{dk} not in YYYY/MM/DD: {data[dk]}")

    refs = data.get("references")
    if isinstance(refs, list):
        for r in refs:
            if not isinstance(r, str) or not r.startswith(("http://","https://")):
                warnings.append(f"reference not http(s): {r}")
    elif refs is not None:
        errors.append("references must be a list")

    ls = data.get("logsource", {})
    if isinstance(ls, dict):
        if not any(k in ls for k in ("category","product","service")):
            errors.append("logsource needs at least one of category/product/service")
    else:
        errors.append("logsource must be a mapping")

    det = data.get("detection", {})
    if not isinstance(det, dict):
        errors.append("detection must be a mapping")
    else:
        if "condition" not in det:
            errors.append("detection.condition is missing")
        sels = collect_selection_names(det)
        if not sels:
            errors.append("detection has no selection blocks")
        for sname in sels:
            sel = det[sname]
            if isinstance(sel, dict):
                for fk in sel.keys():
                    if "|" in fk:
                        check_modifiers(fk, errors, f"detection.{sname}")
        cond = det.get("condition","")
        if isinstance(cond, str):
            lint_condition(cond, sels, errors, "detection.condition")

    fp = data.get("falsepositives")
    if fp is None:
        warnings.append("falsepositives missing (recommended)")
    elif not isinstance(fp, list):
        errors.append("falsepositives must be a list")

    return errors, warnings

def main(argv):
    if len(argv) > 1:
        rules = argv[1:]
    else:
        rules = sorted(glob.glob(os.path.join(ROOT, "days/**/sigma/*.yml"), recursive=True))
        rules += sorted(glob.glob(os.path.join(ROOT, "days/**/sigma/*.yaml"), recursive=True))
    if not rules:
        print("No Sigma rules found")
        return 1
    fail = 0
    for r in rules:
        rel = os.path.relpath(r, ROOT)
        errors, warnings = check_rule(r)
        if not errors and not warnings:
            print(f"[ok]    {rel}")
        else:
            head = "[FAIL]" if errors else "[warn]"
            print(f"{head}  {rel}")
            for e in errors:
                print(f"   ERROR: {e}")
                fail += 1
            for w in warnings:
                print(f"   warn:  {w}")
    print(f"\n=== summary: {len(rules)} rule(s); {fail} error(s)")
    return 0 if fail == 0 else 2

if __name__ == "__main__":
    sys.exit(main(sys.argv))
