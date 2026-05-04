#!/usr/bin/env python3
"""
tools/validate_all.py — offline multi-format validator for detection-diary.

Validates every file type that lives in the repo:

    Sigma       (days/**/sigma/*.yml)         — full structural check
    YARA        (days/**/yara/*.yar)          — block + section parser
    Suricata    (days/**/suricata/*.rules)    — line-level regex parser
    KQL         (days/**/kql/*.kql)           — heuristic balance + keywords
    SPL         (days/**/spl/*.spl)           — heuristic balance + commands
    CSV         (days/**/iocs.csv)            — header schema enforcement
    YAML        (.github/workflows/*.yml etc) — PyYAML strict load
    Markdown    (**/*.md)                     — link sanity (relative path exists)
    Bash        (tools/*.sh)                  — bash -n if available

Errors fail; warnings don't. PyYAML is the only dependency — everything else is
pure stdlib so the script runs in any minimal Python 3.8+ environment.

Usage:
    python3 tools/validate_all.py                  # validate the whole repo
    python3 tools/validate_all.py path1 path2 ...  # validate specific files

Exit code: 0 if no errors, 2 if any errors.
"""

from __future__ import annotations
import os, sys, re, csv, glob, uuid, subprocess, shutil
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(3)

# ---------------------------------------------------------------------------
# Repo root resolution
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Sigma validator (re-export of sigma_check.py logic, kept consistent)
# ---------------------------------------------------------------------------
VALID_STATUS = {"experimental","test","stable","deprecated","unsupported"}
VALID_LEVEL  = {"informational","low","medium","high","critical"}
VALID_MODS   = {
    "contains","contains|all","endswith","startswith","cidr",
    "gte","gt","lte","lt","equals","exists","re","regex",
    "base64","base64offset","wide","ascii","all","windash",
    "expand","fieldref","cased","i",
}

def _is_uuid_v4(s: str) -> bool:
    try:
        u = uuid.UUID(s); return u.version == 4
    except Exception:
        return False

def validate_sigma(path: Path):
    errors, warnings = [], []
    raw = path.read_bytes()
    if b"\x00" in raw:
        errors.append("file contains NULL byte(s)")
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"], []
    if not isinstance(data, dict):
        return ["root is not a mapping"], []
    for k in ("title","id","status","description","logsource","detection","level"):
        if k not in data:
            errors.append(f"missing required field: {k}")
    if "id" in data and not _is_uuid_v4(str(data["id"])):
        errors.append(f"id is not a valid UUID v4: {data['id']}")
    if "status" in data and data["status"] not in VALID_STATUS:
        errors.append(f"status '{data['status']}' invalid")
    if "level" in data and data["level"] not in VALID_LEVEL:
        errors.append(f"level '{data['level']}' invalid")
    for dk in ("date","modified"):
        if dk in data and not re.match(r"^\d{4}/\d{2}/\d{2}$", str(data[dk])):
            warnings.append(f"{dk} not in YYYY/MM/DD")
    ls = data.get("logsource", {})
    if isinstance(ls, dict):
        if not any(k in ls for k in ("category","product","service")):
            errors.append("logsource needs at least one of category/product/service")
    det = data.get("detection", {})
    if isinstance(det, dict):
        if "condition" not in det:
            errors.append("detection.condition is missing")
        sels = [k for k in det.keys() if k != "condition"]
        for sname in sels:
            sel = det[sname]
            if isinstance(sel, dict):
                for fk in sel.keys():
                    if "|" in fk:
                        parts = fk.split("|")[1:]
                        chain = "|".join(parts)
                        if chain not in VALID_MODS:
                            for p in parts:
                                if p not in VALID_MODS:
                                    errors.append(f"unknown field modifier '|{p}' in '{fk}'")
        cond = det.get("condition","")
        if isinstance(cond, str):
            tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_*]*", cond)
            for t in tokens:
                if t.lower() in {"and","or","not","of","them","all","1","2","3","4","5"}:
                    continue
                if "*" in t:
                    base = t.replace("*","")
                    if not any(s.startswith(base) for s in sels):
                        errors.append(f"condition wildcard '{t}' matches no selection")
                    continue
                if t not in sels:
                    errors.append(f"condition references undefined selection '{t}'")
    if "falsepositives" not in data:
        warnings.append("falsepositives missing (recommended)")
    return errors, warnings

# ---------------------------------------------------------------------------
# YARA validator (block parser, no dependency) — also catches unreferenced strings
# ---------------------------------------------------------------------------
def _yara_iter_rules(text):
    rule_re = re.compile(
        r"(?:^|\n)\s*(?:private\s+|global\s+|private\s+global\s+)?"
        r"rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[A-Za-z0-9_ ]+)?\s*\{",
        re.MULTILINE,
    )
    for m in rule_re.finditer(text):
        start = m.end()
        depth = 1
        i = start
        while i < len(text) and depth > 0:
            if text[i] == "{": depth += 1
            elif text[i] == "}": depth -= 1
            i += 1
        body = text[start:i-1]
        yield m.group(1), body


def _yara_collect_strings(body):
    sec = re.search(r"\bstrings\s*:\s*(.*?)(?:\b(?:condition|meta)\s*:|\Z)",
                    body, flags=re.DOTALL)
    if not sec:
        return []
    out = []
    for m in re.finditer(r"^\s*(\$[A-Za-z_][A-Za-z0-9_]*)\s*=",
                         sec.group(1), flags=re.MULTILINE):
        out.append(m.group(1))
    return out


def _yara_condition_uses(condition, strings):
    used = {s: False for s in strings}
    if re.search(r"\bof\s+them\b", condition):
        for s in used: used[s] = True
        return used
    for m in re.finditer(r"\$([A-Za-z_][A-Za-z0-9_]*)\*", condition):
        prefix = "$" + m.group(1)
        for s in strings:
            if s.startswith(prefix):
                used[s] = True
    for s in strings:
        if re.search(r"(?<![A-Za-z0-9_])" + re.escape(s) + r"(?![A-Za-z0-9_*])", condition):
            used[s] = True
    return used


def validate_yara(path):
    errors, warnings = [], []
    raw = path.read_bytes()
    if b"\x00" in raw:
        errors.append("file contains NULL byte(s)")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        errors.append("not valid UTF-8: " + str(e))
        return errors, warnings

    no_line_cmt = re.sub(r"//[^\n]*", "", text)
    no_block_cmt = re.sub(r"/\*.*?\*/", "", no_line_cmt, flags=re.DOTALL)

    opens = no_block_cmt.count("{"); closes = no_block_cmt.count("}")
    if opens != closes:
        errors.append("unbalanced braces: open=" + str(opens) + " close=" + str(closes))

    rules = list(_yara_iter_rules(no_block_cmt))
    if not rules:
        errors.append("no 'rule NAME { ... }' blocks found")

    seen = set()
    for name, body in rules:
        if name in seen:
            errors.append("duplicate rule name: " + name)
        seen.add(name)

        cond_match = re.search(r"\bcondition\s*:\s*(.*)\Z", body, flags=re.DOTALL)
        if not cond_match:
            errors.append("rule '" + name + "' is missing a 'condition:' section")
            continue
        condition = cond_match.group(1)

        if not re.search(r"\bmeta\s*:", body):
            warnings.append("rule '" + name + "' has no 'meta:' block (recommended)")

        strings = _yara_collect_strings(body)
        if strings:
            usage = _yara_condition_uses(condition, strings)
            for s, used in usage.items():
                if not used:
                    errors.append("rule '" + name + "': unreferenced string " + s
                                  + " (declared but never used in condition)")
    return errors, warnings


# ---------------------------------------------------------------------------
# Suricata / Snort validator (line-level)
# ---------------------------------------------------------------------------
SURICATA_ACTIONS = {"alert","drop","reject","pass","log","activate","dynamic","sdrop","rejectsrc","rejectdst","rejectboth"}

def validate_suricata(path: Path):
    errors, warnings = [], []
    text = path.read_text(encoding="utf-8", errors="replace")
    # Strip inline comments and join multi-line rules ('\' continuation)
    joined = re.sub(r"\\\s*\n", " ", text)
    seen_sids = set()
    for lineno, line in enumerate(joined.splitlines(), start=1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        # First token must be an action
        first = s.split(None, 1)[0]
        if first not in SURICATA_ACTIONS:
            errors.append(f"line {lineno}: rule does not start with a valid action ({first})")
            continue
        # Rule must end with a semicolon-bracketed body: ( ... ;)
        if not re.search(r"\(.+;\s*\)\s*$", s):
            errors.append(f"line {lineno}: rule body must be enclosed in (...) and end with ;)")
            continue
        # sid present and unique
        m = re.search(r"\bsid\s*:\s*(\d+)\s*;", s)
        if not m:
            errors.append(f"line {lineno}: missing sid")
        else:
            sid = m.group(1)
            if sid in seen_sids:
                errors.append(f"line {lineno}: duplicate sid {sid}")
            seen_sids.add(sid)
        # msg present
        if not re.search(r'\bmsg\s*:\s*"', s):
            warnings.append(f"line {lineno}: missing msg (recommended)")
        # rev present
        if not re.search(r"\brev\s*:\s*\d+\s*;", s):
            warnings.append(f"line {lineno}: missing rev (recommended)")
    return errors, warnings

# ---------------------------------------------------------------------------
# KQL heuristic validator
# ---------------------------------------------------------------------------
KQL_KEYWORDS = {
    "let","where","summarize","join","kind","project","extend","union","order","by",
    "bin","ago","make_set","make_list","count","dcount","countif","sum","avg","min","max",
    "asc","desc","datetime","datetime_diff","now","todatetime","tostring","tolower","toupper",
    "has","has_any","has_all","contains","startswith","endswith","matches","regex","in","in~","!in",
    "between","not","and","or","true","false","print","range","series_decompose"
}

def _balanced(text: str, openc: str, closec: str):
    depth = 0
    in_str = False
    str_char = ""
    for c in text:
        if in_str:
            if c == str_char: in_str = False
            continue
        if c in ('"', "'"):
            in_str = True; str_char = c; continue
        if c == openc: depth += 1
        elif c == closec: depth -= 1
        if depth < 0: return False
    return depth == 0

def validate_kql(path: Path):
    errors, warnings = [], []
    text = path.read_text(encoding="utf-8", errors="replace")
    # Strip line comments
    code = re.sub(r"//[^\n]*", "", text)
    if "\x00" in text:
        errors.append("file contains NULL byte(s)")
    if not code.strip():
        errors.append("file appears to be empty (or only comments)")
        return errors, warnings
    # Header presence
    head = "\n".join(text.splitlines()[:15])
    if not re.search(r"//\s*Title\s*:", head, re.IGNORECASE):
        warnings.append("missing '// Title:' header comment")
    if not re.search(r"//\s*MITRE\s*:", head, re.IGNORECASE):
        warnings.append("missing '// MITRE:' header comment")
    # Brackets
    for o, c in [("(",")"), ("[","]"), ("{","}")]:
        if not _balanced(code, o, c):
            errors.append(f"unbalanced '{o}{c}' brackets")
    # Must have at least one known keyword
    tokens = set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", code.lower()))
    if not tokens & KQL_KEYWORDS:
        warnings.append("no recognized KQL keyword found — query may be malformed")
    # Heuristic: avoid trailing pipe or unfinished line
    last_nonblank = next((l for l in reversed(code.strip().splitlines()) if l.strip()), "")
    if last_nonblank.rstrip().endswith("|"):
        errors.append("query ends with a trailing pipe '|' — likely truncated")
    # Hint for unsubstituted placeholders
    placeholders = re.findall(r"<[^>]+>", code)
    suspicious = [p for p in placeholders if "add_" in p or "TODO" in p.upper() or "FIXME" in p.upper()]
    for s in suspicious:
        warnings.append(f"unresolved placeholder: {s}")
    return errors, warnings

# ---------------------------------------------------------------------------
# SPL heuristic validator
# ---------------------------------------------------------------------------
SPL_COMMANDS = {
    "search","stats","eval","where","table","timechart","chart","top","rare","head","tail",
    "sort","fields","rename","mvexpand","spath","rex","extract","join","append","appendcols",
    "lookup","tstats","metasearch","datamodel","summarize","streamstats","makeresults","fillnull",
    "untable","xyseries","transaction","cluster","kmeans","dedup","sendalert","outputlookup"
}

def validate_spl(path: Path):
    errors, warnings = [], []
    text = path.read_text(encoding="utf-8", errors="replace")
    if "\x00" in text:
        errors.append("file contains NULL byte(s)")
    # Strip ;-style line comments
    code = re.sub(r";[^\n]*", "", text)
    if not code.strip():
        errors.append("file appears to be empty (or only comments)")
        return errors, warnings
    # Header presence
    head = "\n".join(text.splitlines()[:15])
    if not re.search(r";\s*Title\s*:", head, re.IGNORECASE):
        warnings.append("missing '; Title:' header comment")
    # Bracket balance
    for o, c in [("(",")"), ("[","]")]:
        if not _balanced(code, o, c):
            errors.append(f"unbalanced '{o}{c}' brackets")
    # Should reference at least one index= or sourcetype= or `macro`
    if not re.search(r"\b(index|source|sourcetype|search\s)\s*=", code, re.IGNORECASE) \
       and not re.search(r"`[A-Za-z0-9_]+`", code):
        warnings.append("no 'index=', 'sourcetype=' or `macro` reference found")
    # Should have at least one piped command
    pipes = re.split(r"\|", code)
    found_cmd = False
    for chunk in pipes[1:]:
        first = re.match(r"\s*([a-zA-Z_]+)", chunk)
        if first and first.group(1).lower() in SPL_COMMANDS:
            found_cmd = True; break
    if not found_cmd and "|" in code:
        warnings.append("no recognized SPL command after '|' — query may be unusual")
    # Trailing pipe
    last_nonblank = next((l for l in reversed(code.strip().splitlines()) if l.strip()), "")
    if last_nonblank.rstrip().endswith("|"):
        errors.append("query ends with a trailing pipe '|' — likely truncated")
    return errors, warnings

# ---------------------------------------------------------------------------
# CSV (iocs.csv) validator
# ---------------------------------------------------------------------------
IOCS_HEADER = ["type","value","context","confidence","source"]

def validate_csv(path: Path):
    errors, warnings = [], []
    try:
        with path.open(encoding="utf-8", newline="") as f:
            rows = list(csv.reader(f))
    except Exception as e:
        return [f"CSV parse error: {e}"], []
    if not rows:
        return ["empty CSV"], []
    if rows[0][:5] != IOCS_HEADER:
        errors.append(f"header mismatch — expected {IOCS_HEADER}, got {rows[0][:5]}")
    for i, row in enumerate(rows[1:], start=2):
        if not row: continue
        if len(row) < 5 and row[0].strip() not in ("note",""):
            errors.append(f"line {i}: short row (< 5 cols) and not a 'note' line")
    return errors, warnings

# ---------------------------------------------------------------------------
# Generic YAML validator (workflows + everything not Sigma)
# ---------------------------------------------------------------------------
def validate_yaml(path: Path):
    errors, warnings = [], []
    raw = path.read_bytes()
    if b"\x00" in raw:
        errors.append("file contains NULL byte(s)")
    try:
        yaml.safe_load(raw)
    except yaml.YAMLError as e:
        errors.append(f"YAML parse error: {e}")
    return errors, warnings

# ---------------------------------------------------------------------------
# Bash script validator (uses bash -n if available)
# ---------------------------------------------------------------------------
def validate_bash(path: Path):
    errors, warnings = [], []
    if shutil.which("bash") is None:
        warnings.append("'bash' not in PATH — skipped syntax check")
        return errors, warnings
    res = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
    if res.returncode != 0:
        errors.append(f"bash -n failed: {res.stderr.strip()}")
    return errors, warnings

# ---------------------------------------------------------------------------
# Markdown link sanity (relative links must exist; http(s) syntax check)
# ---------------------------------------------------------------------------
LINK_RE = re.compile(r"\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")

def validate_markdown(path: Path):
    errors, warnings = [], []
    text = path.read_text(encoding="utf-8", errors="replace")
    for m in LINK_RE.finditer(text):
        url = m.group(1)
        if url.startswith(("http://","https://","mailto:","computer://","#")):
            continue
        # Relative link — must resolve from the file's directory
        target = (path.parent / url).resolve()
        # Strip optional anchor
        target_path = str(target).split("#",1)[0]
        if not Path(target_path).exists():
            warnings.append(f"broken relative link: {url}")
    return errors, warnings

# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------
def classify(path: Path):
    p = str(path).replace("\\","/")
    if "/sigma/" in p and path.suffix in (".yml",".yaml"): return "sigma"
    if "/yara/" in p and path.suffix in (".yar",".yara"):  return "yara"
    if "/suricata/" in p and path.suffix == ".rules":      return "suricata"
    if "/kql/" in p and path.suffix == ".kql":             return "kql"
    if "/spl/" in p and path.suffix == ".spl":             return "spl"
    if path.name.lower() == "iocs.csv":                    return "csv"
    if path.suffix in (".yml",".yaml"):                    return "yaml"
    if path.suffix == ".sh":                               return "bash"
    if path.suffix == ".md":                               return "markdown"
    return None

VALIDATORS = {
    "sigma": validate_sigma,
    "yara": validate_yara,
    "suricata": validate_suricata,
    "kql": validate_kql,
    "spl": validate_spl,
    "csv": validate_csv,
    "yaml": validate_yaml,
    "bash": validate_bash,
    "markdown": validate_markdown,
}

def collect_files(args):
    if args:
        for a in args:
            p = Path(a).resolve()
            if p.is_file(): yield p
        return
    for pattern in (
        "days/**/*.yml","days/**/*.yaml","days/**/*.yar","days/**/*.yara",
        "days/**/*.rules","days/**/*.kql","days/**/*.spl","days/**/iocs.csv",
        ".github/workflows/*.yml",".github/workflows/*.yaml",
        "tools/*.sh",
        "**/*.md",
    ):
        for p in ROOT.glob(pattern):
            if p.is_file():
                yield p.resolve()

def main(argv):
    args = argv[1:]
    files = sorted(set(collect_files(args)))
    if not files:
        print("no files matched"); return 1

    counts = {"ok":0,"warn":0,"FAIL":0}
    by_kind = {}
    total_err = 0
    for f in files:
        kind = classify(f)
        if kind is None: continue
        by_kind.setdefault(kind, 0); by_kind[kind] += 1
        rel = f.relative_to(ROOT) if str(ROOT) in str(f) else f
        validator = VALIDATORS[kind]
        try:
            errors, warnings = validator(f)
        except Exception as e:
            errors, warnings = [f"validator crashed: {e}"], []
        tag = "[ok]   "
        if errors:
            tag = "[FAIL] "; counts["FAIL"] += 1; total_err += len(errors)
        elif warnings:
            tag = "[warn] "; counts["warn"] += 1
        else:
            counts["ok"] += 1
        if errors or warnings:
            print(f"{tag} ({kind}) {rel}")
            for e in errors:    print(f"   ERROR: {e}")
            for w in warnings:  print(f"   warn:  {w}")
        else:
            print(f"{tag} ({kind}) {rel}")
    print()
    print(f"=== summary by kind: {dict(sorted(by_kind.items()))}")
    print(f"=== ok={counts['ok']}  warn={counts['warn']}  FAIL={counts['FAIL']}  errors={total_err}")
    return 0 if counts["FAIL"] == 0 else 2

if __name__ == "__main__":
    sys.exit(main(sys.argv))
