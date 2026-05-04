#!/usr/bin/env bash
# tools/lint_all.sh — full multi-format pre-commit linter for detection-diary.
#
# Always runs the offline validator (tools/validate_all.py).
# Then, if the corresponding tool is on PATH, also runs:
#   - sigma         (sigma-cli)        — Sigma deep validation + Splunk conversion
#   - yara          (YARA binary)      — YARA syntax compile
#   - suricata      (Suricata binary)  — rule load test
#   - actionlint    (actionlint)       — GitHub Actions workflow linter
#   - shellcheck    (shellcheck)       — bash linter
#   - markdownlint  (markdownlint-cli) — Markdown style
#
# Exit code 0 if all gates pass, 1 otherwise.
#
# Recommended local install:
#   pipx install sigma-cli && pipx inject sigma-cli pysigma-backend-splunk \
#                                          pysigma-backend-microsoft365defender \
#                                          pysigma-pipeline-sysmon
#   pipx install yamllint
#   sudo apt install -y yara suricata shellcheck
#   bash <(curl -sSfL https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash) \
#     && sudo install -m 0755 actionlint /usr/local/bin/actionlint
#   npm install -g markdownlint-cli

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}" || exit 1

GLOBAL_FAIL=0

section() {
  echo
  echo "============================================================"
  echo "  $*"
  echo "============================================================"
}

shopt -s globstar nullglob

SIGMA_RULES=( days/**/sigma/*.yml days/**/sigma/*.yaml )
YARA_RULES=(  days/**/yara/*.yar  days/**/yara/*.yara )
SURI_RULES=(  days/**/suricata/*.rules )
WF_FILES=(    .github/workflows/*.yml .github/workflows/*.yaml )
SH_FILES=(    tools/*.sh )
MD_FILES=(    README.md INDEX.md CHANGELOG.md days/**/*.md )

# 1. Always-on offline validator
section "1/7  validate_all.py (offline, all formats)"
if command -v python3 >/dev/null 2>&1; then
  python3 tools/validate_all.py || GLOBAL_FAIL=1
else
  python tools/validate_all.py || GLOBAL_FAIL=1
fi

# 2. Sigma deep validation if sigma-cli available
section "2/7  sigma-cli (Sigma structural + Splunk conversion)"
declare -a SIGMA_CMD=()
if command -v sigma >/dev/null 2>&1; then
  SIGMA_CMD=( "$(command -v sigma)" )
elif python3 -c "import sigma.cli" >/dev/null 2>&1; then
  SIGMA_CMD=( python3 -m sigma.cli )
elif command -v python >/dev/null 2>&1 && python -c "import sigma.cli" >/dev/null 2>&1; then
  SIGMA_CMD=( python -m sigma.cli )
fi
if [ "${#SIGMA_CMD[@]}" -gt 0 ] && [ "${#SIGMA_RULES[@]}" -gt 0 ]; then
  "${SIGMA_CMD[@]}" check "${SIGMA_RULES[@]}" || GLOBAL_FAIL=1
  for r in "${SIGMA_RULES[@]}"; do
    if ! "${SIGMA_CMD[@]}" convert -t splunk -p sysmon "$r" >/dev/null; then
      echo "[FAIL] sigma convert -t splunk: $r"; GLOBAL_FAIL=1
    fi
  done
  echo "[ok] sigma-cli passed."
else
  echo "[skip] sigma-cli not installed."
  echo "       pipx install sigma-cli && pipx inject sigma-cli pysigma-backend-splunk pysigma-pipeline-sysmon"
fi

# 3. YARA compile if binary present
section "3/7  yara (compile check)"
if command -v yara >/dev/null 2>&1 && [ "${#YARA_RULES[@]}" -gt 0 ]; then
  for r in "${YARA_RULES[@]}"; do
    if ! yara -w "$r" /dev/null >/dev/null 2>&1; then
      echo "[FAIL] yara compile: $r"
      yara -w "$r" /dev/null
      GLOBAL_FAIL=1
    else
      echo "[ok]   $r"
    fi
  done
else
  echo "[skip] yara binary not installed.  apt-get install yara"
fi

# 4. Suricata rule load test if binary present
section "4/7  suricata (rule load)"
if command -v suricata >/dev/null 2>&1 && [ "${#SURI_RULES[@]}" -gt 0 ]; then
  SURI_TMP="$(mktemp -d -t suri.XXXXXX)"
  trap 'rm -rf "${SURI_TMP}"' EXIT
  # Discover every $VAR_NET / $VAR referenced in any rule and generate a
  # minimal yaml so the test does not fail on missing user-defined vars.
  declare -a EXTRA_VARS=()
  while IFS= read -r v; do
    EXTRA_VARS+=( "$v" )
  done < <(grep -hoE '\$[A-Z][A-Z0-9_]*' "${SURI_RULES[@]}" 2>/dev/null \
           | sort -u \
           | grep -vE '^\$(HOME_NET|EXTERNAL_NET|HTTP_PORTS|SHELLCODE_PORTS|SSH_PORTS|FTP_PORTS|SMTP_PORTS|TELNET_PORTS|FILE_DATA_PORTS|MODBUS_PORTS|DNP3_PORTS|ENIP_PORTS|HTTP_SERVERS|SQL_SERVERS|SMTP_SERVERS|DNS_SERVERS)$' \
           || true)
  {
    echo "%YAML 1.1"
    echo "---"
    echo "vars:"
    echo "  address-groups:"
    echo "    HOME_NET: \"[any]\""
    echo "    EXTERNAL_NET: \"any\""
    for v in "${EXTRA_VARS[@]}"; do
      name="${v#\$}"
      echo "    ${name}: \"[any]\""
    done
    echo "  port-groups:"
    echo "    HTTP_PORTS: \"any\""
    echo "    SSH_PORTS: \"any\""
    echo "default-rule-path: ${SURI_TMP}"
    echo "default-log-dir: ${SURI_TMP}"
    echo "logging: { default-log-level: error, outputs: [{ console: { enabled: yes } }] }"
    echo "outputs: []"
    echo "app-layer:"
    echo "  protocols:"
    echo "    http: { enabled: yes }"
    echo "    ssh:  { enabled: yes }"
  } > "${SURI_TMP}/suricata.yaml"

  for r in "${SURI_RULES[@]}"; do
    if suricata -T -c "${SURI_TMP}/suricata.yaml" -S "$r" -l "${SURI_TMP}" >/dev/null 2>&1; then
      echo "[ok]   $r"
    else
      echo "[FAIL] suricata -T: $r"
      suricata -T -c "${SURI_TMP}/suricata.yaml" -S "$r" -l "${SURI_TMP}" 2>&1 | tail -20
      GLOBAL_FAIL=1
    fi
  done
else
  echo "[skip] suricata binary not installed.  apt-get install suricata"
fi

# 5. actionlint for GitHub workflows
section "5/7  actionlint (GitHub workflows)"
if command -v actionlint >/dev/null 2>&1 && [ "${#WF_FILES[@]}" -gt 0 ]; then
  actionlint "${WF_FILES[@]}" || GLOBAL_FAIL=1
else
  echo "[skip] actionlint not installed."
  echo "       https://github.com/rhysd/actionlint"
fi

# 6. shellcheck for bash scripts
section "6/7  shellcheck (bash)"
if command -v shellcheck >/dev/null 2>&1 && [ "${#SH_FILES[@]}" -gt 0 ]; then
  shellcheck -s bash -S warning "${SH_FILES[@]}" || GLOBAL_FAIL=1
else
  echo "[skip] shellcheck not installed.  apt-get install shellcheck"
fi

# 7. markdownlint
section "7/7  markdownlint"
if command -v markdownlint >/dev/null 2>&1 && [ "${#MD_FILES[@]}" -gt 0 ]; then
  markdownlint -d "MD013 MD033 MD041 MD034" "${MD_FILES[@]}" || GLOBAL_FAIL=1
else
  echo "[skip] markdownlint not installed.  npm i -g markdownlint-cli"
fi

echo
echo "============================================================"
if [ "${GLOBAL_FAIL}" -eq 0 ]; then
  echo "  ALL GATES PASSED"
  exit 0
else
  echo "  SOME GATES FAILED — see logs above"
  exit 1
fi
