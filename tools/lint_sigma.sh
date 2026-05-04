#!/usr/bin/env bash
# tools/lint_sigma.sh — local pre-commit Sigma lint
#
# Modes:
#   ./tools/lint_sigma.sh                # lint every rule under days/**/sigma/
#   ./tools/lint_sigma.sh path/to/rule.yml ...   # lint specific files
#   ./tools/lint_sigma.sh --offline      # skip sigma-cli, run only the offline structural check
#
# Requires for the FULL run (sigma check + sigma convert):
#   pipx install sigma-cli && pipx inject sigma-cli \
#       pysigma-backend-splunk pysigma-backend-microsoft365defender pysigma-pipeline-sysmon
#   pipx install yamllint
#
# If sigma-cli is not on PATH, the script automatically falls back to
# tools/sigma_check.py (offline structural check, only needs PyYAML).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}" || exit 1

OFFLINE=0
RULES=()
for arg in "$@"; do
  case "$arg" in
    --offline) OFFLINE=1 ;;
    -h|--help)
      sed -n '1,20p' "$0"
      exit 0
      ;;
    *) RULES+=( "$arg" ) ;;
  esac
done

if [ "${#RULES[@]}" -eq 0 ]; then
  shopt -s globstar nullglob
  RULES=( days/**/sigma/*.yml days/**/sigma/*.yaml )
fi

if [ "${#RULES[@]}" -eq 0 ]; then
  echo "No Sigma rules found under days/**/sigma/."
  exit 0
fi

echo "==> ${#RULES[@]} rule(s) to validate"

# 1. Resolve sigma-cli (or fall back to offline) — store as array
declare -a SIGMA_CMD=()
if command -v sigma >/dev/null 2>&1; then
  SIGMA_CMD=( "$(command -v sigma)" )
elif python3 -c "import sigma.cli" >/dev/null 2>&1; then
  SIGMA_CMD=( python3 -m sigma.cli )
elif command -v python >/dev/null 2>&1 && python -c "import sigma.cli" >/dev/null 2>&1; then
  SIGMA_CMD=( python -m sigma.cli )
fi

if [ "${#SIGMA_CMD[@]}" -eq 0 ] || [ "${OFFLINE}" -eq 1 ]; then
  if [ "${OFFLINE}" -eq 1 ]; then
    echo "==> --offline requested. Skipping sigma-cli."
  else
    {
      echo "==> sigma-cli not found on PATH."
      echo ""
      echo "To install (recommended):"
      echo "    pipx install sigma-cli && pipx inject sigma-cli \\"
      echo "        pysigma-backend-splunk pysigma-backend-microsoft365defender \\"
      echo "        pysigma-pipeline-sysmon"
      echo ""
      echo "Then re-run: ./tools/lint_sigma.sh"
      echo ""
      echo "Falling back to the offline structural validator (no extra deps required)."
    } >&2
  fi
  echo
  echo "==> running tools/sigma_check.py (offline)"
  if command -v python3 >/dev/null 2>&1; then
    PY=python3
  else
    PY=python
  fi
  "$PY" "${SCRIPT_DIR}/sigma_check.py" "${RULES[@]}"
  exit $?
fi

echo "==> using ${SIGMA_CMD[*]}"

# 2. yamllint (style — never fails the build)
if command -v yamllint >/dev/null 2>&1; then
  echo "==> yamllint"
  yamllint -d "{extends: relaxed, rules: {line-length: {max: 200, level: warning}, truthy: {check-keys: false}}}" "${RULES[@]}" || true
else
  echo "==> yamllint not installed (skipping style check)"
fi

# 3. sigma check (structural)
echo "==> sigma check"
"${SIGMA_CMD[@]}" check "${RULES[@]}"

# 4. sigma convert smoke tests
fail=0
for r in "${RULES[@]}"; do
  echo "==> $r -> splunk (sysmon pipeline)"
  if ! "${SIGMA_CMD[@]}" convert -t splunk -p sysmon "$r" >/dev/null; then
    echo "    [FAIL] splunk conversion"
    fail=1
  fi

  echo "==> $r -> microsoft365defender (soft)"
  if ! "${SIGMA_CMD[@]}" convert -t microsoft365defender "$r" >/dev/null 2>&1; then
    echo "    [warn] not convertible to microsoft365defender (ok for non-Defender logsources)"
  fi
done

if [ "$fail" -eq 0 ]; then
  echo "==> All rules passed structural + Splunk conversion checks."
else
  echo "==> Some rules failed Splunk conversion. See output above."
  exit 1
fi
