#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCANNER="${ROOT_DIR}/tools/claw-vet.sh"

run_case() {
  local expected="$1"
  local fixture="$2"
  local output
  local rc

  set +e
  output="$(bash "$SCANNER" "${ROOT_DIR}/${fixture}" 2>&1)"
  rc="$?"
  set -e

  if [[ "$rc" -ne "$expected" ]]; then
    printf 'Expected %s for %s, got %s\n' "$expected" "$fixture" "$rc"
    printf '%s\n' "$output"
    exit 1
  fi
}

bash -n "$SCANNER"
run_case 0 tests/clawvet/good-skill.md
run_case 1 tests/clawvet/subtle-skill.md
run_case 2 tests/clawvet/malicious-skill.md

printf 'ClawVet fixture tests passed\n'
