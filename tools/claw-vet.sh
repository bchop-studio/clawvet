#!/usr/bin/env bash
# =============================================================================
# claw-vet.sh — ClawVet: SKILL.md Security Scanner
# =============================================================================
# Usage:
#   ./tools/claw-vet.sh <path-to-skill.md>
#   ./tools/claw-vet.sh <url>
#
# Exit codes:
#   0 = PASS  (no issues found)
#   1 = WARN  (suspicious but not definitively malicious)
#   2 = FAIL  (critical security issues found)
# =============================================================================

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Counters ──────────────────────────────────────────────────────────────────
CRITICAL_COUNT=0
WARN_COUNT=0
INFO_COUNT=0

# ── Helpers ───────────────────────────────────────────────────────────────────
sanitize_text() {
  LC_ALL=C tr -d '\000-\037\177'
}

log_finding() {
  local severity="$1"
  local line_num="$2"
  local message
  message="$(printf '%s' "$3" | sanitize_text)"

  case "$severity" in
    CRITICAL)
      printf '  %b[CRITICAL]%b line %b%s%b: %s\n' "$RED" "$RESET" "$BOLD" "$line_num" "$RESET" "$message"
      ;;
    WARN)
      printf '  %b[WARN]%b     line %b%s%b: %s\n' "$YELLOW" "$RESET" "$BOLD" "$line_num" "$RESET" "$message"
      ;;
    INFO)
      printf '  %b[INFO]%b     line %b%s%b: %s\n' "$CYAN" "$RESET" "$BOLD" "$line_num" "$RESET" "$message"
      ;;
  esac
}

separator() {
  echo -e "${BOLD}────────────────────────────────────────────────────────${RESET}"
}

# ── Usage check ───────────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <path-to-skill.md|url>"
  exit 2
fi

INPUT="$1"
DISPLAY_INPUT="$(printf '%s' "$INPUT" | sanitize_text)"
TMPFILE=""

# ── Fetch or read input ───────────────────────────────────────────────────────
if [[ "$INPUT" =~ ^[[:alpha:]][[:alnum:]+.-]*:// && ! "$INPUT" =~ ^https:// ]]; then
  printf '%bERROR: Only HTTPS URLs are accepted: %s%b\n' "$RED" "$DISPLAY_INPUT" "$RESET"
  exit 2
fi

if [[ "$INPUT" =~ ^https:// ]]; then
  TMPFILE=$(mktemp /tmp/clawvet-XXXXXX.md)
  printf '%bFetching URL: %s%b\n' "$CYAN" "$DISPLAY_INPUT" "$RESET"
  if ! curl -fsSL --proto '=https' --proto-redir '=https' --max-time 15 "$INPUT" -o "$TMPFILE" 2>/dev/null; then
    printf '%bERROR: Failed to fetch URL: %s%b\n' "$RED" "$DISPLAY_INPUT" "$RESET"
    rm -f "$TMPFILE"
    exit 2
  fi
  TARGET="$TMPFILE"
else
  if [[ ! -f "$INPUT" ]]; then
    printf '%bERROR: File not found: %s%b\n' "$RED" "$DISPLAY_INPUT" "$RESET"
    exit 2
  fi
  TARGET="$INPUT"
fi

# ── Header ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║              🔍 ClawVet — SKILL.md Scanner           ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${RESET}"
printf '  Target: %b%s%b\n' "$BOLD" "$DISPLAY_INPUT" "$RESET"
echo ""

# =============================================================================
# CATEGORY A: Hidden / Invisible Unicode
# =============================================================================
separator
echo -e "${BOLD}[A] Hidden/Invisible Unicode Characters${RESET}"

# Patterns: zero-width space U+200B through U+200F,
#           line/paragraph separators U+2028–U+202F,
#           BOM U+FEFF
# We use Python for reliable Unicode scanning.
if command -v python3 &>/dev/null; then
  python3 - "$TARGET" <<'PYEOF'
import sys, re

filepath = sys.argv[1]
HIDDEN_RANGES = [
    (0x200B, 0x200F),   # zero-width space, non-joiners, joiners, LTR/RTL marks
    (0x2028, 0x202F),   # line sep, paragraph sep, narrow no-break, RTL overrides
    (0xFEFF, 0xFEFF),   # BOM / zero-width no-break space
    (0x202A, 0x202E),   # LTR/RTL embed/override/pop
    (0x2066, 0x2069),   # Isolates
]

def is_hidden(cp):
    for lo, hi in HIDDEN_RANGES:
        if lo <= cp <= hi:
            return True
    return False

SEVERITY_MAP = {
    0x202E: "CRITICAL",  # RTL Override — very suspicious
    0x202D: "CRITICAL",  # LTR Override
    0xFEFF: "WARN",      # BOM (can be legitimate at file start)
}

findings = []
with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
    for lineno, line in enumerate(f, 1):
        for pos, ch in enumerate(line):
            cp = ord(ch)
            if is_hidden(cp):
                sev = SEVERITY_MAP.get(cp, "WARN")
                findings.append((sev, lineno, f"Hidden Unicode U+{cp:04X} at col {pos+1} ({repr(ch)})"))

for sev, lno, msg in findings:
    print(f"FINDING:{sev}:{lno}:{msg}")

if not findings:
    print("CLEAN:A")
PYEOF
else
  echo "FINDING:WARN:0:Python 3 unavailable; hidden Unicode scan skipped"
fi | while IFS=: read -r tag sev lnum msg; do
  if [[ "$tag" == "FINDING" ]]; then
    log_finding "$sev" "$lnum" "$msg"
  elif [[ "$tag" == "CLEAN" ]]; then
    echo -e "  ${GREEN}No hidden Unicode found${RESET}"
  fi
done

# Re-run to capture counts (subshell above doesn't propagate)
if command -v python3 &>/dev/null; then
  UNICODE_FINDINGS=$(python3 - "$TARGET" <<'PYEOF2'
import sys
filepath = sys.argv[1]
HIDDEN_RANGES = [
    (0x200B, 0x200F), (0x2028, 0x202F), (0xFEFF, 0xFEFF),
    (0x202A, 0x202E), (0x2066, 0x2069),
]
def is_hidden(cp):
    for lo, hi in HIDDEN_RANGES:
        if lo <= cp <= hi:
            return True
    return False
SEVERITY_MAP = {0x202E: "CRITICAL", 0x202D: "CRITICAL", 0xFEFF: "WARN"}
count_c=0; count_w=0
with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
    for lineno, line in enumerate(f, 1):
        for pos, ch in enumerate(line):
            cp = ord(ch)
            if is_hidden(cp):
                sev = SEVERITY_MAP.get(cp, "WARN")
                if sev == "CRITICAL": count_c += 1
                else: count_w += 1
print(f"{count_c}:{count_w}")
PYEOF2
)
  UC_CRIT=$(printf '%s\n' "$UNICODE_FINDINGS" | cut -d: -f1)
  UC_WARN=$(printf '%s\n' "$UNICODE_FINDINGS" | cut -d: -f2)
  CRITICAL_COUNT=$(( CRITICAL_COUNT + UC_CRIT ))
  WARN_COUNT=$(( WARN_COUNT + UC_WARN ))
else
  WARN_COUNT=$(( WARN_COUNT + 1 ))
fi

# =============================================================================
# CATEGORY B: Prompt Injection Phrases
# =============================================================================
separator
echo -e "${BOLD}[B] Prompt Injection Phrases${RESET}"

INJECT_PATTERNS=(
  "ignore previous instructions:CRITICAL"
  "ignore all previous:CRITICAL"
  "disregard (all |your )?(previous |prior )?(instructions|rules|guidelines):CRITICAL"
  "you are now:WARN"
  "act as (a |an )?[a-z]:WARN"
  "new role:WARN"
  "system prompt override:CRITICAL"
  "override (your |all )?(previous |prior )?(instructions|rules|training):CRITICAL"
  "forget (your |all |previous )?(instructions|rules|guidelines|training):CRITICAL"
  "jailbreak:WARN"
  "do anything now:WARN"
  "DAN mode:CRITICAL"
  "developer mode:WARN"
)

B_COUNT=0
while IFS= read -r line_raw; do
  lineno="${line_raw%%:*}"
  content="${line_raw#*:}"
  lower_content=$(printf '%s\n' "$content" | tr '[:upper:]' '[:lower:]')

  for pat_sev in "${INJECT_PATTERNS[@]}"; do
    pat="${pat_sev%%:*}"
    sev="${pat_sev##*:}"
    if printf '%s\n' "$lower_content" | grep -qiE "$pat" 2>/dev/null; then
      matched=$(printf '%s\n' "$lower_content" | grep -oiE "$pat" | head -1)
      log_finding "$sev" "$lineno" "Prompt injection phrase: \"${matched}\""
      if [[ "$sev" == "CRITICAL" ]]; then
        (( CRITICAL_COUNT++ )) || true
      else
        (( WARN_COUNT++ )) || true
      fi
      (( B_COUNT++ )) || true
      break
    fi
  done
done < <(grep -n "" "$TARGET" 2>/dev/null || true)

[[ $B_COUNT -eq 0 ]] && echo -e "  ${GREEN}No prompt injection phrases found${RESET}"

# =============================================================================
# CATEGORY C: Dangerous Shell Patterns
# =============================================================================
separator
echo -e "${BOLD}[C] Dangerous Shell Patterns${RESET}"

SHELL_PATTERNS=(
  'curl[[:space:]]+.*[|][[:space:]]*(bash|sh):CRITICAL'
  'wget[[:space:]]+.*[|][[:space:]]*(bash|sh):CRITICAL'
  'bash[[:space:]]+-c[[:space:]]:CRITICAL'
  'sh[[:space:]]+-c[[:space:]]:CRITICAL'
  '/dev/tcp/:CRITICAL'
  'eval[[:space:]]*\(:CRITICAL'
  'eval[[:space:]]+\$:CRITICAL'
  'npx[[:space:]]+-y[[:space:]]:WARN'
  'python[23]?[[:space:]]+-c[[:space:]]:WARN'
  'exec[[:space:]]*\([[:space:]]*['\''"]:WARN'
  'base64[[:space:]]+-d.*[|]:WARN'
  '\$\(curl:CRITICAL'
  '\$\(wget:CRITICAL'
)

C_COUNT=0
while IFS= read -r line_raw; do
  lineno="${line_raw%%:*}"
  content="${line_raw#*:}"

  for pat_sev in "${SHELL_PATTERNS[@]}"; do
    pat="${pat_sev%:*}"
    sev="${pat_sev##*:}"
    if printf '%s\n' "$content" | grep -qE "$pat" 2>/dev/null; then
      snippet=$(printf '%s\n' "$content" | cut -c1-80)
      log_finding "$sev" "$lineno" "Dangerous shell pattern: $snippet"
      if [[ "$sev" == "CRITICAL" ]]; then
        (( CRITICAL_COUNT++ )) || true
      else
        (( WARN_COUNT++ )) || true
      fi
      (( C_COUNT++ )) || true
      break
    fi
  done
done < <(grep -n "" "$TARGET" 2>/dev/null || true)

[[ $C_COUNT -eq 0 ]] && echo -e "  ${GREEN}No dangerous shell patterns found${RESET}"

# =============================================================================
# CATEGORY D: HTML Comment Instructions
# =============================================================================
separator
echo -e "${BOLD}[D] HTML Comment Instructions${RESET}"

COMMENT_INJECT_PATTERNS=(
  "ignore"
  "override"
  "disregard"
  "you are"
  "system prompt"
  "new role"
  "forget"
  "instruction"
  "do not reveal"
  "do not tell"
  "hidden"
  "secret"
)

D_COUNT=0
# Extract HTML comments with their line numbers (handles multi-line poorly but catches single-line)
while IFS= read -r line_raw; do
  lineno="${line_raw%%:*}"
  content="${line_raw#*:}"

  # Check if line contains an HTML comment
  if printf '%s\n' "$content" | grep -qE '<!--.*-->' 2>/dev/null; then
    comment_body=$(printf '%s\n' "$content" | sed -E 's/.*<!--(.*)-->.*/\1/')
    lower_body=$(printf '%s\n' "$comment_body" | tr '[:upper:]' '[:lower:]')
    for kw in "${COMMENT_INJECT_PATTERNS[@]}"; do
      if printf '%s\n' "$lower_body" | grep -q "$kw"; then
        log_finding "WARN" "$lineno" "HTML comment contains instruction keyword: \"${kw}\" → $(printf '%s\n' "$comment_body" | cut -c1-60)"
        (( WARN_COUNT++ )) || true
        (( D_COUNT++ )) || true
        break
      fi
    done
  elif printf '%s\n' "$content" | grep -qE '<!--' 2>/dev/null; then
    # Opening comment without close — flag as INFO
    log_finding "INFO" "$lineno" "Unclosed HTML comment start (may span multiple lines)"
    (( INFO_COUNT++ )) || true
    (( D_COUNT++ )) || true
  fi
done < <(grep -n "" "$TARGET" 2>/dev/null || true)

[[ $D_COUNT -eq 0 ]] && echo -e "  ${GREEN}No suspicious HTML comments found${RESET}"

# =============================================================================
# VERDICT
# =============================================================================
separator
echo -e "${BOLD}Summary:${RESET}"
echo -e "  Critical: ${RED}${CRITICAL_COUNT}${RESET}  |  Warnings: ${YELLOW}${WARN_COUNT}${RESET}  |  Info: ${CYAN}${INFO_COUNT}${RESET}"
echo ""

if [[ $CRITICAL_COUNT -gt 0 ]]; then
  echo -e "${BOLD}Verdict: ${RED}⛔ FAIL${RESET} — Critical issues detected. Do NOT load this SKILL.md."
  EXITCODE=2
elif [[ $WARN_COUNT -gt 0 ]]; then
  echo -e "${BOLD}Verdict: ${YELLOW}⚠️  WARN${RESET} — Suspicious content found. Review carefully before loading."
  EXITCODE=1
else
  echo -e "${BOLD}Verdict: ${GREEN}✅ PASS${RESET} — No configured patterns detected. Review before loading."
  EXITCODE=0
fi
echo ""

# Cleanup temp file if we fetched a URL
[[ -n "$TMPFILE" ]] && rm -f "$TMPFILE"

exit $EXITCODE
