# ClawVet Guide

ClawVet is a local Bash scanner for Markdown-based AI agent instruction files. It was built around OpenClaw's `SKILL.md` format, but the scanner accepts any regular file containing text.

It checks the file. It does not install it, load it into an agent, or execute commands found inside it.

## Run it

```bash
# Local file
bash tools/claw-vet.sh path/to/SKILL.md

# Remote raw file, HTTPS only
bash tools/claw-vet.sh https://raw.githubusercontent.com/user/repo/main/SKILL.md
```

### Requirements

The full scan needs:

- Bash
- Python 3
- `grep`, `sed`, `tr`, `cut`, and `mktemp`
- `curl` for remote URLs

ClawVet warns when Python 3 is missing because it cannot complete the hidden-Unicode check. It never reports a clean pass for a scan that skipped that check.

## Results and exit codes

| Result | Code | Meaning |
| --- | ---: | --- |
| `PASS` | `0` | No configured pattern matched. Manual review is still required. |
| `WARN` | `1` | A suspicious pattern matched, or a check could not run. |
| `FAIL` | `2` | A critical pattern matched, the input was invalid, or a remote fetch failed. |

A `PASS` result is not a safety guarantee. ClawVet is one review layer.

## Detection categories

### Hidden and invisible Unicode

The Python check reports characters that can be hard to see in rendered text:

- U+200B through U+200F, including zero-width characters and direction marks
- U+2028 through U+202F, including line separators and bidirectional controls
- U+2066 through U+2069, the directional isolate controls
- U+FEFF, the byte-order mark or zero-width no-break space

U+202D and U+202E direction overrides are critical. Other configured characters are warnings.

### Prompt-injection phrases

The scanner looks for common instruction-override shapes, including:

- requests to ignore, disregard, forget, or override earlier instructions
- role reassignment such as `you are now` or `new role`
- jailbreak, DAN, and developer-mode phrases
- explicit system-prompt override language

These checks are context-blind. A security article quoting an attack phrase can trigger the same finding as an actual malicious instruction.

### Dangerous shell patterns

Critical patterns include:

- remote content piped into `bash` or `sh`
- `bash -c` and `sh -c`
- `/dev/tcp/` reverse-shell paths
- command substitution around `curl` or `wget`
- selected forms of `eval`

Warning patterns include unattended `npx`, inline Python, and encoded content piped into another command.

ClawVet reports these lines but never runs them.

### Hidden HTML instructions

Single-line HTML comments are checked for instruction-like words such as `ignore`, `override`, `system prompt`, `new role`, `secret`, and `do not reveal`.

A multi-line comment receives only an informational finding at its opening line. Its body is not fully analyzed.

## Remote input safety

Remote scanning accepts lowercase `https://` URLs only. `curl` is restricted to HTTPS for the first request and every redirect.

The response is written to a private temporary file created by `mktemp`. The file is removed after normal completion. ClawVet does not send the scanned content anywhere else.

File paths, URLs, and matched snippets are stripped of terminal control characters before they are printed. This prevents a malicious input from changing the terminal title or injecting other control sequences into scanner output.

## Use it in a script

Handle every exit code explicitly:

```bash
set +e
bash tools/claw-vet.sh path/to/SKILL.md
result=$?
set -e

case "$result" in
  0) echo "No configured patterns matched. Review before loading." ;;
  1) echo "Manual review required." ;;
  2) echo "Blocked or incomplete scan."; exit 1 ;;
esac
```

Do not use `command || echo ...` as the whole gate. That pattern can print a warning and then continue as if the scan succeeded.

## Run the repository checks

```bash
bash tests/clawvet/run-fixtures.sh
```

The suite verifies:

- a clean fixture exits `0`
- a suspicious fixture exits `1`
- a malicious fixture exits `2`
- finding totals match the lines reported
- terminal control characters from input are not printed
- unencrypted remote URLs are rejected
- a skipped Unicode check produces a warning

The GitHub Actions security baseline runs this same suite on pull requests and pushes to `main`. It also blocks common secret-file names and audits npm lockfiles if any are added later.

## Known limitations

- Patterns can produce false positives in documentation and code examples.
- Reworded, split, encoded, or semantic attacks can avoid regex matching.
- Multi-line HTML comments are not fully parsed.
- Invalid or unusual text encodings may not be interpreted the same way another runtime interprets them.
- Remote cleanup is guaranteed on normal completion, not after every possible machine crash or forced termination.
- ClawVet scans one file at a time and does not inspect an entire skill directory.

Keep agent permissions narrow. Review third-party code and supporting files, not only `SKILL.md`.
