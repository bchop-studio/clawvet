# ClawVet

A small local security scanner for Markdown-based AI agent skill files.

[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](./LICENSE)
[![Security Baseline](https://github.com/bchop-studio/clawvet/actions/workflows/security-baseline.yml/badge.svg)](https://github.com/bchop-studio/clawvet/actions/workflows/security-baseline.yml)

ClawVet checks one local file or HTTPS URL for suspicious text before you load it into an agent. It was built for OpenClaw `SKILL.md` files, but it can scan any Markdown instruction file.

It does not execute the file it scans.

## What it checks

| Check | Examples |
| --- | --- |
| Hidden Unicode | Zero-width characters, direction overrides, and invisible markers |
| Prompt injection | Instruction overrides, role changes, and jailbreak phrases |
| Dangerous shell | Remote scripts piped into shells, reverse-shell paths, `eval`, and encoded execution |
| Hidden HTML instructions | Suspicious instructions inside single-line `<!-- comments -->` |

ClawVet is pattern-based. A clean result means none of its configured patterns matched. It does not prove that a skill is safe.

## Requirements

- Bash
- Python 3 for the hidden-Unicode check
- Standard command-line tools such as `grep`, `sed`, `tr`, and `mktemp`
- `curl` only when scanning a remote URL

If Python 3 is unavailable, ClawVet returns a warning instead of silently passing the file.

## Install

```bash
git clone https://github.com/bchop-studio/clawvet.git
cd clawvet
```

Review `tools/claw-vet.sh` before running it. ClawVet has no package install step and does not need root access.

## Use

Scan a local skill:

```bash
bash tools/claw-vet.sh path/to/SKILL.md
```

Scan a raw file over HTTPS:

```bash
bash tools/claw-vet.sh https://raw.githubusercontent.com/user/repo/main/SKILL.md
```

Remote scans accept HTTPS only. ClawVet downloads the file to a temporary location, scans it, and removes the temporary copy after normal completion.

## Results

| Result | Exit code | Meaning |
| --- | ---: | --- |
| `PASS` | `0` | No configured patterns matched. Review before loading. |
| `WARN` | `1` | Suspicious text or an incomplete check needs manual review. |
| `FAIL` | `2` | A critical pattern matched, or the scan could not be completed safely. |

Each finding includes its severity, category, and line number.

## Run the tests

```bash
bash tests/clawvet/run-fixtures.sh
```

The test suite checks clean, suspicious, and malicious fixtures. It also covers terminal-control sanitizing, accurate finding counts, HTTPS-only remote input, and the missing-Python warning path.

## Limits

ClawVet uses simple pattern matching, not semantic analysis. It can miss reworded or encoded attacks, and it can flag harmless examples that contain dangerous-looking text.

Treat it as an early warning layer. Keep normal permission limits, sandboxing, and human review around agents that can take real actions.

Read [the detailed guide](./docs/clawvet.md) for the full rule list and known limitations. OpenClaw's current skill format is documented in [Creating skills](https://docs.openclaw.ai/tools/creating-skills).

## Security

The malicious test files contain fake attack examples on reserved domains. They do not contain working credentials.

Report a real vulnerability privately through [GitHub Security Advisories](https://github.com/bchop-studio/clawvet/security/advisories/new). Do not put secrets or exploit details in a public issue.

See [SECURITY.md](./SECURITY.md) for the reporting policy.

---

MIT. Do whatever you want with these.

Built by [@BChopLXXXII](https://x.com/BChopLXXXII)

Built for BUILDERS who just want their AI to feel less... corporate.

Ship it. 🚀

If this helped, ⭐ the repo — it helps others find it.
