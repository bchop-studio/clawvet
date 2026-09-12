# Security Policy

ClawVet scans untrusted agent instruction files, so scanner bugs and misleading verdicts are security-sensitive.

## Supported version

The latest commit on `main` is the supported version.

## Report a vulnerability privately

Use [GitHub's private vulnerability reporting form](https://github.com/bchop-studio/clawvet/security/advisories/new).

Include the affected command or file, the unexpected behavior, and a minimal reproduction when possible. Do not include real passwords, API keys, private keys, tokens, customer data, or private machine details.

Do not open a public issue containing exploit details. A normal bug with no security impact can use the public issue tracker.

## Security notes

- A `PASS` result means no configured pattern matched. It is not proof that a skill is safe.
- Review the whole skill directory, not only `SKILL.md`, before installing third-party code.
- Do not run shell commands copied from an untrusted skill merely because ClawVet did not flag them.
- Keep agent tools behind narrow permissions, sandboxes, and approval checks.
- The malicious fixtures use reserved example domains and contain no working credentials.
