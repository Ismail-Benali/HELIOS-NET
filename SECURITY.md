# Security Policy

HELIOS-NET is a dual-use security tool. Handle vulnerabilities as you would for
any offensive framework: privately, with a coordinated timeline.

> **Authorized use only.** Never point HELIOS-NET at systems you do not own or
> have explicit, verifiable written permission to assess. The scope file is a
> hard boundary; do not weaken it to "make a test work".

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.** Public issues
disclose the flaw before a fix exists and make it trivial to weaponize.

Use GitHub's private vulnerability report instead:
<https://github.com/Ismail-Benali/HELIOS-NET/security/advisories/new>

Include:

- affected version/commit and platform
- reproduction steps against a local lab (no third-party targets)
- impact and any proof-of-concept you can safely share
- whether the finding concerns scope enforcement, the WAL, IPC/native cores,
  report rendering, or dependencies

If private reporting is unavailable in your GitHub client, ask the maintainer
for a private channel before disclosing details.

### Response timeline

| Stage | Target |
| --- | --- |
| Acknowledgement | within 7 days |
| Reproduce and triage | within 14 days |
| Fix or mitigation | within 30 days for high/critical issues |
| Coordinated publication | after the fix ships, by mutual agreement |

Reporters are credited in the advisory unless they prefer anonymity.

## Supported versions

| Version | Supported |
| --- | --- |
| `master` (latest commit) | Yes |
| Latest release tag | Yes |
| Older tags | No — update first |

## Threat model (what we actually protect)

| Trust boundary | Adversary | Current mitigation |
| --- | --- | --- |
| CLI → control plane | crafted YAML/JSON scope, paths, flags | fail-closed scope; `*` and unreadable/malformed scopes are errors |
| Control plane → network | target-controlled DNS/HTTP/TLS responses | scope checked before any socket; redirects followed only while every hop stays in scope |
| Native cores (Go/C/Rust) → Python | malformed NDJSON, ABI payloads | typed contracts in `docs/IPC-CONTRACT.md`, length limits, validated FFI inputs |
| WAL and campaign state | local attacker reading logs/files | PBKDF2-stretched key, per-record nonce, HMAC-SHA256 keystream |
| Reports → browser | hostile hostnames/banners | HTML escaping in generated reports |
| Supply chain | compromised dependency | Dependabot, pinned dev toolchain, CI on Ubuntu and Windows |

Out of scope for this project: protecting a user who deliberately disables
scope enforcement, or who runs HELIOS-NET on a machine they do not control.

## Secure development

- Never commit API keys, tokens, scopes for real targets, or campaign output.
- Run `pre-commit install` and `python -m pytest -q` before opening a PR.
- Keep scope enforcement fail-closed; any change that widens the default
  authorization boundary needs an explicit security review.
- Treat native code changes as security-sensitive: sanitizers and the C golden
  contract must stay green.
- Report suspected vulnerabilities privately, per the section above.

See [scope enforcement](docs/SCOPE-ENFORCEMENT.md) and
[architecture](docs/Architecture.md) for the implementation details.
