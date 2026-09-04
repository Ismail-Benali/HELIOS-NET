# Security Policy

HELIOS-NET is a **dual-use security framework** for authorized red teaming and attack surface management (ASM). We take the security of this project — and the responsible disclosure of any vulnerabilities found within it — very seriously.

---

## 🔒 Supported Versions

We actively maintain and patch the latest release. Older releases receive security updates on a best-effort basis.

| Version | Supported          |
| ------- | ------------------ |
| latest (≥ v1.0.0) | ✅ Supported |
| < v1.0.0 | ❌ Not supported |

---

## 🚨 Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Instead, report privately so we can coordinate a fix and disclosure responsibly. To report a vulnerability:

- **Email:** [7175ismail@gmail.com](mailto:7175ismail@gmail.com)
  - Subject line: `[HELIOS-NET SECURITY] <short summary>`
- **Alternatively:** use GitHub's **Private Vulnerability Reporting** on this repository
  - Repo → **Security** tab → **Report a vulnerability**

### What to include
To help us triage quickly, please provide:

1. **Description** — what the vulnerability is and any impact.
2. **Affected versions** — commit/tag and component (`core/`, `engine/`, `transport/`, `rust-core/`, build pipeline).
3. **Reproduction** — minimal steps, a proof-of-concept (if safe to share), and environment details.
4. **Suggested fix** — if you have one.

---

## 📋 Our Commitment

- We will acknowledge receipt of your report within **48 hours**.
- We will work toward a fix and validated release.
- We will coordinate public disclosure after a fix is available, giving credit unless you prefer to remain anonymous.
- We **will not** take legal action against researchers acting in good faith and following this policy.

---

## ⚠️ Scope

This policy covers the HELIOS-NET codebase itself (Python core, Go/C native binaries, Rust core, build/CI automation).

**Out of scope:**
- Network targets or third-party systems (these are the *subjects* of authorized testing, not part of this project's scope).
- Misuse of the framework against unauthorized assets — such misuse is the user's responsibility and is not something we support or remediate within this policy.

---

## 🛡️ Responsible Use

HELIOS-NET must only be used against systems **you own** or have **explicit written authorization** to assess. Unauthorized testing is unethical and illegal in most jurisdictions. By using or contributing to HELIOS-NET you agree to use it responsibly.

---

## 🤝 Coordinated Disclosure

We follow a reasonable coordinated-disclosure process: report privately → we patch → we publish a security advisory and release notes → you may then discuss publicly.

Thank you for helping make HELIOS-NET more secure. ⚡
