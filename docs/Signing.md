# Code signing the native cores

Smart App Control, AppLocker and WDAC refuse to execute a freshly built
**unsigned** native image. The refusal is permanent for that image, arrives as
`WinError 4551`, and Code Integrity records:

> did not meet the Enterprise signing level requirements or violated code
> integrity policy

The verdict is not about the compiler. Measured on a Windows 11 host with Smart
App Control in evaluation mode:

| Image | Result |
|---|---|
| MinGW `helios_c_core.dll`, built moments earlier | refused, 4551 |
| `rustprobe.dll` — a **rustc** cdylib built seconds earlier | refused, 4551 |
| `helios_rust_core.dll`, present for some time | loads |
| `goscan.exe`, Go, present for some time | runs |

All four were `NotSigned` with no Mark of the Web, and all were produced by
different toolchains. What Smart App Control weighs is the image's standing, not
its language or its exports. So on a developer's own machine the C core, the C
fuzzer and the Go test binaries can all be blocked for reasons that have nothing
to do with the code, and the only supported answer is a valid code signature.

**Do not work around this.** Relocating a binary to obtain a different policy
decision, renaming it, or adding an exclusion all defeat a security control that
exists precisely to stop an unvetted image from running. Signing satisfies the
control instead of evading it.

`build.py` signs every native artifact — the C core, the Rust cdylib, the Go
scanners, the C unit suite and the C fuzzer — as each is built, verifies each
signature with `signtool verify /pa`, and prints the outcome in its summary:

```
- Signing:        3 signed, 0 unsigned
```

An artifact `signtool` reports as signed but that does not verify is a **build
failure**, not a warning: it is exactly the condition that produces binaries
which look trusted and are not.

## Prerequisites

`signtool.exe` ships with the Windows SDK. Install the SDK (or just the Signing
Tools component) and make sure it is discoverable — `build.py` finds it on
`PATH` first, then under `%ProgramFiles(x86)%\Windows Kits\10\bin\*\x64\`.

## Getting a certificate

Any certificate whose chain validates to a root in `Trusted Root Certification
Authorities` satisfies the policy. In practice that means a real code-signing
certificate from a CA, not a self-signed one:

- **OV (Organisation Validation)** — the certificate names your organisation.
  Cheapest option that Smart App Control accepts.
- **EV (Extended Validation)** — same trust result for this purpose, at a higher
  price and with stricter identity checks. Worth it only if you also want the
  reputation benefits elsewhere; the signing requirement here does not ask for it.

A self-signed certificate will **not** work for distribution. It only helps on
the one machine whose trust store you modify, and it does not give anyone else a
running C core — which is the entire point of signing rather than patching.

## Exporting the certificate

Convert to a PFX containing the private key, then base64 it. GitHub Actions
cannot store a binary secret directly.

```powershell
# Export with the private key, prompted for a password.
certutil -p <password> -exportpfx "My\CertName" code-signing.pfx

# Base64 it, on one line, with no wrapping.
[Convert]::ToBase64String([IO.File]::ReadAllBytes("code-signing.pfx")) | Set-Content cert.b64 -NoNewline
```

Keep that password. It is the second secret, and it is not recoverable.

## Configuring the repository secrets

Add both under **Settings → Secrets and variables → Actions**:

| Secret | Value |
|---|---|
| `HELIOS_SIGN_PFX_B64` | contents of `cert.b64` |
| `HELIOS_SIGN_PASSWORD` | the PFX export password |

The workflow decodes the certificate into the runner's temp directory and points
`build.py` at it. Both secrets are optional: a build without them runs and
reports every artifact as `UNSIGNED`, which is honest rather than broken, so a
fork or a contributor without access still gets a working pipeline.

`HELIOS_SIGN_TIMESTAMP` overrides the RFC 3161 timestamp service if the default
(`timestamp.digicert.com`) is unreachable from your runner. Timestamping is not
optional in practice: an undated signature stops validating when the certificate
expires, which would silently turn a signed release back into a blocked one.

## Verifying locally

```powershell
$env:HELIOS_SIGN_PFX      = "C:\path\to\code-signing.pfx"
$env:HELIOS_SIGN_PASSWORD = "<password>"
python build.py --test
```

Then confirm the C core is genuinely running rather than silently falling back:

```powershell
python -c "from core.c_core_bridge import core_available, core_version; print(core_available(), core_version())"
```

`True <version>` means the native core is loaded. `False` with
`WinError 4551` means the signature is not being accepted — check that the
issuing root is in `Trusted Root Certification Authorities` and that the
certificate is not expired.

## Verifying the signature itself

```powershell
Get-AuthenticodeSignature .\transport\c_core\build\helios_core.exe | Format-List
```

`Status` should be `Valid` and `SignerCertificate` should be your certificate,
not `NotSigned`. `build.py` performs the equivalent check with
`signtool verify /pa` after every signing and fails the build if it does not pass.

## What CI proves

Two steps guard this on a Windows runner:

- **`Code Signing Credentials`** materialises the certificate from the secrets.
- **`Signed Build Actually Runs the C Core`** asserts `core_available()` is true
  after the build, and fails the job if it is not.

The second step is the one that matters. Signing that quietly stops working — an
expired certificate, a rotated secret, a root that fell out of the store — would
otherwise leave the pipeline green while the C core stayed unrunnable, which is
precisely the failure signing exists to remove.

## If you cannot sign

Nothing breaks, and nothing is hidden. The C core falls back to Rust or Python,
`core_available()` returns `False` with the reason, the report reads
`UNSIGNED`, and the C stages report `BLOCKED BY HOST POLICY` rather than
`PASSED`. The fallback is verified against the C core's recorded contract on
every machine and on every push — see *Verifying the C contract on a host that
cannot run the C core* in `Architecture.md` — so a campaign produces the same
detections either way. What signing adds is native performance and the ability
to run the C test suite locally, not correctness.
