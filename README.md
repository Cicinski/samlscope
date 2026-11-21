# samlscope

**Decode, verify and security-check SAML messages on your own machine.** A desktop app for Windows and Linux, plus a CLI for pipelines.

> SAML responses contain names, emails, roles and session identifiers. Pasting them into online decoders sends personal data to a third party. samlscope never touches the network: nothing is uploaded, stored or logged.

## What it does

- **Decodes anything you paste:** HTTP-POST (base64), HTTP-Redirect (base64 + DEFLATE), a full redirect URL, a form body, URL-encoded values, or raw XML. It detects the format automatically.
- **Explains the message:** issuer, destination, `InResponseTo`, status, subject and NameID format, audience, validity window, authentication context, attributes, AuthnRequest details.
- **Verifies signatures** against a certificate or the IdP/SP **metadata** you trust, and shows **what each signature actually covers**, which is the key to spotting signature-wrapping attacks.
- **Security lint:**

| Severity | Checks |
|---|---|
| High | Unsigned response; signature does not verify; XML Signature Wrapping indicators (several assertions, duplicate IDs, reference ≠ own element); XML comment in NameID (CVE-2017-11427 family) |
| Medium | Only the Response is signed; SHA-1; weak or expired signing key; no AudienceRestriction; bearer confirmation without Recipient; not-yet-valid assertion |
| Low / info | Unsolicited (IdP-initiated) response; long validity window; missing Destination; encrypted assertion present; embedded-certificate trust warning |

- **Safe on hostile input:** DTDs and entities are refused (no XXE, no billion laughs), DEFLATE and size limits apply, and untrusted content is only ever shown as plain text.

## Desktop app

Download `samlscope-linux-x86_64` or `samlscope-windows-x86_64.exe` from the CI artifacts or releases and run it. No installation and no Python needed.

Paste a message (or drop a file) and press **Ctrl+Enter**. To verify signatures, use **Trust metadata…** or **Trust certificate…**. **File → Export report** saves JSON. The report contains the decoded message, so handle it with care.

From source:
```bash
pip install ".[gui]"
samlscope-gui
```

## CLI

```bash
pip install .
samlscope message.b64                       # file, '-' for stdin, or the value itself
samlscope --metadata idp-metadata.xml message.b64
samlscope --json < message.b64 | jq .findings
```
Exit codes: `0` no high-severity findings, `1` could not decode / refused, `2` high-severity finding or invalid signature, so you can use it as a CI gate.

## Build the desktop executables

| Platform | How |
|---|---|
| Linux | `docker build -f packaging/Dockerfile.linux .` builds on Debian bookworm (glibc 2.36) for wide compatibility, then runs a smoke test |
| Windows | CI on a Windows runner (`.github/workflows/test.yml` or `.gitlab-ci.yml`), using `packaging/samlscope.spec` |

PyInstaller cannot cross-compile, so each OS builds its own executable. Build dependencies are pinned in `packaging/requirements-build.txt`: PySide6 6.12 produced a binary that crashed at start-up, while 6.8.2.1 is tested by the smoke test on every build.

## Development

```bash
python -m venv .venv && .venv/bin/pip install -e ".[test]"
QT_QPA_PLATFORM=offscreen .venv/bin/pytest -q
```
Tests generate real signed SAML with throwaway keys (no captured data from real systems): valid, wrong-key and tampered signatures, signature wrapping, comment injection, XXE and entity expansion, SHA-1, replay hygiene, plus the desktop UI (plain-text rendering, refusal of hostile input).

## Licence
MIT. Qt for Python (PySide6) is used under the LGPL v3.
