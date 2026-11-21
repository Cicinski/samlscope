"""Export certificates embedded in SAML signatures, in the formats people actually need.

  raw   exactly as it appears inside <ds:X509Certificate> (line breaks preserved)
  b64   base64 on one line (what most admin consoles expect)
  pem   -----BEGIN CERTIFICATE----- with 64-character lines
  der   binary DER (.cer/.der: Windows certificate viewer, Java keystores)

An embedded certificate is attacker-controllable: exporting it is fine, trusting it is not.
"""
from __future__ import annotations

import base64
import binascii

FORMATS = {
    "pem": {"label": "PEM", "ext": ".pem", "binary": False},
    "der": {"label": "DER (binary)", "ext": ".cer", "binary": True},
    "b64": {"label": "Base64, one line", "ext": ".txt", "binary": False},
    "raw": {"label": "As in the message", "ext": ".txt", "binary": False},
}


class ExportError(ValueError):
    pass


def unique_certificates(signatures: list[dict]) -> list[dict]:
    """One entry per distinct certificate (Response and Assertion are usually signed with the same one).
    Each entry lists which signed elements it appeared on."""
    seen: dict[str, dict] = {}
    for s in signatures:
        cert = s.get("embedded_certificate")
        if not cert or not cert.get("base64"):
            continue
        entry = seen.setdefault(cert["base64"], {"certificate": cert, "used_by": []})
        entry["used_by"].append(f"{s['on']} {s['on_id'] or ''}".strip())
    return list(seen.values())


def export(cert: dict, fmt: str) -> bytes:
    if fmt not in FORMATS:
        raise ExportError(f"unknown format {fmt!r} (choose from {', '.join(FORMATS)})")
    if fmt == "raw":
        return cert["raw"].encode()
    if fmt == "b64":
        return (cert["base64"] + "\n").encode()
    try:
        der = base64.b64decode(cert["base64"], validate=True)
    except (binascii.Error, ValueError) as e:
        raise ExportError(f"the embedded certificate is not valid base64, so only 'raw' export is possible: {e}") from e
    if fmt == "der":
        return der
    body = base64.b64encode(der).decode()
    lines = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n".encode()


def suggested_filename(cert: dict, fmt: str) -> str:
    """e.g. 'globex-7B418D0C.pem' from the subject CN and fingerprint."""
    subject = cert.get("subject") or "certificate"
    cn = next((p.split("=", 1)[1] for p in subject.split(",") if p.strip().upper().startswith("CN=")), "certificate")
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in cn).strip("-.") or "certificate"
    fp = (cert.get("sha256_fingerprint") or "").replace(":", "")[:8]
    return f"{safe}{'-' + fp if fp else ''}{FORMATS[fmt]['ext']}"
