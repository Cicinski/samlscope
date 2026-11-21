"""One entry point used by the CLI, the local web UI and as a library."""
from __future__ import annotations

import datetime as dt

from .decode import DecodeError, decode
from .lint import lint
from .signatures import describe, load_trusted_certs, verify
from .summary import summarize
from .xmlsafe import UnsafeXML, parse, pretty


def analyze(text: str, cert: str | None = None, metadata: str | None = None,
            now: dt.datetime | None = None) -> dict:
    """Decode, summarise, lint and (if trust material is given) verify a SAML message.
    Never raises for bad input: errors are returned in the result."""
    try:
        decoded = decode(text)
    except DecodeError as e:
        return {"ok": False, "error": f"Could not decode input: {e}"}
    try:
        root = parse(decoded.xml)
    except UnsafeXML as e:
        return {"ok": False, "error": str(e), "refused": True,
                "decoding": {"binding": decoded.binding, "steps": decoded.steps}}

    summary = summarize(root)
    sigs = describe(root)
    result = {
        "ok": True,
        "decoding": {"binding": decoded.binding, "parameter": decoded.parameter, "steps": decoded.steps,
                     "relay_state": decoded.relay_state, "redirect_sig_alg": decoded.redirect_sig_alg,
                     "redirect_signature_present": decoded.redirect_signature_present},
        "summary": summary,
        "signatures": sigs,
        "findings": lint(root, summary, sigs, now),
        "xml": pretty(root),
        "verification": None,
    }
    try:
        trusted = load_trusted_certs(cert, metadata)
    except (UnsafeXML, ValueError) as e:
        result["verification"] = {"error": f"could not load trust material: {e}"}
        return result
    if trusted:
        checks = verify(root, trusted)
        result["verification"] = {"trusted_certificates": len(trusted), "results": checks}
        for c in checks:
            if not c["valid"]:
                result["findings"].insert(0, {"id": "signature-invalid", "severity": "high",
                                              "title": f"Signature on {c['on']} does NOT verify",
                                              "detail": c["error"]})
    return result
