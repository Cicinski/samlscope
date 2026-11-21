"""Security findings for a SAML message. Each finding: id, severity, title, detail."""
from __future__ import annotations

import datetime as dt

from lxml import etree

from .summary import parse_time
from .xmlsafe import NS

HIGH, MEDIUM, LOW, INFO = "high", "medium", "low", "info"
ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}


def _f(fid: str, severity: str, title: str, detail: str) -> dict:
    return {"id": fid, "severity": severity, "title": title, "detail": detail}


def lint(root: etree._Element, summary: dict, signatures: list[dict], now: dt.datetime | None = None) -> list[dict]:
    now = now or dt.datetime.now(dt.timezone.utc)
    out: list[dict] = []
    kind = summary["type"]
    assertions = summary["assertions"]
    signed_on = {s["on"] for s in signatures}

    # --- signature wrapping (XSW) indicators ------------------------------------------
    if len(assertions) > 1:
        out.append(_f("multiple-assertions", HIGH, "More than one Assertion",
                      "Legitimate IdPs send one assertion. Several assertions are a classic XML Signature Wrapping "
                      "pattern: the SP may verify one and read another."))
    ids = [el.get("ID") for el in root.iter() if isinstance(el.tag, str) and el.get("ID")]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        out.append(_f("duplicate-ids", HIGH, "Duplicate ID attributes",
                      f"IDs {dupes} appear more than once: a signature reference may resolve to a different element "
                      "than the one the SP processes (XSW)."))
    for s in signatures:
        if not s["reference_matches_parent"]:
            out.append(_f("reference-mismatch", HIGH, f"Signature on {s['on']} does not reference its own element",
                          f"References {s['references']} but the enclosing element has ID {s['on_id']!r}. "
                          "Enveloped SAML signatures must reference their parent; anything else suggests XSW."))
        if s["weak_algorithm"]:
            out.append(_f("weak-signature-algorithm", MEDIUM, f"Weak algorithm in signature on {s['on']}",
                          f"Signature {s['signature_algorithm']}, digests {s['digest_algorithms']}. "
                          "SHA-1 is deprecated; use RSA-SHA256 or stronger."))
        cert = s.get("embedded_certificate") or {}
        if cert.get("expired"):
            out.append(_f("certificate-expired", MEDIUM, "Embedded signing certificate has expired",
                          f"{cert.get('subject')} expired {cert.get('not_after')}. Many SPs ignore expiry for pinned "
                          "keys, but it signals poor key rotation."))
        if cert.get("weak_key"):
            out.append(_f("weak-key", MEDIUM, "Weak signing key", f"{cert.get('key')} is below current minimums."))
    if signatures and any(s.get("embedded_certificate") for s in signatures):
        out.append(_f("embedded-certificate", INFO, "Certificate is embedded in the signature",
                      "Never trust the embedded certificate on its own. Verify against the IdP certificate you "
                      "obtained out of band (metadata), e.g. samlscope --metadata idp.xml."))

    # --- signing coverage --------------------------------------------------------------
    if kind == "Response":
        if assertions and "Assertion" not in signed_on and "Response" not in signed_on:
            out.append(_f("unsigned", HIGH, "Neither the Response nor the Assertion is signed",
                          "Anyone can forge this message. An SP must reject it."))
        elif assertions and "Assertion" not in signed_on:
            out.append(_f("assertion-unsigned", MEDIUM, "Only the Response is signed, not the Assertion",
                          "Acceptable per the spec, but signing the assertion itself (wantAssertionsSigned) "
                          "protects it if it is ever extracted or forwarded."))
        if summary["encrypted_assertions"]:
            out.append(_f("encrypted-assertion", INFO, "Encrypted assertion present",
                          "Decryption needs the SP's private key and is not performed by samlscope."))
        if summary.get("in_response_to") is None:
            out.append(_f("unsolicited", LOW, "Unsolicited response (no InResponseTo)",
                          "IdP-initiated SSO. It cannot be tied to a request, which makes replay and login-CSRF "
                          "easier; accept only if you need IdP-initiated SSO."))
        if summary.get("destination") is None and signatures:
            out.append(_f("no-destination", LOW, "Signed Response without Destination",
                          "Destination lets the SP detect a response sent to the wrong endpoint."))
        status = summary.get("status") or {}
        if status and not status.get("success"):
            out.append(_f("status-not-success", INFO, f"Status: {'/'.join(status.get('codes', []))}",
                          status.get("message") or "The IdP did not authenticate the user."))

    # --- per-assertion checks --------------------------------------------------------------
    for a_el, a in zip(root.iter(f"{{{NS['saml']}}}Assertion"), assertions):
        name_id = a_el.find("saml:Subject/saml:NameID", NS)
        if name_id is not None and any(isinstance(c, etree._Comment) for c in name_id.iter()):
            out.append(_f("comment-in-nameid", HIGH, "XML comment inside NameID",
                          "Libraries that read only the first text node would see a truncated identity "
                          "(e.g. 'admin@victim.com<!---->.evil.com'), the CVE-2017-11427 family of SAML bugs."))
        for attr in a_el.iter(f"{{{NS['saml']}}}AttributeValue"):
            if any(isinstance(c, etree._Comment) for c in attr.iter()):
                out.append(_f("comment-in-attribute", MEDIUM, "XML comment inside an attribute value",
                              "Same truncation risk as for NameID if the SP reads only the first text node."))
                break
        if not a["conditions"]["audiences"]:
            out.append(_f("no-audience", MEDIUM, "No AudienceRestriction",
                          "Without an audience the assertion could be replayed to another service provider."))
        nb, na = parse_time(a["conditions"]["not_before"]), parse_time(a["conditions"]["not_on_or_after"])
        if nb and na and (na - nb) > dt.timedelta(hours=1):
            out.append(_f("long-validity", LOW, "Long assertion validity window",
                          f"Valid for {na - nb}. Minutes, not hours, limit the replay window."))
        if na and na < now:
            out.append(_f("expired", INFO, "Assertion has expired",
                          f"NotOnOrAfter {a['conditions']['not_on_or_after']} is in the past (normal for a captured message)."))
        if nb and nb > now + dt.timedelta(minutes=5):
            out.append(_f("not-yet-valid", MEDIUM, "Assertion is not valid yet",
                          f"NotBefore {a['conditions']['not_before']}: check clock skew between IdP and SP."))
        bearer = [c for c in a["subject_confirmations"] if c["method"] == "bearer"]
        if bearer and not any(c["recipient"] for c in bearer):
            out.append(_f("no-recipient", MEDIUM, "Bearer confirmation without Recipient",
                          "Recipient binds the assertion to the SP's endpoint; without it a stolen assertion "
                          "is easier to replay elsewhere."))
        if a["name_id"]["format"] == "unspecified":
            out.append(_f("nameid-unspecified", INFO, "NameID format is 'unspecified'",
                          "Agree a stable identifier with the IdP (persistent, or email with care)."))

    if kind == "AuthnRequest" and "AuthnRequest" not in signed_on:
        out.append(_f("request-unsigned", INFO, "AuthnRequest is not signed",
                      "Common and usually acceptable. Sign it if the IdP requires it or uses the request's ACS URL "
                      "without checking it against registered endpoints."))
    return sorted(out, key=lambda f: ORDER[f["severity"]])
