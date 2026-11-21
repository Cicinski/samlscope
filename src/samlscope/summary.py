"""Human-readable facts from a SAML message."""
from __future__ import annotations

import datetime as dt

from lxml import etree

from .xmlsafe import NS, local


def _text(el, path: str) -> str | None:
    found = el.find(path, NS)
    return found.text.strip() if found is not None and found.text else None


def parse_time(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _status(root) -> dict | None:
    st = root.find("samlp:Status", NS)
    if st is None:
        return None
    codes = [c.get("Value", "").rsplit(":", 1)[-1] for c in st.iter(f"{{{NS['samlp']}}}StatusCode")]
    return {"codes": codes, "message": _text(st, "samlp:StatusMessage"), "success": codes[:1] == ["Success"]}


def _assertion(a) -> dict:
    subject = a.find("saml:Subject", NS)
    name_id = subject.find("saml:NameID", NS) if subject is not None else None
    confirmations = []
    if subject is not None:
        for sc in subject.findall("saml:SubjectConfirmation", NS):
            data = sc.find("saml:SubjectConfirmationData", NS)
            confirmations.append({
                "method": (sc.get("Method") or "").rsplit(":", 1)[-1],
                "recipient": data.get("Recipient") if data is not None else None,
                "not_on_or_after": data.get("NotOnOrAfter") if data is not None else None,
                "in_response_to": data.get("InResponseTo") if data is not None else None,
            })
    cond = a.find("saml:Conditions", NS)
    authn = a.find("saml:AuthnStatement", NS)
    attributes: dict[str, list[str]] = {}
    for attr in a.iter(f"{{{NS['saml']}}}Attribute"):
        name = attr.get("FriendlyName") or attr.get("Name")
        attributes.setdefault(name, []).extend(
            "".join(v.itertext()).strip() for v in attr.findall("saml:AttributeValue", NS))
    return {
        "id": a.get("ID"),
        "issuer": _text(a, "saml:Issuer"),
        "issue_instant": a.get("IssueInstant"),
        "name_id": {
            "value": "".join(name_id.itertext()).strip() if name_id is not None else None,
            "format": (name_id.get("Format") or "").rsplit(":", 1)[-1] if name_id is not None else None,
        },
        "subject_confirmations": confirmations,
        "conditions": {
            "not_before": cond.get("NotBefore") if cond is not None else None,
            "not_on_or_after": cond.get("NotOnOrAfter") if cond is not None else None,
            "audiences": [x.text for x in cond.iter(f"{{{NS['saml']}}}Audience")] if cond is not None else [],
        },
        "authn": {
            "instant": authn.get("AuthnInstant") if authn is not None else None,
            "session_index": authn.get("SessionIndex") if authn is not None else None,
            "session_not_on_or_after": authn.get("SessionNotOnOrAfter") if authn is not None else None,
            "context": _text(authn, "saml:AuthnContext/saml:AuthnContextClassRef") if authn is not None else None,
        },
        "attributes": attributes,
    }


def summarize(root: etree._Element) -> dict:
    kind = local(root)
    s = {
        "type": kind,
        "id": root.get("ID"),
        "issue_instant": root.get("IssueInstant"),
        "destination": root.get("Destination"),
        "issuer": _text(root, "saml:Issuer"),
        "in_response_to": root.get("InResponseTo"),
        "status": _status(root),
    }
    if kind == "AuthnRequest":
        policy = root.find("samlp:NameIDPolicy", NS)
        s["request"] = {
            "acs_url": root.get("AssertionConsumerServiceURL"),
            "protocol_binding": (root.get("ProtocolBinding") or "").rsplit(":", 1)[-1] or None,
            "name_id_format": (policy.get("Format") or "").rsplit(":", 1)[-1] if policy is not None else None,
            "force_authn": root.get("ForceAuthn"),
            "is_passive": root.get("IsPassive"),
            "requested_authn_context": [c.text for c in root.iter(f"{{{NS['saml']}}}AuthnContextClassRef")],
        }
    if kind in ("LogoutRequest",):
        s["logout"] = {"name_id": _text(root, "saml:NameID"), "session_index": _text(root, "samlp:SessionIndex")}
    s["assertions"] = [_assertion(a) for a in root.iter(f"{{{NS['saml']}}}Assertion")]
    s["encrypted_assertions"] = len(list(root.iter(f"{{{NS['saml']}}}EncryptedAssertion")))
    return s
