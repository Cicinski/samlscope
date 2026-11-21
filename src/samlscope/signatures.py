"""Describe XML signatures and, when a trusted certificate is supplied, verify them."""
from __future__ import annotations

import base64
import copy
import datetime as dt
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from lxml import etree
from signxml import XMLVerifier
from signxml.exceptions import InvalidCertificate, InvalidDigest, InvalidInput, InvalidSignature

from .xmlsafe import NS, local, parser

WEAK_ALGS = ("sha1", "md5")


def _short(uri: str | None) -> str | None:
    return uri.rsplit("#", 1)[-1] if uri else None


def certificate_info(b64der: str) -> dict:
    try:
        cert = x509.load_der_x509_certificate(base64.b64decode(re.sub(r"\s+", "", b64der)))
    except Exception as e:  # noqa: BLE001 - report, don't crash on garbage
        return {"error": f"unreadable certificate: {e}"}
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_desc, weak_key = f"RSA {key.key_size}", key.key_size < 2048
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_desc, weak_key = f"EC {key.curve.name}", key.curve.key_size < 256
    else:
        key_desc, weak_key = type(key).__name__, False
    now = dt.datetime.now(dt.timezone.utc)
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "expired": cert.not_valid_after_utc < now,
        "key": key_desc,
        "weak_key": weak_key,
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(":").upper(),
    }


def describe(root: etree._Element) -> list[dict]:
    out = []
    for sig in root.iter(f"{{{NS['ds']}}}Signature"):
        parent = sig.getparent()
        refs = [r.get("URI") for r in sig.findall("ds:SignedInfo/ds:Reference", NS)]
        digests = [_short(d.get("Algorithm")) for d in sig.findall("ds:SignedInfo/ds:Reference/ds:DigestMethod", NS)]
        method = sig.find("ds:SignedInfo/ds:SignatureMethod", NS)
        cert_el = sig.find("ds:KeyInfo/ds:X509Data/ds:X509Certificate", NS)
        parent_id = parent.get("ID") if parent is not None else None
        out.append({
            "on": local(parent) if parent is not None else None,
            "on_id": parent_id,
            "references": refs,
            "reference_matches_parent": refs == [f"#{parent_id}"] if parent_id else False,
            "signature_algorithm": _short(method.get("Algorithm")) if method is not None else None,
            "digest_algorithms": digests,
            "weak_algorithm": any(w in (a or "") for w in WEAK_ALGS
                                  for a in [_short(method.get("Algorithm")) if method is not None else ""] + digests),
            "embedded_certificate": _embedded(cert_el.text) if cert_el is not None and cert_el.text else None,
        })
    return out


def _embedded(raw: str) -> dict:
    """Certificate details plus the material needed to export it: the exact text from the message
    and the whitespace-free base64. Embedded certificates are untrusted: exporting is not trusting."""
    return certificate_info(raw) | {"raw": raw, "base64": re.sub(r"\s+", "", raw)}


def load_trusted_certs(cert_text: str | None = None, metadata_text: str | None = None) -> list[str]:
    """PEM certificates to trust: from a PEM/base64 cert, or the signing keys in IdP/SP metadata."""
    pems: list[str] = []
    if cert_text and cert_text.strip():
        blocks = re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", cert_text, re.S)
        pems.extend(blocks or [_pem(cert_text)])
    if metadata_text and metadata_text.strip():
        from .xmlsafe import parse
        md = parse(metadata_text.encode())
        for kd in md.iter(f"{{{NS['md']}}}KeyDescriptor"):
            if kd.get("use") in (None, "signing"):
                for c in kd.iter(f"{{{NS['ds']}}}X509Certificate"):
                    pems.append(_pem(c.text))
    return list(dict.fromkeys(pems))


def _pem(b64: str) -> str:
    body = re.sub(r"\s+", "", b64)
    lines = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"


def verify(root: etree._Element, trusted: list[str]) -> list[dict]:
    """Verify every signature against the trusted certificates.
    Returns, per signature, whether it is valid and WHICH element the signature really covers."""
    results = []
    for sig in root.iter(f"{{{NS['ds']}}}Signature"):
        parent = sig.getparent()
        # Re-parse the signed element on its own so only its own signature is considered
        element = etree.fromstring(etree.tostring(copy.deepcopy(parent)), parser=parser())
        outcome = {"on": local(parent), "on_id": parent.get("ID"), "valid": False, "signed_element": None, "error": None}
        errors = []
        for pem in trusted:
            try:
                res = XMLVerifier().verify(element, x509_cert=pem)
                signed = res.signed_xml
                outcome |= {"valid": True, "error": None,
                            "signed_element": f"{local(signed)} ID={signed.get('ID')}" if signed is not None else None}
                break
            except InvalidInput as e:
                errors.append(f"rejected: {e}")
            except (InvalidSignature, InvalidDigest, InvalidCertificate) as e:
                errors.append(str(e) or type(e).__name__)
            except Exception as e:  # noqa: BLE001
                errors.append(f"{type(e).__name__}: {e}")
        if not outcome["valid"]:
            outcome["error"] = "; ".join(dict.fromkeys(errors)) or "no trusted certificate supplied"
        results.append(outcome)
    return results
