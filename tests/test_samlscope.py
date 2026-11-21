from __future__ import annotations

import json
import subprocess
import sys
from urllib.parse import quote

from samlscope import analyze
from tests.conftest import NOW, post_binding, redirect_binding, response_xml, sign_assertion, unsigned


def ids(result) -> set[str]:
    return {f["id"] for f in result["findings"]}


# --- decoding ---------------------------------------------------------------------

def test_post_binding_base64():
    r = analyze(post_binding(unsigned(response_xml())), now=NOW)
    assert r["ok"] and r["decoding"]["binding"] == "post"
    assert r["summary"]["assertions"][0]["name_id"]["value"] == "eve@globex.test"


def test_redirect_binding_from_full_url():
    authn = ('<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
             'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req1" Version="2.0" '
             'IssueInstant="2026-11-21T12:00:00Z" AssertionConsumerServiceURL="https://sp.example/acs">'
             '<saml:Issuer>https://sp.example</saml:Issuer></samlp:AuthnRequest>')
    url = f"https://idp.example/sso?SAMLRequest={quote(redirect_binding(authn))}&RelayState=abc&SigAlg=x"
    r = analyze(url)
    assert r["decoding"]["binding"] == "redirect" and r["decoding"]["relay_state"] == "abc"
    assert r["summary"]["type"] == "AuthnRequest"
    assert r["summary"]["request"]["acs_url"] == "https://sp.example/acs"


def test_url_encoded_value_and_raw_xml():
    xml = unsigned(response_xml())
    assert analyze(quote(post_binding(xml)))["ok"]
    assert analyze(xml)["decoding"]["binding"] == "raw-xml"


def test_garbage_is_reported_not_raised():
    r = analyze("definitely not saml !!!")
    assert r["ok"] is False and "decode" in r["error"]


# --- parser hardening ------------------------------------------------------------------

def test_xxe_and_entity_expansion_are_refused():
    xxe = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'
    r = analyze(post_binding(xxe))
    assert r["ok"] is False and r["refused"] and "DOCTYPE" in r["error"]
    bomb = '<!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><l>&b;</l>'
    assert analyze(bomb)["refused"]


# --- summary ---------------------------------------------------------------------------

def test_summary_extracts_the_important_facts():
    s = analyze(unsigned(response_xml()), now=NOW)["summary"]
    a = s["assertions"][0]
    assert s["type"] == "Response" and s["status"]["success"] and s["in_response_to"] == "_req1"
    assert a["conditions"]["audiences"] == ["https://sp.example"]
    assert a["attributes"]["groups"] == ["staff", "benefits"]
    assert a["authn"]["context"].endswith("PasswordProtectedTransport")


# --- signatures --------------------------------------------------------------------------

def test_valid_signature_verifies_with_the_right_certificate(idp):
    signed = sign_assertion(response_xml(), idp)
    r = analyze(post_binding(signed), cert=idp[1], now=NOW)
    check = r["verification"]["results"][0]
    assert check["valid"] and check["signed_element"] == "Assertion ID=_assert1"
    assert "signature-invalid" not in ids(r) and "unsigned" not in ids(r)
    assert r["signatures"][0]["embedded_certificate"]["key"] == "RSA 2048"


def test_wrong_certificate_fails(idp, other_idp):
    r = analyze(sign_assertion(response_xml(), idp), cert=other_idp[1], now=NOW)
    assert not r["verification"]["results"][0]["valid"]
    assert "signature-invalid" in ids(r)


def test_tampered_assertion_fails(idp):
    tampered = sign_assertion(response_xml(), idp).replace("eve@globex.test", "admin@globex.test", 1)
    r = analyze(tampered, cert=idp[1], now=NOW)
    assert not r["verification"]["results"][0]["valid"]


def test_trust_from_metadata(idp):
    body = "".join(idp[1].strip().splitlines()[1:-1])
    metadata = f"""<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example">
      <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data>
          <ds:X509Certificate>{body}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
      </md:IDPSSODescriptor></md:EntityDescriptor>"""
    r = analyze(sign_assertion(response_xml(), idp), metadata=metadata, now=NOW)
    assert r["verification"]["results"][0]["valid"]


# --- lint ----------------------------------------------------------------------------------

def test_unsigned_response_is_high_risk():
    r = analyze(unsigned(response_xml()), now=NOW)
    assert r["findings"][0]["id"] == "unsigned" and r["findings"][0]["severity"] == "high"


def test_signature_wrapping_is_flagged(idp):
    """XSW: attacker injects a forged assertion and keeps the genuine signed one."""
    signed = sign_assertion(response_xml(), idp)
    evil = unsigned(response_xml(name_id="admin@globex.test")).split("<saml:Assertion", 1)[1].rsplit("</samlp:Response>", 1)[0]
    wrapped = signed.replace("<samlp:Status>", "<saml:Assertion" + evil + "<samlp:Status>", 1)
    r = analyze(wrapped, cert=idp[1], now=NOW)
    assert {"multiple-assertions", "duplicate-ids"} <= ids(r)


def test_comment_injection_in_nameid_is_flagged():
    r = analyze(unsigned(response_xml(name_id="admin@victim.com<!---->.evil.com")), now=NOW)
    assert "comment-in-nameid" in ids(r)
    assert r["summary"]["assertions"][0]["name_id"]["value"] == "admin@victim.com.evil.com"


def test_sha1_is_flagged(idp):
    signed = sign_assertion(response_xml(), idp).replace("xmldsig-more#rsa-sha256", "xmldsig#rsa-sha1")
    assert "weak-signature-algorithm" in ids(analyze(signed, now=NOW))


def test_replay_hygiene_findings():
    r = analyze(unsigned(response_xml(audience=False, in_response_to=False, validity_minutes=600, recipient=False)), now=NOW)
    assert {"no-audience", "unsolicited", "long-validity", "no-recipient"} <= ids(r)


def test_expiry_is_relative_to_now():
    import datetime as dt
    later = NOW + dt.timedelta(hours=2)
    assert "expired" in ids(analyze(unsigned(response_xml()), now=later))
    assert "expired" not in ids(analyze(unsigned(response_xml()), now=NOW))


# --- CLI -----------------------------------------------------------------------------------

def test_cli_json_from_stdin_and_exit_code(tmp_path):
    p = subprocess.run([sys.executable, "-m", "samlscope.cli", "--json", "-"], input=post_binding(unsigned(response_xml())),
                       capture_output=True, text=True)
    assert p.returncode == 2, p.stderr            # high-severity finding -> exit 2 (useful in CI)
    assert json.loads(p.stdout)["summary"]["type"] == "Response"


def test_cli_text_report(idp, tmp_path):
    cert = tmp_path / "idp.pem"
    cert.write_text(idp[1])
    p = subprocess.run([sys.executable, "-m", "samlscope.cli", "--cert", str(cert), "--no-color", "-"],
                       input=sign_assertion(response_xml(), idp), capture_output=True, text=True)
    assert "eve@globex.test" in p.stdout and "VALID" in p.stdout


# --- certificate export ------------------------------------------------------------------

def _embedded(idp):
    from samlscope.certexport import unique_certificates
    r = analyze(sign_assertion(response_xml(), idp), now=NOW)
    certs = unique_certificates(r["signatures"])
    assert len(certs) == 1
    return certs[0]["certificate"]


def test_certificate_export_formats_round_trip(idp):
    from cryptography import x509
    from samlscope.certexport import export
    cert = _embedded(idp)
    original = x509.load_pem_x509_certificate(idp[1].encode())

    pem = export(cert, "pem")
    assert pem.startswith(b"-----BEGIN CERTIFICATE-----\n") and all(len(l) <= 64 for l in pem.splitlines())
    assert x509.load_pem_x509_certificate(pem) == original
    assert x509.load_der_x509_certificate(export(cert, "der")) == original
    one_line = export(cert, "b64").decode()
    assert one_line.count("\n") == 1 and " " not in one_line
    assert export(cert, "raw").decode() == cert["raw"]        # byte-for-byte as in the message


def test_raw_export_preserves_the_message_text_exactly():
    from samlscope.certexport import export
    weird = "MIIB\n  AAAA\n\tBBBB"
    assert export({"raw": weird, "base64": "MIIBAAAABBBB"}, "raw").decode() == weird


def test_same_certificate_on_response_and_assertion_is_offered_once():
    from samlscope.certexport import unique_certificates
    sig = {"on": "Response", "on_id": "_r", "embedded_certificate": {"base64": "AAAA", "raw": "AAAA"}}
    assert len(unique_certificates([sig, {**sig, "on": "Assertion", "on_id": "_a"}])) == 1


def test_garbage_certificate_only_exports_raw():
    import pytest
    from samlscope.certexport import ExportError, export
    bad = {"raw": "not base64 !!", "base64": "notbase64!!"}
    assert export(bad, "raw") == b"not base64 !!"
    with pytest.raises(ExportError):
        export(bad, "pem")


def test_cli_exports_certificates(idp, tmp_path):
    from cryptography import x509
    signed = sign_assertion(response_xml(), idp)
    p = subprocess.run([sys.executable, "-m", "samlscope.cli", "--certs", "pem", "-"], input=signed,
                       capture_output=True, text=True)
    assert p.returncode == 0 and x509.load_pem_x509_certificate(p.stdout.encode())
    assert "untrusted" in p.stderr
    p = subprocess.run([sys.executable, "-m", "samlscope.cli", "--certs", "der", "--certs-out", str(tmp_path), "-"],
                       input=signed, capture_output=True, text=True)
    files = list(tmp_path.glob("*.cer"))
    assert p.returncode == 0 and len(files) == 1 and files[0].name.startswith("Test-IdP-signing-")
