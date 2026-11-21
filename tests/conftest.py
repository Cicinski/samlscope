"""Builds real, signed SAML messages for the tests (throwaway keys, generated per test session)."""
from __future__ import annotations

import base64
import datetime as dt
import zlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner

SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
NOW = dt.datetime(2026, 11, 21, 12, 0, tzinfo=dt.timezone.utc)


def _keypair(cn: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - dt.timedelta(days=1)).not_valid_after(NOW + dt.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return key_pem, cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture(scope="session")
def idp():
    return _keypair("Test IdP signing")


@pytest.fixture(scope="session")
def other_idp():
    return _keypair("Some other IdP")


def iso(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def response_xml(name_id: str = "eve@globex.test", audience: bool = True, in_response_to: bool = True,
                 validity_minutes: int = 5, recipient: bool = True) -> str:
    nb, na = iso(NOW - dt.timedelta(minutes=1)), iso(NOW + dt.timedelta(minutes=validity_minutes))
    irt = ' InResponseTo="_req1"' if in_response_to else ""
    rcp = ' Recipient="https://sp.example/acs"' if recipient else ""
    aud = ("<saml:AudienceRestriction><saml:Audience>https://sp.example</saml:Audience></saml:AudienceRestriction>"
           if audience else "")
    return f"""<samlp:Response xmlns:samlp="{SAMLP}" xmlns:saml="{SAML}" ID="_resp1" Version="2.0"
 IssueInstant="{iso(NOW)}" Destination="https://sp.example/acs"{irt}>
 <saml:Issuer>https://idp.example</saml:Issuer>
 <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
 <saml:Assertion ID="_assert1" Version="2.0" IssueInstant="{iso(NOW)}">
  <saml:Issuer>https://idp.example</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="placeholder"/>
  <saml:Subject>
   <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>
   <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
    <saml:SubjectConfirmationData NotOnOrAfter="{na}"{rcp}{irt}/>
   </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="{nb}" NotOnOrAfter="{na}">{aud}</saml:Conditions>
  <saml:AuthnStatement AuthnInstant="{iso(NOW)}" SessionIndex="s1">
   <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
  </saml:AuthnStatement>
  <saml:AttributeStatement>
   <saml:Attribute Name="email"><saml:AttributeValue>{name_id}</saml:AttributeValue></saml:Attribute>
   <saml:Attribute Name="groups"><saml:AttributeValue>staff</saml:AttributeValue><saml:AttributeValue>benefits</saml:AttributeValue></saml:Attribute>
  </saml:AttributeStatement>
 </saml:Assertion>
</samlp:Response>"""


def sign_assertion(xml: str, keypair) -> str:
    key_pem, cert_pem = keypair
    root = etree.fromstring(xml.encode())
    assertion = root.find(f"{{{SAML}}}Assertion")
    signed = XMLSigner(signature_algorithm="rsa-sha256", digest_algorithm="sha256",
                       c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#").sign(
        assertion, key=key_pem, cert=cert_pem, reference_uri=assertion.get("ID"))
    root.replace(assertion, signed)
    return etree.tostring(root).decode()


def unsigned(xml: str) -> str:
    return xml.replace('<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="placeholder"/>', "")


def post_binding(xml: str) -> str:
    return base64.b64encode(xml.encode()).decode()


def redirect_binding(xml: str) -> str:
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return base64.b64encode(c.compress(xml.encode()) + c.flush()).decode()
