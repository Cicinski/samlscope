"""Turn whatever the user pasted into SAML XML bytes.

Accepted input:
  - raw XML
  - base64 (HTTP-POST binding), optionally URL-encoded
  - base64 + raw DEFLATE (HTTP-Redirect binding)
  - a full URL or query string containing SAMLRequest= / SAMLResponse=
  - a form body (SAMLResponse=...&RelayState=...)
"""
from __future__ import annotations

import base64
import binascii
import re
import zlib
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlsplit

MAX_INPUT = 2 * 1024 * 1024        # 2 MiB of text is far beyond any real SAML message
MAX_INFLATED = 5 * 1024 * 1024     # guard against DEFLATE bombs


class DecodeError(ValueError):
    pass


@dataclass
class Decoded:
    xml: bytes
    binding: str                    # "raw-xml" | "post" | "redirect"
    parameter: str | None = None    # "SAMLRequest" | "SAMLResponse"
    steps: list[str] = field(default_factory=list)
    relay_state: str | None = None
    redirect_sig_alg: str | None = None
    redirect_signature_present: bool = False


def _b64(text: str) -> bytes:
    cleaned = re.sub(r"\s+", "", text)
    cleaned = cleaned.replace("-", "+").replace("_", "/")   # tolerate base64url
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        return base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError) as e:
        raise DecodeError(f"not valid base64: {e}") from e


def _inflate(data: bytes) -> bytes:
    d = zlib.decompressobj(-15)
    out = d.decompress(data, MAX_INFLATED)
    if d.unconsumed_tail:
        raise DecodeError("inflated message exceeds the size limit (possible DEFLATE bomb)")
    return out


def _looks_like_xml(data: bytes) -> bool:
    return data.lstrip()[:1] == b"<"


def _from_param(value: str, parameter: str, steps: list[str]) -> tuple[bytes, str]:
    raw = _b64(value)
    steps.append("base64 decoded")
    if _looks_like_xml(raw):
        return raw, "post"
    try:
        xml = _inflate(raw)
    except zlib.error as e:
        raise DecodeError(f"{parameter}: decoded bytes are neither XML nor DEFLATE data") from e
    steps.append("DEFLATE inflated")
    if not _looks_like_xml(xml):
        raise DecodeError(f"{parameter}: inflated data is not XML")
    return xml, "redirect"


def decode(text: str) -> Decoded:
    if len(text) > MAX_INPUT:
        raise DecodeError("input too large")
    text = text.strip()
    if not text:
        raise DecodeError("empty input")

    if text.startswith("<"):
        return Decoded(text.encode(), "raw-xml", steps=["raw XML"])

    # URL, query string or form body carrying SAML parameters
    if "SAMLRequest=" in text or "SAMLResponse=" in text:
        query = urlsplit(text).query if "://" in text else text.lstrip("?")
        params = {k: v[0] for k, v in parse_qs(query, keep_blank_values=True).items()}
        parameter = "SAMLResponse" if "SAMLResponse" in params else "SAMLRequest"
        steps = [f"extracted {parameter} from query/form", "URL decoded"]
        xml, binding = _from_param(params[parameter], parameter, steps)
        return Decoded(xml, binding, parameter, steps, params.get("RelayState"),
                       params.get("SigAlg"), "Signature" in params)

    # A bare value: maybe still URL-encoded
    steps = []
    if "%" in text:
        text = unquote(text)
        steps.append("URL decoded")
    xml, binding = _from_param(text, "input", steps)
    return Decoded(xml, binding, None, steps)
