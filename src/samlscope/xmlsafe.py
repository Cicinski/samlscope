"""Hardened XML parsing. SAML never needs a DTD, so any DOCTYPE is refused outright
(blocks XXE, entity expansion / billion laughs, and external DTD fetches)."""
from __future__ import annotations

import re

from lxml import etree

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xenc": "http://www.w3.org/2001/04/xmlenc#",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
}

_DOCTYPE = re.compile(rb"<!DOCTYPE|<!ENTITY", re.IGNORECASE)


class UnsafeXML(ValueError):
    pass


def parser() -> etree.XMLParser:
    return etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, dtd_validation=False,
                           huge_tree=False, remove_comments=False, remove_pis=False)


def parse(xml: bytes) -> etree._Element:
    if _DOCTYPE.search(xml):
        raise UnsafeXML("DOCTYPE/ENTITY declarations are not allowed in SAML (possible XXE or entity-expansion attack)")
    try:
        root = etree.fromstring(xml, parser=parser())
    except etree.XMLSyntaxError as e:
        raise UnsafeXML(f"not well-formed XML: {e}") from e
    if root.getroottree().docinfo.doctype:
        raise UnsafeXML("DOCTYPE is not allowed in SAML")
    return root


def local(el: etree._Element) -> str:
    return etree.QName(el).localname


def pretty(el: etree._Element) -> str:
    import copy
    clone = copy.deepcopy(el)
    etree.indent(clone, space="  ")
    return etree.tostring(clone, pretty_print=True, encoding="unicode")
