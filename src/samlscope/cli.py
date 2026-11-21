"""samlscope command line.

  samlscope [INPUT]   decode a message: file path, '-' for stdin (default), or the value itself
  samlscope-gui       desktop app (Windows, Linux)

Exit codes: 0 = no high findings, 1 = could not decode / refused, 2 = high-severity finding or invalid signature.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .analyze import analyze

SEV_COLOR = {"high": "31;1", "medium": "33;1", "low": "36", "info": "2"}


def _read(arg: str | None) -> str:
    if arg in (None, "-"):
        return sys.stdin.read()
    p = Path(arg)
    if len(arg) < 4096 and p.is_file():
        return p.read_text()
    return arg


def _fmt(color: bool):
    def c(code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if color else text
    return c


def report(r: dict, color: bool, show_xml: bool) -> str:
    c = _fmt(color)
    lines: list[str] = []
    if not r["ok"]:
        return c("31;1", "REFUSED: " if r.get("refused") else "ERROR: ") + r["error"]
    s, d = r["summary"], r["decoding"]
    lines.append(c("1", f"{s['type']}") + f"  ({d['binding']} binding: {', '.join(d['steps'])})")
    for label, value in [("Issuer", s["issuer"]), ("ID", s["id"]), ("Issued", s["issue_instant"]),
                         ("Destination", s["destination"]), ("InResponseTo", s["in_response_to"]),
                         ("RelayState", d.get("relay_state"))]:
        if value:
            lines.append(f"  {label:<14}{value}")
    if s.get("status"):
        st = s["status"]
        lines.append(f"  {'Status':<14}{'/'.join(st['codes'])}" + (f" ({st['message']})" if st["message"] else ""))
    if s.get("request"):
        for k, v in s["request"].items():
            if v:
                lines.append(f"  {k.replace('_', ' ').capitalize():<14}{v}")
    for i, a in enumerate(s["assertions"], 1):
        lines.append(c("1", f"\nAssertion {i}") + f"  ID={a['id']}")
        lines.append(f"  {'Subject':<14}{a['name_id']['value']}  [{a['name_id']['format']}]")
        cond = a["conditions"]
        lines.append(f"  {'Valid':<14}{cond['not_before']} → {cond['not_on_or_after']}")
        lines.append(f"  {'Audience':<14}{', '.join(cond['audiences']) or '(none)'}")
        if a["authn"]["context"]:
            lines.append(f"  {'AuthnContext':<14}{a['authn']['context'].rsplit(':', 1)[-1]}")
        for name, values in a["attributes"].items():
            lines.append(f"  {'@' + name:<14}{', '.join(values)}")
    if s["encrypted_assertions"]:
        lines.append(f"\n{s['encrypted_assertions']} encrypted assertion(s) (not decrypted)")

    lines.append(c("1", "\nSignatures"))
    if not r["signatures"]:
        lines.append("  (none)")
    for sig in r["signatures"]:
        cert = sig.get("embedded_certificate") or {}
        lines.append(f"  on {sig['on']} {sig['on_id']}: {sig['signature_algorithm']} / {', '.join(sig['digest_algorithms'])}"
                     + (f"  cert: {cert.get('subject')} ({cert.get('key')}, until {cert.get('not_after', '')[:10]})" if cert else ""))
    if r["verification"]:
        v = r["verification"]
        if v.get("error"):
            lines.append(c("31", f"  verification: {v['error']}"))
        for res in v.get("results", []):
            status = c("32;1", "VALID") if res["valid"] else c("31;1", "INVALID")
            lines.append(f"  {status} signature on {res['on']} {res['on_id']}"
                         + (f": signed content is {res['signed_element']}" if res["valid"] else f": {res['error']}"))
    else:
        lines.append(c("2", "  not verified (pass --cert idp.pem or --metadata idp-metadata.xml)"))

    lines.append(c("1", "\nFindings"))
    if not r["findings"]:
        lines.append("  none")
    for f in r["findings"]:
        lines.append("  " + c(SEV_COLOR[f["severity"]], f"[{f['severity'].upper()}]") + f" {f['title']}")
        lines.append(c("2", f"      {f['detail']}"))
    if show_xml:
        lines.append(c("1", "\nXML") + "\n" + r["xml"])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    p = argparse.ArgumentParser(prog="samlscope", description="Decode, verify and lint SAML messages locally.")
    p.add_argument("input", nargs="?", default="-", help="file, '-' for stdin, or the encoded value itself")
    p.add_argument("--cert", help="trusted IdP/SP signing certificate (PEM)")
    p.add_argument("--metadata", help="trusted SAML metadata (XML); its signing keys are used")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--xml", action="store_true", help="also print the pretty-printed XML")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"samlscope {__version__}")
    args = p.parse_args(argv)

    r = analyze(_read(args.input),
                cert=Path(args.cert).read_text() if args.cert else None,
                metadata=Path(args.metadata).read_text() if args.metadata else None)
    if args.json:
        print(json.dumps(r, indent=2))
    else:
        color = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        print(report(r, color, args.xml))
    if not r["ok"]:
        return 1
    return 2 if any(f["severity"] == "high" for f in r["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
