"""samlscope desktop app (Windows, Linux). Qt for Python (PySide6).

Privacy and safety:
  - no network access: nothing is uploaded; trust material is loaded only from files you choose
  - SAML content is untrusted: it is shown only through plain-text widgets (never rich text / HTML)
  - nothing is written to disk unless you explicitly export a report
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QColor, QFont, QFontDatabase, QKeySequence
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QHBoxLayout, QLabel, QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QPushButton,
    QSplitter, QTabWidget, QToolButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from . import __version__
from .analyze import analyze
from .certexport import FORMATS, ExportError, export, suggested_filename, unique_certificates

SEVERITY_COLORS = {"high": "#d92d20", "medium": "#c4730a", "low": "#2e78c7", "info": "#7a8494"}
MAX_FILE = 5 * 1024 * 1024


def _mono() -> QFont:
    f = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
    f.setPointSize(max(f.pointSize(), 10))
    return f


def _plain_label(text: str = "") -> QLabel:
    label = QLabel(text)
    label.setTextFormat(Qt.TextFormat.PlainText)      # never interpret HTML
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    label.setWordWrap(True)
    return label


def _tree(headers: list[str]) -> QTreeWidget:
    t = QTreeWidget()
    t.setHeaderLabels(headers)
    t.setAlternatingRowColors(True)
    t.setUniformRowHeights(False)
    t.setWordWrap(True)
    return t


def _item(parent, *cols) -> QTreeWidgetItem:
    it = QTreeWidgetItem(parent, ["" if c is None else str(c) for c in cols])   # QTreeWidgetItem text is plain
    for i, c in enumerate(cols):
        it.setToolTip(i, "" if c is None else str(c)[:2000])
    return it


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("samlscope: local SAML decoder")
        self.resize(1180, 820)
        self.setAcceptDrops(True)
        self.cert_text: str | None = None
        self.metadata_text: str | None = None
        self.result: dict | None = None

        # --- input -----------------------------------------------------------------
        self.input = QPlainTextEdit()
        self.input.setFont(_mono())
        self.input.setPlaceholderText("Paste a SAMLRequest / SAMLResponse: base64, a redirect URL, a form body, or raw XML.\n"
                                      "Or drop a file here. Ctrl+Enter to analyse.")
        self.input.setTabChangesFocus(True)

        analyse = QPushButton("Analyse")
        analyse.setDefault(True)
        analyse.clicked.connect(self.run)
        paste = QPushButton("Paste")
        paste.clicked.connect(lambda: self.input.setPlainText(QApplication.clipboard().text()))
        clear = QPushButton("Clear")
        clear.clicked.connect(self.clear)
        self.trust_label = _plain_label("Signatures: not verified (no trusted certificate loaded)")
        load_cert = QPushButton("Trust certificate…")
        load_cert.clicked.connect(self.load_cert)
        load_md = QPushButton("Trust metadata…")
        load_md.clicked.connect(self.load_metadata)

        buttons = QHBoxLayout()
        for b in (analyse, paste, clear):
            buttons.addWidget(b)
        buttons.addStretch(1)
        buttons.addWidget(load_cert)
        buttons.addWidget(load_md)

        top = QWidget()
        tl = QVBoxLayout(top)
        tl.setContentsMargins(0, 0, 0, 0)
        tl.addWidget(self.input)
        tl.addLayout(buttons)
        tl.addWidget(self.trust_label)

        # --- results -------------------------------------------------------------------
        self.findings = _tree(["Severity", "Finding", "Detail"])
        self.findings.setColumnWidth(0, 90)
        self.findings.setColumnWidth(1, 360)
        self.summary = _tree(["Field", "Value"])
        self.summary.setColumnWidth(0, 230)
        self.signatures = _tree(["Signature", "Details"])
        self.signatures.setColumnWidth(0, 320)
        self.xml = QPlainTextEdit()
        self.xml.setReadOnly(True)
        self.xml.setFont(_mono())
        self.xml.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

        self.signatures.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.signatures.customContextMenuRequested.connect(self._signature_menu)
        self.signatures.itemSelectionChanged.connect(self._update_cert_buttons)

        self.copy_cert_btn = QToolButton()
        self.copy_cert_btn.setText("Copy certificate")
        self.copy_cert_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.copy_cert_btn.setMenu(self._copy_menu(self))
        self.save_cert_btn = QPushButton("Save certificate…")
        self.save_cert_btn.clicked.connect(lambda: self.save_certificate())
        self.cert_hint = _plain_label("")
        cert_bar = QHBoxLayout()
        cert_bar.addWidget(self.copy_cert_btn)
        cert_bar.addWidget(self.save_cert_btn)
        cert_bar.addWidget(self.cert_hint, 1)
        sig_tab = QWidget()
        sl = QVBoxLayout(sig_tab)
        sl.setContentsMargins(0, 4, 0, 0)
        sl.addLayout(cert_bar)
        sl.addWidget(self.signatures)
        self._update_cert_buttons()

        self.tabs = QTabWidget()
        self.tabs.addTab(self.findings, "Findings")
        self.tabs.addTab(self.summary, "Summary")
        self.tabs.addTab(sig_tab, "Signatures")
        self.tabs.addTab(self.xml, "XML")

        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(top)
        split.addWidget(self.tabs)
        split.setSizes([260, 560])
        self.setCentralWidget(split)
        self.statusBar().showMessage("Ready. Nothing leaves this computer.")
        self._menus()

    # --- menus ------------------------------------------------------------------------------
    def _menus(self) -> None:
        file_menu = self.menuBar().addMenu("&File")
        for text, slot, key in [("&Open message…", self.open_message, QKeySequence.StandardKey.Open),
                                ("Trust &certificate…", self.load_cert, None),
                                ("Trust &metadata…", self.load_metadata, None),
                                ("&Export report (JSON)…", self.export, QKeySequence.StandardKey.Save),
                                ("Export ce&rtificate…", lambda: self.save_certificate(), None),
                                (None, None, None),
                                ("&Quit", self.close, QKeySequence.StandardKey.Quit)]:
            if text is None:
                file_menu.addSeparator()
                continue
            a = QAction(text, self)
            a.triggered.connect(slot)
            if key is not None:
                a.setShortcut(key)
            file_menu.addAction(a)
        run = QAction("Analyse", self)
        run.setShortcuts([QKeySequence("Ctrl+Return"), QKeySequence("Ctrl+Enter")])
        run.triggered.connect(self.run)
        self.addAction(run)
        about = QAction("&About", self)
        about.triggered.connect(self.about)
        self.menuBar().addMenu("&Help").addAction(about)

    # --- file handling -------------------------------------------------------------------------
    @staticmethod
    def _read_file(path: str) -> str:
        p = Path(path)
        if p.stat().st_size > MAX_FILE:
            raise ValueError("file is larger than 5 MiB")
        return p.read_text(errors="replace")

    def open_message(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open SAML message", "", "All files (*)")
        if path:
            self.input.setPlainText(self._read_file(path))
            self.run()

    def load_cert(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Trusted signing certificate", "", "Certificates (*.pem *.crt *.cer);;All files (*)")
        if path:
            self.cert_text, self.metadata_text = self._read_file(path), None
            self.trust_label.setText(f"Signatures: verified against certificate {Path(path).name}")
            self.run()

    def load_metadata(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Trusted SAML metadata", "", "XML (*.xml);;All files (*)")
        if path:
            self.metadata_text, self.cert_text = self._read_file(path), None
            self.trust_label.setText(f"Signatures: verified against metadata {Path(path).name}")
            self.run()

    def export(self) -> None:
        if not self.result:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export report", "samlscope-report.json", "JSON (*.json)")
        if path:
            Path(path).write_text(json.dumps(self.result, indent=2))
            self.statusBar().showMessage(f"Report saved to {path} (it contains the decoded message: handle with care)")

    # --- certificate export --------------------------------------------------------------------
    def _certificates(self) -> list[dict]:
        return unique_certificates(self.result["signatures"]) if self.result and self.result.get("ok") else []

    def selected_certificate(self) -> dict | None:
        """The certificate of the selected signature, or the only one in the message."""
        item = self.signatures.currentItem()
        while item is not None and item.parent() is not None:
            item = item.parent()
        if item is not None and item.data(0, Qt.ItemDataRole.UserRole) is not None:
            sig = self.result["signatures"][item.data(0, Qt.ItemDataRole.UserRole)]
            if sig.get("embedded_certificate"):
                return sig["embedded_certificate"]
        certs = self._certificates()
        return certs[0]["certificate"] if len(certs) == 1 else None

    def _update_cert_buttons(self) -> None:
        certs = self._certificates()
        cert = self.selected_certificate() if certs else None
        for w in (self.copy_cert_btn, self.save_cert_btn):
            w.setEnabled(cert is not None)
        if not certs:
            self.cert_hint.setText("No certificate embedded in this message." if self.result else "")
        elif cert is None:
            self.cert_hint.setText(f"{len(certs)} different certificates: select a signature first.")
        else:
            self.cert_hint.setText(f"{cert.get('subject')} · SHA-256 {str(cert.get('sha256_fingerprint'))[:23]}…  "
                                   "(untrusted: compare with the IdP's metadata)")

    def _copy_menu(self, parent) -> QMenu:
        menu = QMenu(parent)
        for fmt in ("pem", "b64", "raw"):
            menu.addAction(f"Copy as {FORMATS[fmt]['label']}", lambda f=fmt: self.copy_certificate(f))
        return menu

    def _signature_menu(self, pos) -> None:
        if self.selected_certificate() is None:
            return
        menu = self._copy_menu(self.signatures)
        menu.addSeparator()
        menu.addAction("Save certificate…", lambda: self.save_certificate())
        menu.exec(self.signatures.viewport().mapToGlobal(pos))

    def copy_certificate(self, fmt: str) -> None:
        cert = self.selected_certificate()
        if cert is None:
            return
        try:
            QApplication.clipboard().setText(export(cert, fmt).decode())
        except ExportError as e:
            QMessageBox.warning(self, "Cannot export", str(e))
            return
        self.statusBar().showMessage(f"Copied certificate ({FORMATS[fmt]['label']}): {cert.get('subject')}")

    def save_certificate(self, path: str | None = None, fmt: str | None = None) -> str | None:
        cert = self.selected_certificate()
        if cert is None:
            if self._certificates():
                QMessageBox.information(self, "Select a signature", "This message contains several certificates. "
                                        "Select a signature on the Signatures tab first.")
            return None
        if path is None:
            filters = {f"{FORMATS[f]['label']} (*{FORMATS[f]['ext']})": f for f in ("pem", "der", "b64", "raw")}
            path, chosen = QFileDialog.getSaveFileName(self, "Save certificate", suggested_filename(cert, "pem"),
                                                       ";;".join(filters))
            if not path:
                return None
            fmt = filters.get(chosen, "pem")
        try:
            Path(path).write_bytes(export(cert, fmt or "pem"))
        except ExportError as e:
            QMessageBox.warning(self, "Cannot export", str(e))
            return None
        self.statusBar().showMessage(f"Certificate saved as {FORMATS[fmt or 'pem']['label']}: {path}")
        return path

    def dragEnterEvent(self, e) -> None:  # noqa: N802 - Qt API
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e) -> None:  # noqa: N802
        urls = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
        if urls:
            self.input.setPlainText(self._read_file(urls[0]))
            self.run()

    def clear(self) -> None:
        self.input.clear()
        for w in (self.findings, self.summary, self.signatures):
            w.clear()
        self.xml.clear()
        self.result = None
        self._update_cert_buttons()
        self.statusBar().showMessage("Cleared.")

    def about(self) -> None:
        box = QMessageBox(self)
        box.setWindowTitle("About samlscope")
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(f"samlscope {__version__}\n\nDecode, verify and security-check SAML messages locally.\n"
                    "No network access. Nothing is uploaded or stored.\n\nCopyright (c) 2026 Grecu Cosmin\nLicensed under the GNU GPL v3 or later.")
        box.exec()

    # --- analysis ----------------------------------------------------------------------------------
    def run(self) -> None:
        text = self.input.toPlainText()
        if not text.strip():
            return
        self.result = analyze(text, cert=self.cert_text, metadata=self.metadata_text)
        self.show_result(self.result)
        self._update_cert_buttons()

    def show_result(self, r: dict) -> None:
        for w in (self.findings, self.summary, self.signatures):
            w.clear()
        self.xml.clear()
        if not r["ok"]:
            it = _item(self.findings, "ERROR", "Refused" if r.get("refused") else "Could not analyse", r["error"])
            it.setForeground(0, QColor(SEVERITY_COLORS["high"]))
            self.tabs.setCurrentWidget(self.findings)
            self.statusBar().showMessage(r["error"])
            return

        # findings
        for f in r["findings"]:
            it = _item(self.findings, f["severity"].upper(), f["title"], f["detail"])
            it.setForeground(0, QColor(SEVERITY_COLORS[f["severity"]]))
            bold = it.font(0)
            bold.setBold(True)
            it.setFont(0, bold)
        if not r["findings"]:
            _item(self.findings, "", "No findings", "")

        # summary
        s, d = r["summary"], r["decoding"]
        msg = _item(self.summary, s["type"], f"{d['binding']} binding: {', '.join(d['steps'])}")
        for k in ("issuer", "id", "issue_instant", "destination", "in_response_to"):
            if s.get(k):
                _item(msg, k.replace("_", " ").title(), s[k])
        if d.get("relay_state"):
            _item(msg, "RelayState", d["relay_state"])
        if s.get("status"):
            st = s["status"]
            _item(msg, "Status", "/".join(st["codes"]) + (f" ({st['message']})" if st["message"] else ""))
        for k, v in (s.get("request") or {}).items():
            if v:
                _item(msg, k.replace("_", " ").title(), ", ".join(v) if isinstance(v, list) else v)
        for i, a in enumerate(s["assertions"], 1):
            node = _item(self.summary, f"Assertion {i}", a["id"])
            _item(node, "Subject", f"{a['name_id']['value']}  [{a['name_id']['format']}]")
            _item(node, "Issuer", a["issuer"])
            _item(node, "Valid", f"{a['conditions']['not_before']} → {a['conditions']['not_on_or_after']}")
            _item(node, "Audience", ", ".join(a["conditions"]["audiences"]) or "(none)")
            for c in a["subject_confirmations"]:
                _item(node, "Confirmation", f"{c['method']} · recipient {c['recipient']} · until {c['not_on_or_after']}")
            _item(node, "AuthnContext", a["authn"]["context"])
            _item(node, "Session index", a["authn"]["session_index"])
            attrs = _item(node, "Attributes", str(len(a["attributes"])))
            for name, values in a["attributes"].items():
                _item(attrs, name, ", ".join(values))
        if s["encrypted_assertions"]:
            _item(self.summary, "Encrypted assertions", f"{s['encrypted_assertions']} (not decrypted)")
        self.summary.expandAll()

        # signatures
        for index, g in enumerate(r["signatures"]):
            node = _item(self.signatures, f"on {g['on']} {g['on_id'] or ''}",
                         f"{g['signature_algorithm']} / {', '.join(g['digest_algorithms'])}")
            node.setData(0, Qt.ItemDataRole.UserRole, index)
            _item(node, "References", ", ".join(g["references"]))
            cert = g.get("embedded_certificate") or {}
            for k in ("subject", "issuer", "key", "not_before", "not_after", "sha256_fingerprint"):
                if cert.get(k):
                    _item(node, f"Certificate {k.replace('_', ' ')}", cert[k])
        v = r.get("verification")
        valid = invalid = 0
        if v and v.get("results"):
            for res in v["results"]:
                ok = res["valid"]
                valid, invalid = valid + ok, invalid + (not ok)
                it = _item(self.signatures, "VALID" if ok else "INVALID",
                           f"signature on {res['on']} {res['on_id'] or ''}: "
                           + (f"signed content is {res['signed_element']}" if ok else res["error"]))
                it.setForeground(0, QColor("#1f7a4c" if ok else SEVERITY_COLORS["high"]))
        elif v and v.get("error"):
            _item(self.signatures, "ERROR", v["error"])
        elif r["signatures"]:
            _item(self.signatures, "Not verified", "Load the IdP certificate or metadata to check signatures.")
        if not r["signatures"]:
            _item(self.signatures, "No signatures", "")
        self.signatures.expandAll()

        self.xml.setPlainText(r["xml"])
        counts = {sev: sum(f["severity"] == sev for f in r["findings"]) for sev in ("high", "medium", "low")}
        sig_text = f"{valid} valid, {invalid} invalid" if v and v.get("results") else "not verified"
        self.statusBar().showMessage(f"{s['type']} · findings: {counts['high']} high, {counts['medium']} medium, "
                                     f"{counts['low']} low · signatures: {sig_text}")
        self.tabs.setCurrentWidget(self.findings)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv if argv is None else argv
    app = QApplication(argv)
    app.setApplicationName("samlscope")
    app.setApplicationVersion(__version__)
    w = MainWindow()
    if "--smoke-test" in argv:      # used by packaging CI: start, analyse a sample, exit
        w.input.setPlainText("<samlp:AuthnRequest xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' ID='_x' Version='2.0'/>")
        w.run()
        ok = bool(w.result and w.result.get("ok") and w.result["summary"]["type"] == "AuthnRequest")
        if sys.stdout is not None:      # a windowed Windows build has no stdout: rely on the exit code
            print("smoke test", "ok" if ok else "FAILED")
        return 0 if ok else 1
    w.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
