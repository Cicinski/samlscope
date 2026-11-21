"""Desktop app tests (run headless with QT_QPA_PLATFORM=offscreen)."""
from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QLabel  # noqa: E402

from samlscope.gui import MainWindow  # noqa: E402
from tests.conftest import post_binding, response_xml, sign_assertion, unsigned  # noqa: E402


@pytest.fixture
def window(qtbot):
    w = MainWindow()
    qtbot.addWidget(w)
    return w


def top_level_texts(tree, col=1):
    return [tree.topLevelItem(i).text(col) for i in range(tree.topLevelItemCount())]


def test_unsigned_response_shows_high_finding(window):
    window.input.setPlainText(post_binding(unsigned(response_xml())))
    window.run()
    first = window.findings.topLevelItem(0)
    assert first.text(0) == "HIGH" and "Neither the Response nor the Assertion is signed" in first.text(1)
    assert "1 high" in window.statusBar().currentMessage()
    assert "eve@globex.test" in window.xml.toPlainText()


def test_signature_verification_with_trusted_certificate(window, idp):
    window.cert_text = idp[1]
    window.input.setPlainText(sign_assertion(response_xml(), idp))
    window.run()
    verdicts = top_level_texts(window.signatures, col=0)
    assert "VALID" in verdicts and "INVALID" not in verdicts
    assert "1 valid, 0 invalid" in window.statusBar().currentMessage()


def test_xxe_is_refused_in_the_ui(window):
    window.input.setPlainText('<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>')
    window.run()
    item = window.findings.topLevelItem(0)
    assert item.text(0) == "ERROR" and "DOCTYPE" in item.text(2)


def test_untrusted_content_is_never_rendered_as_rich_text(window):
    """A NameID containing markup must show as literal text."""
    window.input.setPlainText(unsigned(response_xml(name_id="&lt;b&gt;pwn&lt;/b&gt;@evil.test")))
    window.run()
    for label in window.findChildren(QLabel):
        assert label.textFormat().name == "PlainText"
    subject = window.summary.topLevelItem(1).child(0).text(1)
    assert subject.startswith("<b>pwn</b>@evil.test")


def test_clear_wipes_everything(window):
    window.input.setPlainText(post_binding(unsigned(response_xml())))
    window.run()
    window.clear()
    assert window.input.toPlainText() == "" and window.findings.topLevelItemCount() == 0 and window.result is None
