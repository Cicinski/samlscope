# PyInstaller spec for the samlscope desktop app (Windows and Linux).
# -*- mode: python -*-
import sys

a = Analysis(
    ["samlscope_gui.py"],
    excludes=["tkinter", "PySide6.QtNetwork", "PySide6.QtWebEngineCore", "PySide6.QtQml", "PySide6.QtQuick"],
)
if sys.platform.startswith("linux"):
    # Use the desktop's own fontconfig/freetype: a bundled older fontconfig cannot read newer
    # system font configuration and floods the terminal with warnings.
    a.binaries = [b for b in a.binaries if not b[0].startswith(("libfontconfig", "libfreetype"))]

pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="samlscope",
    console=False,          # windowed app (no terminal window on Windows)
    upx=False,
    strip=False,
)
