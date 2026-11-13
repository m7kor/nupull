#!/usr/bin/env python3
"""NUP GUI — a modern desktop front-end for the nup container tool (PyQt6).

Run:    py -3.12 nup_gui.py
Smoke:  py -3.12 nup_gui.py --smoke [--file x.nup]
Auto:   py -3.12 nup_gui.py --smoke --auto <dump dir>

Nupull Studio front-end with a one-shot AUTO pipeline: drop a dump
folder, get a verified .nup (scan -> pack -> verify -> done) with live
tracking (files, bytes, speed, ETA) and a Cancel button that stops at the
next file boundary. Containers are written atomically (.partial + rename):
a crash or cancelled run never leaves a corrupt output, and a confirmed
replacement keeps the old file until the new one is complete. Advanced
pages (info, extract, verify, edit, pack) remain available. Heavy work
runs on background jobs; only one job runs at a time.
"""

from __future__ import annotations

import argparse
import html
import os
from pathlib import Path
import shutil
import sys
import threading
import time
import traceback
from collections import deque
from datetime import datetime

# ---- dependencies ----------------------------------------------------------

try:
    from PyQt6.QtCore import Qt, QThread, QSettings, QTimer, QSize, \
        QPointF, QRectF, pyqtSignal
    from PyQt6.QtGui import QColor, QFont, QFontDatabase, QPainter, \
        QPainterPath, QPen, QIcon, QBrush, QPolygonF, QPixmap
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
        QStackedWidget, QLabel, QPushButton, QLineEdit, QComboBox, QSpinBox,
        QCheckBox, QPlainTextEdit, QProgressBar, QTableWidget, QTableWidgetItem,
        QTreeWidget, QTreeWidgetItem, QFileDialog, QMessageBox, QGroupBox,
        QFormLayout, QHeaderView, QAbstractItemView, QStyle, QFrame,
        QRadioButton, QButtonGroup,
    )
except ImportError as e:  # pragma: no cover
    sys.exit(f"PyQt6 is not installed ({e}) — run: py -3.12 -m pip install pyqt6")

# Ensure local tools/nup is in sys.path when running from source or repo clone
_tools_nup = Path(__file__).resolve().parent / "tools" / "nup"
if _tools_nup.is_dir() and str(_tools_nup) not in sys.path:
    sys.path.insert(0, str(_tools_nup))

try:
    from nup import format as F
    from nup.access import app_meta, build_id, extract_tree, iter_children, \
        resolve_path
    from nup.discover import scan_source
    from nup.edit import edit as nup_edit
    from nup.pack import pack as nup_pack
    from nup.read import NupReader
    from nup.verify import verify as nup_verify
except ImportError as e:  # pragma: no cover
    sys.exit(f"nup package is not installed ({e}) — run: "
             "py -3.12 -m pip install ./tools/nup")

KIND_LABEL = {
    F.KIND_BASE: "base",
    F.KIND_UPDATE: "update",
    F.KIND_ADDON: "addon (DLC)",
    F.KIND_ADDON_UPDATE: "addon+update",
    F.KIND_SYSTEM: "system",
}

ROLE_DIR = int(Qt.ItemDataRole.UserRole)          # dir index of tree items
ROLE_READY = int(Qt.ItemDataRole.UserRole) + 1    # children already populated

BAD_CHARS = "/\\:*?\"<>|\0"

PAGE_AUTO, PAGE_INFO, PAGE_EXTRACT, PAGE_VERIFY, PAGE_EDIT, PAGE_PACK, PAGE_UNPACK, PAGE_BATCH, PAGE_PATCH, PAGE_EXPORT = range(10)

# auto-pipeline stages, in execution order
STAGES = ("scan", "pack", "verify", "done")
STAGE_TEXT = {
    "scan": "Scanning source",
    "pack": "Packing files",
    "verify": "Verifying content",
    "done": "Complete",
}

# ---- theme -----------------------------------------------------------------

THEME = """
/* ============================================================
   Nupull Studio theme:
   Satin ruby crimson shell, deep midnight obsidian LCD screen,
   cyber gold and electric emerald accents, modern typography.
   ============================================================ */

/* ---- base: the device shell ---- */
QWidget {
    color: #e2e8f0;
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    font-size: 13px;
}
QMainWindow {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #8d1920, stop:0.4 #7b141a, stop:1 #5e0d12);
}
QWidget#bg {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #8d1920, stop:0.4 #7b141a, stop:1 #5e0d12);
}
QWidget#screen {
    background: #0b1220;
    border: 1.5px solid #1a2a47;
    border-radius: 14px;
}

/* ---- labels & typography ---- */
QLabel {
    color: #e2e8f0;
    background: transparent;
}
QLabel[muted="true"] {
    color: #7e8ea8;
}
QLabel[h1="true"] {
    font-size: 19px;
    font-weight: 800;
    color: #ffd75e;
    letter-spacing: 0.5px;
}
QLabel[section="true"] {
    font-size: 10px;
    font-weight: 800;
    color: #fca5a5;
    letter-spacing: 1.5px;
    padding-left: 8px;
    margin-top: 8px;
    margin-bottom: 2px;
}
QLabel[ok="true"] {
    color: #10b981;
    font-weight: 700;
}
QLabel[bad="true"] {
    color: #f43f5e;
    font-weight: 700;
}
QLabel[badge="true"] {
    background: rgba(255, 215, 94, 0.12);
    border: 1px solid rgba(255, 215, 94, 0.35);
    border-radius: 6px;
    padding: 3px 8px;
    color: #ffd75e;
    font-size: 11px;
    font-weight: 700;
}

/* ---- sidebar: left half of the Nupull console shell ---- */
QFrame#sidebar {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #5b0e13, stop:1 #470a0e);
    border: 1.5px solid #33070a;
    border-radius: 14px;
}
QLabel#appTitle {
    font-size: 21px;
    font-weight: 900;
    color: #ffd75e;
    letter-spacing: 1px;
}
QLabel#appSub {
    font-size: 11px;
    font-weight: 600;
    color: #f87171;
    letter-spacing: 0.5px;
}

/* ---- nav buttons in sidebar ---- */
QPushButton[nav="true"] {
    text-align: left;
    padding: 8px 12px;
    border: none;
    border-radius: 8px;
    background: transparent;
    color: #f1d1d3;
    font-size: 12.5px;
    font-weight: 600;
    margin: 1px 0;
}
QPushButton[nav="true"]:hover {
    background: rgba(255, 255, 255, 0.08);
    color: #ffffff;
}
QPushButton[nav="true"]:checked {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(255, 215, 94, 0.22), stop:1 rgba(255, 215, 94, 0.04));
    color: #ffe58f;
    border-left: 3.5px solid #ffd75e;
    border-radius: 6px;
    font-weight: 700;
}
QPushButton[nav="true"]:disabled {
    color: #7f5558;
}

/* ---- standard buttons ---- */
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1a2a48, stop:1 #121e33);
    color: #f1f5f9;
    border: 1px solid #28406c;
    border-radius: 8px;
    padding: 8px 16px;
    font-weight: 600;
    font-size: 13px;
}
QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #22375e, stop:1 #172742);
    border-color: #3b619f;
}
QPushButton:pressed {
    background: #0f192c;
    border-color: #1e3357;
}
QPushButton:disabled {
    background: #0f1624;
    color: #4b5873;
    border-color: #19243b;
}

QPushButton[primary="true"] {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #ffd966, stop:1 #f5b700);
    color: #1a0f00;
    border: 1px solid #d49b00;
    padding: 9px 22px;
    font-size: 13.5px;
    font-weight: 800;
    border-radius: 8px;
}
QPushButton[primary="true"]:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #ffe58f, stop:1 #ffc519);
    border-color: #f5b700;
}
QPushButton[primary="true"]:pressed {
    background: #d49b00;
}
QPushButton[primary="true"]:disabled {
    background: #332d1d;
    color: #736850;
    border-color: #262217;
}

QPushButton[flat="true"] {
    background: transparent;
    border: none;
    color: #ffd75e;
    padding: 4px 8px;
    font-weight: 600;
}
QPushButton[flat="true"]:hover {
    background: rgba(255, 215, 94, 0.12);
    border-radius: 6px;
}

QPushButton[drop="true"] {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0d1627, stop:1 #080e1a);
    border: 2px dashed #284473;
    border-radius: 14px;
    color: #7e8ea8;
    font-size: 14.5px;
    font-weight: 700;
    padding: 24px;
}
QPushButton[drop="true"]:hover {
    border-color: #ffd75e;
    color: #ffd75e;
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #121e35, stop:1 #0a1222);
}

/* ---- inputs ---- */
QLineEdit, QComboBox, QSpinBox {
    background: #090f1a;
    border: 1.5px solid #1e3357;
    border-radius: 8px;
    padding: 7px 11px;
    color: #f1f5f9;
    font-size: 13px;
    selection-background-color: #ffd75e;
    selection-color: #1a0f00;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border-color: #ffd75e;
    background: #0b1322;
}
QLineEdit:disabled, QComboBox:disabled {
    color: #4b5873;
    background: #080c14;
    border-color: #142036;
}
QLineEdit[card="true"] {
    background: #070c16;
    padding: 8px 12px;
    font-size: 13px;
}
QComboBox::drop-down {
    border: none;
    width: 24px;
}
QComboBox::down-arrow {
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 6px solid #7e8ea8;
    margin-right: 10px;
}
QComboBox QAbstractItemView {
    background: #0d1627;
    border: 1.5px solid #1e3357;
    color: #f1f5f9;
    selection-background-color: rgba(255, 215, 94, 0.22);
    selection-color: #ffffff;
    outline: none;
    padding: 4px;
}

/* ---- checkboxes & radio ---- */
QCheckBox, QRadioButton {
    spacing: 9px;
    color: #e2e8f0;
    background: transparent;
    font-size: 13px;
}
QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border-radius: 5px;
    border: 1.5px solid #2e4a78;
    background: #090f1a;
}
QCheckBox::indicator:hover {
    border-color: #ffd75e;
}
QCheckBox::indicator:checked {
    background: #ffd75e;
    border-color: #ffd75e;
}
QRadioButton::indicator {
    width: 17px;
    height: 17px;
    border-radius: 8px;
    border: 1.5px solid #2e4a78;
    background: #090f1a;
}
QRadioButton::indicator:checked {
    background: #ffd75e;
    border-color: #ffd75e;
}

/* ---- cards / groups ---- */
QGroupBox {
    background: #0e1729;
    border: 1.5px solid #1b2d4c;
    border-radius: 12px;
    margin-top: 18px;
    padding: 18px 14px 14px 14px;
    font-weight: 700;
    font-size: 12.5px;
    color: #ffd75e;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 14px;
    top: 4px;
    padding: 0 8px;
    background: #0e1729;
    border-radius: 4px;
    color: #ffd75e;
}

QFrame#trackCard, QFrame#card {
    background: #0e1729;
    border: 1.5px solid #1b2d4c;
    border-radius: 12px;
}

/* ---- tables & trees ---- */
QTableWidget, QTreeWidget {
    background: #0c1424;
    border: 1.5px solid #1b2d4c;
    border-radius: 10px;
    gridline-color: #172640;
    color: #e2e8f0;
    selection-background-color: rgba(255, 215, 94, 0.22);
    selection-color: #ffffff;
    alternate-background-color: #0f182b;
}
QTableWidget::item, QTreeWidget::item {
    padding: 5px 8px;
}
QTableWidget::item:selected, QTreeWidget::item:selected {
    background: rgba(255, 215, 94, 0.28);
    color: #ffffff;
}
QHeaderView::section {
    background: #111d33;
    color: #7e8ea8;
    border: none;
    border-right: 1px solid #1b2d4c;
    border-bottom: 1.5px solid #1b2d4c;
    padding: 7px 9px;
    font-weight: 700;
    font-size: 12px;
}

/* ---- log ---- */
QPlainTextEdit {
    background: #070c16;
    border: 1.5px solid #1b2d4c;
    border-radius: 10px;
    color: #a0aec0;
    font-family: Consolas, 'Cascadia Code', monospace;
    font-size: 12px;
    selection-background-color: rgba(255, 215, 94, 0.25);
}

/* ---- progress bars ---- */
QProgressBar {
    background: #070c16;
    border: 1.5px solid #1b2d4c;
    border-radius: 8px;
    text-align: center;
    color: #f1f5f9;
    height: 18px;
    font-weight: 700;
    font-size: 11px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #10b981, stop:1 #34d399);
    border-radius: 6px;
}
QProgressBar[pct="mid"]::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f59e0b, stop:1 #fbbf24);
}
QProgressBar[pct="low"]::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ef4444, stop:1 #f87171);
}

/* ---- scrollbars ---- */
QScrollBar:vertical {
    background: #090f1a;
    width: 10px;
    border: none;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #1e3357;
    border-radius: 5px;
    min-height: 28px;
    margin: 2px;
}
QScrollBar::handle:vertical:hover {
    background: #2b497c;
}
QScrollBar:horizontal {
    background: #090f1a;
    height: 10px;
    border: none;
    margin: 0;
}
QScrollBar::handle:horizontal {
    background: #1e3357;
    border-radius: 5px;
    min-width: 28px;
    margin: 2px;
}
QScrollBar::handle:horizontal:hover {
    background: #2b497c;
}
QScrollBar::add-line, QScrollBar::sub-line {
    width: 0;
    height: 0;
}
QScrollBar::add-page, QScrollBar::sub-page {
    background: none;
}

/* ---- stage chips ---- */
QLabel[chip="pending"] {
    background: #0c1424;
    border: 1.5px solid #1a2944;
    border-radius: 13px;
    padding: 6px 14px;
    color: #64748b;
    font-weight: 700;
    font-size: 11.5px;
}
QLabel[chip="active"] {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #ffd966, stop:1 #f5b700);
    border: 1.5px solid #d49b00;
    border-radius: 13px;
    padding: 6px 14px;
    color: #1a0f00;
    font-weight: 800;
    font-size: 11.5px;
}
QLabel[chip="done"] {
    background: #064e3b;
    border: 1.5px solid #10b981;
    border-radius: 13px;
    padding: 6px 14px;
    color: #34d399;
    font-weight: 700;
    font-size: 11.5px;
}
QLabel[chip="failed"] {
    background: #4c0519;
    border: 1.5px solid #f43f5e;
    border-radius: 13px;
    padding: 6px 14px;
    color: #fb7185;
    font-weight: 700;
    font-size: 11.5px;
}
QLabel[chip="cancelled"] {
    background: #1e293b;
    border: 1.5px solid #475569;
    border-radius: 13px;
    padding: 6px 14px;
    color: #94a3b8;
    font-weight: 700;
    font-size: 11.5px;
}

QPushButton#auCancel, QPushButton#bat_cancel, QPushButton#patch_cancel, QPushButton#exp_cancel {
    background: #3b0d14;
    border: 1px solid #e11d48;
    border-radius: 8px;
    color: #fda4af;
    padding: 8px 18px;
    font-weight: 700;
    font-size: 13px;
}
QPushButton#auCancel:hover, QPushButton#bat_cancel:hover, QPushButton#patch_cancel:hover, QPushButton#exp_cancel:hover {
    background: #4c111a;
    border-color: #f43f5e;
    color: #ffffff;
}
QPushButton#auCancel:disabled, QPushButton#bat_cancel:disabled, QPushButton#patch_cancel:disabled, QPushButton#exp_cancel:disabled {
    background: #141b2b;
    border-color: #1f2c44;
    color: #475569;
}
"""


# ---- background job --------------------------------------------------------

class Job(QThread):
    """A function run off the UI thread: one result or one error message,
    with optional (done, total, label) progress, byte progress and named
    pipeline stages."""

    done = pyqtSignal(object)
    error = pyqtSignal(str)
    note = pyqtSignal(str, str)  # (message, level) from worker -> activity log
    prog = pyqtSignal(int, int, str)
    # float, not int: pyqtSignal(int) is 32-bit, so totals past 2 GiB
    # overflowed into negative numbers on big dumps (e.g. 18 GB DKB).
    # float64 is exact for integers up to 2^53 — far beyond any dump.
    bytesig = pyqtSignal(float, float)
    stage = pyqtSignal(str)

    def __init__(self, fn, parent=None):
        super().__init__(parent)
        self.fn = fn
        # cooperative cancel: workers check at file boundaries (a QThread
        # cannot be killed mid-write without corrupting the output)
        self.cancelled = threading.Event()

    def run(self) -> None:
        try:
            result = self.fn(self)
        except SystemExit as e:
            msg = e.code if isinstance(e.code, str) else ""
            self.error.emit(msg or "operation aborted")
            return
        except Exception as e:
            self.error.emit(f"{type(e).__name__}: {e}")
            return
        self.done.emit(result)


# ---- helpers ---------------------------------------------------------------

def count_files(r: NupReader, dir_index: int) -> int:
    n = 0
    stack = [dir_index]
    while stack:
        for ref in iter_children(r, stack.pop()):
            if ref.is_dir:
                stack.append(ref.index)
            else:
                n += 1
    return n


def version_text(p, disp: str) -> str:
    """Prefer the display version; otherwise decode the NCM value like the
    CLI does (Switch 2 stores a revision counter in the low word)."""
    if disp:
        return disp
    if p.version == 0:
        return "-"
    if p.version & 0xFFFF == 0:
        return f"rev {p.version >> 16}"
    return f"{p.version >> 16}.{(p.version >> 8) & 0xFF}.{p.version & 0xFF}"


def esc(s: str) -> str:
    return html.escape(s, quote=False)


def sanitize_label(name: bytes) -> str:
    label = name.decode("utf-8", "surrogateescape")
    for ch in BAD_CHARS:
        label = label.replace(ch, "_")
    return label


def fmt_bytes(n: int) -> str:
    """Human-readable size: 1,234 B / 5.6 MB / 8.7 GB."""
    if n < 1024:
        return f"{n:,} B"
    for unit in ("KB", "MB", "GB", "TB"):
        n /= 1024.0
        if n < 1024.0:
            return f"{n:,.1f} {unit}"
    return f"{n:,.1f} PB"


def fmt_eta(seconds: float) -> str:
    """Human-readable duration: 45s / 7m 12s / 1h 04m."""
    if seconds < 0 or seconds != seconds or seconds == float("inf"):
        return "—"
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    return f"{s // 3600}h {(s % 3600) // 60:02d}m"


def create_nav_icon(name: str, size: int = 20, color_hex: str = "#f1d1d3") -> QPixmap:
    """Generate crisp, vector-rendered navigation and tool icons with antialiasing."""
    pix = QPixmap(size, size)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    scale = size / 20.0
    p.scale(scale, scale)

    pen = QPen(QColor(color_hex), 1.8)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)

    if name == "auto":
        poly = QPolygonF([QPointF(11, 2), QPointF(4, 11), QPointF(9, 11),
                          QPointF(8, 18), QPointF(16, 9), QPointF(11, 9)])
        p.setBrush(QBrush(QColor(color_hex)))
        p.drawPolygon(poly)
    elif name == "batch":
        p.drawRoundedRect(QRectF(2, 3, 16, 3.5), 1.5, 1.5)
        p.drawRoundedRect(QRectF(2, 8.5, 16, 3.5), 1.5, 1.5)
        p.drawRoundedRect(QRectF(2, 14, 16, 3.5), 1.5, 1.5)
    elif name == "unpack":
        p.drawArc(QRectF(2, 2, 16, 16), 30 * 16, 280 * 16)
        p.drawLine(QPointF(15, 10), QPointF(18, 13))
        p.drawLine(QPointF(15, 10), QPointF(12, 13))
    elif name == "info":
        p.drawEllipse(QRectF(2, 2, 16, 16))
        p.drawLine(QPointF(10, 6), QPointF(10, 7))
        p.drawLine(QPointF(10, 9.5), QPointF(10, 14))
    elif name == "verify":
        poly = QPolygonF([QPointF(10, 2), QPointF(17, 4.5), QPointF(17, 11),
                          QPointF(10, 18), QPointF(3, 11), QPointF(3, 4.5)])
        p.drawPolygon(poly)
        p.drawLine(QPointF(7, 10), QPointF(9.5, 12.5))
        p.drawLine(QPointF(9.5, 12.5), QPointF(14, 7))
    elif name == "extract":
        p.drawRoundedRect(QRectF(2, 4, 16, 13), 2, 2)
        p.drawLine(QPointF(10, 7), QPointF(10, 13))
        p.drawLine(QPointF(7, 10), QPointF(10, 13))
        p.drawLine(QPointF(13, 10), QPointF(10, 13))
    elif name == "edit":
        p.drawLine(QPointF(4, 16), QPointF(14, 4))
        p.drawLine(QPointF(14, 4), QPointF(16, 6))
        p.drawLine(QPointF(16, 6), QPointF(6, 18))
        p.drawLine(QPointF(4, 16), QPointF(6, 18))
        p.drawLine(QPointF(3, 17), QPointF(2, 19))
    elif name == "pack":
        p.drawRoundedRect(QRectF(3, 3, 14, 14), 2, 2)
        p.drawLine(QPointF(3, 8), QPointF(17, 8))
        p.drawLine(QPointF(10, 8), QPointF(10, 17))
    elif name == "patch":
        p.drawRoundedRect(QRectF(2, 4, 16, 12), 4, 4)
        p.drawLine(QPointF(6, 8), QPointF(6, 12))
        p.drawLine(QPointF(4, 10), QPointF(8, 10))
        p.drawPoint(QPointF(13, 8))
        p.drawPoint(QPointF(15, 10))
    elif name == "export":
        p.drawLine(QPointF(3, 13), QPointF(3, 17))
        p.drawLine(QPointF(3, 17), QPointF(17, 17))
        p.drawLine(QPointF(17, 17), QPointF(17, 13))
        p.drawLine(QPointF(10, 4), QPointF(10, 12))
        p.drawLine(QPointF(7, 7), QPointF(10, 4))
        p.drawLine(QPointF(13, 7), QPointF(10, 4))
    elif name in ("nupull", "pokeball"):
        p.setBrush(QBrush(QColor("#0b1424")))
        p.setPen(QPen(QColor("#ffd75e"), 1.5))
        p.drawEllipse(QRectF(1, 1, 18, 18))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(QColor("#ffd75e")))
        p.drawPolygon(QPolygonF([QPointF(5, 5), QPointF(7.5, 5), QPointF(7.5, 15), QPointF(5, 15)]))
        p.drawPolygon(QPolygonF([QPointF(12.5, 5), QPointF(15, 5), QPointF(15, 15), QPointF(12.5, 15)]))
        p.setBrush(QBrush(QColor("#f59e0b")))
        p.drawPolygon(QPolygonF([QPointF(6.5, 5), QPointF(9.5, 5), QPointF(13.5, 15), QPointF(10.5, 15)]))
        p.setBrush(QBrush(QColor("#10b981")))
        p.drawEllipse(QPointF(10, 10), 1.5, 1.5)
    p.end()
    return pix


class NupullLogo(QWidget):
    """An animated Nupull logo widget that rotates when a background job is active."""

    def __init__(self, size: int = 44, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self._angle = 0.0
        self._spinning = False
        self._timer = QTimer(self)
        self._timer.setInterval(40)          # 25 fps
        self._timer.timeout.connect(self._tick)

    def set_spinning(self, on: bool) -> None:
        if on == self._spinning:
            return
        self._spinning = on
        if on:
            self._timer.start()
        else:
            self._timer.stop()
            self._angle = 0.0
            self.update()

    def _tick(self) -> None:
        self._angle = (self._angle + 6.0) % 360.0
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802 (Qt naming)
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = self.rect().adjusted(2, 2, -2, -2)
        cx, cy = r.center().x(), r.center().y()

        p.save()
        p.translate(cx, cy)
        p.rotate(self._angle)
        p.translate(-cx, -cy)

        scale = r.width() / 44.0
        p.translate(r.left(), r.top())
        p.scale(scale, scale)

        # Outer badge circle
        p.setBrush(QBrush(QColor("#0b1424")))
        p.setPen(QPen(QColor("#ffd75e"), 2.2))
        p.drawEllipse(QRectF(1, 1, 42, 42))

        # Inner subtle ring
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(QColor("#1e355b"), 1.4))
        p.drawEllipse(QRectF(5, 5, 34, 34))

        # Stylized Nupull 'N'
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(QColor("#ffd75e")))
        p.drawPolygon(QPolygonF([QPointF(11, 11), QPointF(16, 11), QPointF(16, 33), QPointF(11, 33)]))
        p.drawPolygon(QPolygonF([QPointF(28, 11), QPointF(33, 11), QPointF(33, 33), QPointF(28, 33)]))

        p.setBrush(QBrush(QColor("#f59e0b")))
        p.drawPolygon(QPolygonF([QPointF(14, 11), QPointF(20, 11), QPointF(30, 33), QPointF(24, 33)]))

        # Core pull indicator pip
        p.setBrush(QBrush(QColor("#10b981")))
        p.drawEllipse(QPointF(22, 22), 3.0, 3.0)

        p.restore()
        p.end()


# Backward compatibility alias
Pokeball = NupullLogo


class Lamp(QLabel):
    """A small status LED: on/off with a fixed color."""

    def __init__(self, color: str, on: bool = False, parent=None):
        super().__init__(parent)
        self._color = color
        self.setFixedSize(12, 12)
        self.set_on(on)

    def set_on(self, on: bool) -> None:
        if on:
            self.setStyleSheet(
                f"background: {self._color}; border: 1px solid #101010;"
                " border-radius: 6px;")
        else:
            self.setStyleSheet(
                "background: #3a3f4a; border: 1px solid #101010;"
                " border-radius: 6px;")


def h1(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setProperty("h1", True)
    return lbl


def muted(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setProperty("muted", True)
    lbl.setWordWrap(True)
    return lbl


# ---- main window -----------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self, settings: QSettings):
        super().__init__()
        self.settings = settings
        self.job: Job | None = None
        self.t0 = 0.0
        self.active_file: str | None = None
        self.info: dict | None = None
        self._btns: list[QPushButton] = []
        self.nav_btns: list[QPushButton] = []
        # auto-pipeline tracking state
        self._track_bytes = 0
        self._track_total_bytes = 0
        self._track_files = 0
        self._track_total_files = 0
        self._speed_samples: deque[tuple[float, int]] = deque()
        self._auto_out: str | None = None
        self._auto_running = False
        self._auto_cancelled = False
        self._auto_result: dict | None = None

        self.setWindowTitle("Nupull — NX Package Manager (Switch 1/2)")
        self.setWindowIcon(QIcon(create_nav_icon("nupull", 48)))
        self.resize(1260, 840)
        self.setAcceptDrops(True)

        central = QWidget()
        central.setObjectName("bg")
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        # crimson console shell visible around the whole device
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        root.addWidget(self._build_sidebar())

        right = QVBoxLayout()
        # device bezel: red shell visible around the LCD screen
        right.setContentsMargins(12, 12, 14, 12)
        right.setSpacing(10)
        right.addWidget(self._build_file_bar())

        self.stack = QStackedWidget()
        for page in (
            self._build_auto_tab(),
            self._build_info_tab(),
            self._build_extract_tab(),
            self._build_verify_tab(),
            self._build_edit_tab(),
            self._build_pack_tab(),
            self._build_unpack_tab(),
            self._build_batch_tab(),
            self._build_patch_tab(),
            self._build_export_tab(),
        ):
            self.stack.addWidget(page)
        right.addWidget(self.stack, 1)

        # progress + status
        prow = QHBoxLayout()
        prow.setSpacing(10)
        self.pbar = QProgressBar()
        self.pbar.setRange(0, 100)
        self.pbar.setValue(0)
        self.pbar.setFixedWidth(260)
        self.pbar.hide()
        self.status_lbl = QLabel("Ready")
        self.status_lbl.setProperty("muted", True)
        prow.addWidget(self.pbar)
        prow.addWidget(self.status_lbl, 1)
        pw = QWidget()
        pw.setLayout(prow)
        right.addWidget(pw)

        # collapsible log
        log_hdr = QHBoxLayout()
        log_hdr.setSpacing(6)
        self.log_toggle = QPushButton("▸  Activity log")
        self.log_toggle.setProperty("flat", True)
        self.log_toggle.setCheckable(True)
        self.log_toggle.toggled.connect(self._toggle_log)
        log_hdr.addWidget(self.log_toggle)
        log_hdr.addStretch(1)
        self.log_hint = QLabel("")
        self.log_hint.setProperty("muted", True)
        log_hdr.addWidget(self.log_hint)
        lw = QWidget()
        lw.setLayout(log_hdr)
        right.addWidget(lw)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(3000)
        self.log_view.setFixedHeight(150)
        self.log_view.hide()
        right.addWidget(self.log_view)

        right_w = QWidget()
        right_w.setObjectName("screen")
        right_w.setLayout(right)
        root.addWidget(right_w, 1)

        geo = settings.value("geometry")
        if geo is not None:
            self.restoreGeometry(geo)

        self.goto_page(PAGE_AUTO)
        self._update_buttons(busy=False)
        self.log("NUP GUI started — drop a dump folder for one-shot "
                 "automation, or a .nup file to inspect")

    # ---- construction ------------------------------------------------------

    def _build_sidebar(self) -> QFrame:
        side = QFrame()
        side.setObjectName("sidebar")
        side.setFixedWidth(224)
        lay = QVBoxLayout(side)
        lay.setContentsMargins(12, 16, 12, 14)
        lay.setSpacing(2)

        # device logo: spinning Nupull core
        logo_row = QHBoxLayout()
        logo_row.setSpacing(10)
        self.logo = NupullLogo(44)
        self.pball = self.logo  # compatibility alias
        logo_row.addWidget(self.logo)
        title_col = QVBoxLayout()
        title_col.setSpacing(1)
        title = QLabel("NUPULL")
        title.setObjectName("appTitle")
        sub = QLabel("NX Package Studio")
        sub.setObjectName("appSub")
        title_col.addWidget(title)
        title_col.addWidget(sub)
        logo_row.addLayout(title_col)
        logo_row.addStretch(1)
        lw = QWidget()
        lw.setLayout(logo_row)
        lay.addWidget(lw)
        lay.addSpacing(4)

        # Console front details: two round buttons + speaker grille
        deco = QHBoxLayout()
        deco.setSpacing(6)
        for color in ("#38bdf8", "#f43f5e"):
            dot = QLabel()
            dot.setFixedSize(12, 12)
            dot.setStyleSheet(
                f"background: {color}; border: 1.5px solid #1a0507;"
                " border-radius: 6px;")
            deco.addWidget(dot)
        deco.addStretch(1)
        for _ in range(4):
            hole = QLabel()
            hole.setFixedSize(5, 5)
            hole.setStyleSheet(
                "background: #33070a; border: 1px solid #1a0507;"
                " border-radius: 2px;")
            deco.addWidget(hole)
        deco.addSpacing(4)
        dw2 = QWidget()
        dw2.setLayout(deco)
        lay.addWidget(dw2)
        lay.addSpacing(8)

        sections: list[tuple[str, list[tuple[str, str, int]]]] = [
            ("CONVERSION PIPELINE", [
                ("Auto Build", "auto", PAGE_AUTO),
                ("Batch Convert", "batch", PAGE_BATCH),
                ("Unpack & Convert", "unpack", PAGE_UNPACK),
            ]),
            ("CONTAINER TOOLS", [
                ("Container Info", "info", PAGE_INFO),
                ("Deep Verify", "verify", PAGE_VERIFY),
                ("Extract Tree", "extract", PAGE_EXTRACT),
                ("Edit Metadata", "edit", PAGE_EDIT),
                ("Pack Dump", "pack", PAGE_PACK),
            ]),
            ("MODS & EXPORT", [
                ("Mod Manager", "patch", PAGE_PATCH),
                ("Exporter", "export", PAGE_EXPORT),
            ]),
        ]

        all_btns: list[QPushButton] = []
        for sec_title, group_items in sections:
            sec_lbl = QLabel(sec_title)
            sec_lbl.setProperty("section", True)
            lay.addWidget(sec_lbl)
            for label, icon_name, page in group_items:
                b = QPushButton("  " + label)
                b.setCheckable(True)
                b.setProperty("nav", True)
                b.setProperty("page_idx", page)
                b.setIcon(QIcon(create_nav_icon(icon_name)))
                b.setIconSize(QSize(18, 18))
                b.setFixedHeight(34)
                b.clicked.connect(lambda _c=False, p=page: self.goto_page(p))
                lay.addWidget(b)
                all_btns.append(b)

        # Keep self.nav_btns sorted by page_idx so self.nav_btns[PAGE_X] matches PAGE_X exactly
        self.nav_btns = sorted(all_btns, key=lambda btn: int(btn.property("page_idx") or 0))

        lay.addStretch(1)

        # status LEDs: green=idle, yellow=running, red=error
        lamps = QHBoxLayout()
        lamps.setSpacing(6)
        cap = QLabel("DEVICE STATUS")
        cap.setStyleSheet("font-size:9.5px; font-weight:800;"
                          " color:#fca5a5; letter-spacing:1px;")
        self.lamp_ok = Lamp("#10b981", on=True)
        self.lamp_run = Lamp("#ffd75e", on=False)
        self.lamp_err = Lamp("#f43f5e", on=False)
        lamps.addWidget(cap)
        lamps.addSpacing(4)
        for w in (self.lamp_ok, self.lamp_run, self.lamp_err):
            lamps.addWidget(w)
        lamps.addStretch(1)
        lampw = QWidget()
        lampw.setLayout(lamps)
        lay.addWidget(lampw)

        self.side_status = QLabel("● Ready")
        self.side_status.setProperty("muted", True)
        self.side_status.setStyleSheet("font-size:11px; padding-left:2px;")
        lay.addWidget(self.side_status)
        return side

    def goto_page(self, i: int) -> None:
        self.stack.setCurrentIndex(i)
        for b in self.nav_btns:
            b.setChecked(b.property("page_idx") == i)

    def _build_file_bar(self) -> QWidget:
        bar = QFrame()
        bar.setStyleSheet(
            "QFrame { background:#0f192c; border:1.5px solid #1e3357;"
            " border-radius:12px; }")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(14, 10, 12, 10)
        lay.setSpacing(8)

        badge = QLabel("ACTIVE CONTAINER")
        badge.setProperty("badge", True)
        lay.addWidget(badge)

        self.file_edit = QLineEdit()
        self.file_edit.setProperty("card", True)
        self.file_edit.setPlaceholderText("Select or drop a .nup container to inspect / edit / verify…")
        self.file_edit.returnPressed.connect(self.load_info)
        lay.addWidget(self.file_edit, 1)

        self.browse_file_btn = QPushButton("Browse…")
        self.browse_file_btn.setIcon(QIcon(create_nav_icon("extract")))
        self.browse_file_btn.clicked.connect(self.browse_active_file)
        lay.addWidget(self.browse_file_btn)

        self.load_btn = QPushButton("Load")
        self.load_btn.setProperty("primary", True)
        self.load_btn.setIcon(QIcon(create_nav_icon("unpack", color_hex="#1a0f00")))
        self.load_btn.clicked.connect(self.load_info)
        lay.addWidget(self.load_btn)

        self._btns += [self.browse_file_btn, self.load_btn]
        return bar

    # -- page 0: auto (one-shot pipeline) ----------------------------------

    def _build_auto_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(2, 4, 2, 4)
        lay.setSpacing(10)

        head = QHBoxLayout()
        head.addWidget(h1("Auto Build — dump folder to .nup"))
        head.addStretch(1)
        self.au_elapsed_lbl = QLabel("")
        self.au_elapsed_lbl.setProperty("muted", True)
        head.addWidget(self.au_elapsed_lbl)
        hw = QWidget()
        hw.setLayout(head)
        lay.addWidget(hw)

        # drop zone
        self.au_drop = QPushButton(
            "⬌  Drop your game dump folder here\n"
            "or click to browse — scanning, packing and verification "
            "start automatically")
        self.au_drop.setProperty("drop", True)
        self.au_drop.setMinimumHeight(92)
        self.au_drop.setCursor(Qt.CursorShape.PointingHandCursor)
        self.au_drop.clicked.connect(self.browse_auto_src)
        lay.addWidget(self.au_drop)

        # output path — where the finished .nup is written (user's choice)
        out_row = QHBoxLayout()
        out_row.setSpacing(8)
        out_cap = QLabel("OUTPUT")
        out_cap.setStyleSheet("font-size:10px; font-weight:700;"
                              " color:#ffd75e; letter-spacing:1px;")
        self.au_out = QLineEdit()
        self.au_out.setProperty("card", True)
        self.au_out.setPlaceholderText(
            "destination .nup  —  defaults next to the dump folder")
        out_browse = QPushButton("Save as…")
        out_browse.setIcon(self.style().standardIcon(
            QStyle.StandardPixmap.SP_DialogSaveButton))
        out_browse.clicked.connect(self.browse_auto_out)
        out_row.addWidget(out_cap)
        out_row.addWidget(self.au_out, 1)
        out_row.addWidget(out_browse)
        ow = QWidget()
        ow.setLayout(out_row)
        lay.addWidget(ow)

        # stage chips: scan -> pack -> verify -> done
        chip_row = QHBoxLayout()
        chip_row.setSpacing(6)
        self.au_chips: dict[str, QLabel] = {}
        labels = {"scan": "1 · Scan", "pack": "2 · Pack",
                  "verify": "3 · Verify", "done": "4 · Done"}
        for key in STAGES:
            chip = QLabel(labels[key])
            chip.setProperty("chip", "pending")
            chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
            chip.setFixedWidth(110)
            self.au_chips[key] = chip
            chip_row.addWidget(chip)
            if key != "done":
                arrow = QLabel("→")
                arrow.setProperty("muted", True)
                chip_row.addWidget(arrow)
        chip_row.addStretch(1)
        cw = QWidget()
        cw.setLayout(chip_row)
        lay.addWidget(cw)

        # tracking card
        card = QFrame()
        card.setObjectName("trackCard")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(18, 14, 18, 14)
        cl.setSpacing(7)

        self.au_stage = QLabel("Waiting for a dump folder…")
        self.au_stage.setStyleSheet("font-size:15px; font-weight:800;"
                                    " color:#ffd75e;")
        cl.addWidget(self.au_stage)

        grid = QHBoxLayout()
        grid.setSpacing(24)

        def stat(caption: str) -> QLabel:
            col = QVBoxLayout()
            col.setSpacing(1)
            cap = QLabel(caption.upper())
            cap.setProperty("muted", True)
            cap.setStyleSheet("font-size:10px; font-weight:700;")
            val = QLabel("—")
            val.setStyleSheet("font-size:14px; font-weight:700;")
            val.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse)
            col.addWidget(cap)
            col.addWidget(val)
            grid.addLayout(col)
            return val

        self.au_files = stat("Files")
        self.au_bytes = stat("Data")
        self.au_speed = stat("Speed")
        self.au_eta = stat("Remaining")
        grid.addStretch(1)
        gw = QWidget()
        gw.setLayout(grid)
        cl.addWidget(gw)

        self.au_bar = QProgressBar()
        self.au_bar.setRange(0, 100)
        self.au_bar.setValue(0)
        self.au_bar.setFormat("%p%")
        cl.addWidget(self.au_bar)

        cur_row = QHBoxLayout()
        cur_row.setSpacing(8)
        cur_cap = QLabel("CURRENT")
        cur_cap.setProperty("muted", True)
        cur_cap.setStyleSheet("font-size:10px; font-weight:700;")
        self.au_cur = QLabel("—")
        self.au_cur.setProperty("muted", True)
        self.au_cur.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        cur_row.addWidget(cur_cap)
        cur_row.addWidget(self.au_cur, 1)
        crw = QWidget()
        crw.setLayout(cur_row)
        cl.addWidget(crw)

        lay.addWidget(card)

        # result row (hidden until a run finishes)
        self.au_result = QLabel(" ")
        self.au_result.setWordWrap(True)
        self.au_result.hide()
        lay.addWidget(self.au_result)

        self.au_reveal = QPushButton("Reveal in folder")
        self.au_reveal.setProperty("flat", True)
        self.au_reveal.hide()
        self.au_reveal.clicked.connect(self._reveal_output)
        lay.addWidget(self.au_reveal)

        lay.addStretch(1)

        btn_row = QHBoxLayout()
        self.au_cancel_btn = QPushButton("■ Cancel")
        self.au_cancel_btn.setObjectName("auCancel")
        self.au_cancel_btn.setEnabled(False)
        self.au_cancel_btn.setToolTip(
            "Stop the pipeline at the next file boundary.\n"
            "A partial container is removed automatically; a packed "
            "container kept (it just won't be fully verified).")
        self.au_cancel_btn.clicked.connect(self.cancel_auto)
        btn_row.addWidget(self.au_cancel_btn)
        btn_row.addStretch(1)
        self.au_go_btn = QPushButton("Choose dump folder…")
        self.au_go_btn.setProperty("primary", True)
        self.au_go_btn.setIcon(self.style().standardIcon(
            QStyle.StandardPixmap.SP_DirOpenIcon))
        self.au_go_btn.clicked.connect(self.browse_auto_src)
        btn_row.addWidget(self.au_go_btn)
        bw = QWidget()
        bw.setLayout(btn_row)
        lay.addWidget(bw)
        self._btns.append(self.au_go_btn)
        return w

    # -- page 1: info -------------------------------------------------------

    def _build_info_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(2, 4, 2, 4)
        lay.setSpacing(8)

        head = QHBoxLayout()
        head.addWidget(h1("Container information"))
        head.addStretch(1)
        for label, page in (("Extract…", PAGE_EXTRACT),
                            ("Verify", PAGE_VERIFY),
                            ("Edit metadata", PAGE_EDIT),
                            ("Pack new…", PAGE_PACK)):
            b = QPushButton(label)
            b.setProperty("flat", True)
            b.clicked.connect(lambda _c=False, p=page: self.goto_page(p))
            head.addWidget(b)
        hw = QWidget()
        hw.setLayout(head)
        lay.addWidget(hw)

        split = QSplitter(Qt.Orientation.Horizontal)

        # stats + packages table
        left = QVBoxLayout()
        left.setSpacing(8)

        cards = QHBoxLayout()
        cards.setSpacing(8)
        self.stats_lbls: dict[str, QLabel] = {}
        for key, caption in (("size", "Size"), ("pkgs", "Packages"),
                             ("nodes", "Nodes")):
            card = QFrame()
            card.setStyleSheet(
                "QFrame { background:#131f38; border:1px solid #2f4a7a;"
                " border-radius:12px; }")
            cl = QVBoxLayout(card)
            cl.setContentsMargins(14, 10, 14, 10)
            cl.setSpacing(2)
            cap = QLabel(caption.upper())
            cap.setProperty("muted", True)
            cap.setStyleSheet("font-size:11px; font-weight:700;")
            val = QLabel("-")
            val.setStyleSheet("font-size:16px; font-weight:700;")
            val.setWordWrap(False)
            val.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse)
            cl.addWidget(cap)
            cl.addWidget(val)
            cards.addWidget(card, 1)
            self.stats_lbls[key] = val
        cw = QWidget()
        cw.setLayout(cards)
        left.addWidget(cw)
        # uuid / toc on their own muted line (was crammed into the cards)
        self.meta_lbl = QLabel("-")
        self.meta_lbl.setProperty("muted", True)
        self.meta_lbl.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        left.addWidget(self.meta_lbl)

        left.addWidget(QLabel("Packages"))
        self.pkg_table = QTableWidget(0, 6)
        self.pkg_table.setHorizontalHeaderLabels(
            ["#", "Kind", "Title ID", "Version", "Name", "Build ID"])
        self.pkg_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self.pkg_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.pkg_table.setAlternatingRowColors(True)
        self.pkg_table.verticalHeader().setVisible(False)
        hh = self.pkg_table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        left.addWidget(self.pkg_table, 1)
        lw = QWidget()
        lw.setLayout(left)
        lw.setMinimumWidth(470)

        right = QVBoxLayout()
        right.addWidget(QLabel("Content tree"))
        self.info_tree = QTreeWidget()
        self.info_tree.setHeaderLabels(["Name", "Details"])
        self.info_tree.setUniformRowHeights(True)
        self.info_tree.setAlternatingRowColors(True)
        self.info_tree.itemExpanded.connect(self._tree_expanded)
        right.addWidget(self.info_tree)
        rw = QWidget()
        rw.setLayout(right)

        split.addWidget(lw)
        split.addWidget(rw)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 4)
        lay.addWidget(split, 1)
        return w

    # -- page 2: extract ----------------------------------------------------

    def _build_extract_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(2, 4, 2, 4)
        lay.setSpacing(10)
        lay.addWidget(h1("Extract files"))
        lay.addWidget(muted("Pull files out of a package, or the whole "
                            "container subtree."))

        form = QFormLayout()
        form.setSpacing(10)
        self.ext_pkg = QComboBox()
        form.addRow("Package:", self.ext_pkg)
        self.ext_subtree = QLineEdit()
        self.ext_subtree.setPlaceholderText(
            "empty = whole package, or a path like: romfs")
        form.addRow("Subtree:", self.ext_subtree)

        dest_row = QHBoxLayout()
        dest_row.setSpacing(6)
        self.ext_dest = QLineEdit()
        self.ext_dest.setPlaceholderText("destination directory")
        browse = QPushButton("Browse…")
        browse.setIcon(self.style().standardIcon(
            QStyle.StandardPixmap.SP_DirOpenIcon))
        browse.clicked.connect(self.browse_extract_dest)
        dest_row.addWidget(self.ext_dest, 1)
        dest_row.addWidget(browse)
        dw = QWidget()
        dw.setLayout(dest_row)
        form.addRow("Destination:", dw)
        fw = QWidget()
        fwl = QVBoxLayout(fw)
        fwl.setContentsMargins(0, 0, 0, 0)
        self.ext_flat = QCheckBox(
            "Rescue mode: dump the file table directly "
            "(for containers with a broken tree)")
        fwl.addWidget(self.ext_flat)
        form.addRow("", fw)
        lay.addLayout(form)

        self.ext_result = QLabel(" ")
        self.ext_result.setProperty("ok", True)
        self.ext_result.setWordWrap(True)
        lay.addWidget(self.ext_result)
        lay.addStretch(1)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        btn = QPushButton("Extract")
        btn.setProperty("primary", True)
        btn.setIcon(self.style().standardIcon(
            QStyle.StandardPixmap.SP_DialogSaveButton))
        btn.clicked.connect(self.run_extract)
        btn_row.addWidget(btn)
        bw = QWidget()
        bw.setLayout(btn_row)
        lay.addWidget(bw)
        self.ext_btn = btn
        self._btns.append(btn)
        return w

    # -- page 3: verify -----------------------------------------------------

    def _build_verify_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(2, 4, 2, 4)
        lay.setSpacing(10)
        lay.addWidget(h1("Verify integrity"))
        lay.addWidget(muted("Deep check recomputes the SHA-256 of every "
                            "file against the stored hashes."))

        self.vf_deep = QCheckBox("Deep check (recompute every file hash)")
        self.vf_deep.setChecked(True)
        lay.addWidget(self.vf_deep)

        verdict_card = QFrame()
        verdict_card.setStyleSheet(
            "QFrame { background:#131f38; border:1px solid #2f4a7a;"
            " border-radius:12px; }")
        vc = QVBoxLayout(verdict_card)
        vc.setContentsMargins(16, 12, 16, 12)
        cap = QLabel("VERDICT")
        cap.setProperty("muted", True)
        cap.setStyleSheet("font-size:11px; font-weight:700;")
        self.vf_verdict = QLabel("—")
        self.vf_verdict.setStyleSheet("font-size:22px; font-weight:800;")
        vc.addWidget(cap)
        vc.addWidget(self.vf_verdict)
        lay.addWidget(verdict_card)

        btn_row = QHBoxLayout()
        btn = QPushButton("Verify")
        btn.setProperty("primary", True)
        btn.setIcon(self.style().standardIcon(
            QStyle.StandardPixmap.SP_DialogYesButton))
        btn.clicked.connect(self.run_verify)
        btn_row.addWidget(btn)
        btn_row.addStretch(1)
        bw = QWidget()
        bw.setLayout(btn_row)
        lay.addWidget(bw)
        self.vf_btn = btn
        self._btns.append(btn)

        lay.addWidget(QLabel("Problems"))
        self.vf_problems = QPlainTextEdit()
        self.vf_problems.setReadOnly(True)
        self.vf_problems.setPlaceholderText(
            "No problems — or failure details here")
        self.vf_problems.setMaximumHeight(300)
        lay.addWidget(self.vf_problems, 1)
        return w

    # -- page 4: edit -------------------------------------------------------

    def _build_edit_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(2, 4, 2, 4)
        lay.setSpacing(10)
        lay.addWidget(h1("Edit metadata"))
        lay.addWidget(muted("An edit rewrites only the metadata tail — "
                            "contents and their hashes stay untouched, and "
                            "the result is validated before an atomic "
                            "replace."))

        box = QGroupBox("Package fields (merged with what exists)")
        form = QFormLayout(box)
        form.setSpacing(10)
        self.ed_pkg = QComboBox()
        form.addRow("Target package:", self.ed_pkg)
        self.ed_name, self.ed_name_clear = self._editable_row(
            form, "Title:", "game title")
        self.ed_pub, self.ed_pub_clear = self._editable_row(
            form, "Publisher:", "publisher")
        self.ed_ver, self.ed_ver_clear = self._editable_row(
            form, "Display version:", "1.2.3")

        icon_row = QHBoxLayout()
        icon_row.setSpacing(6)
        self.ed_icon = QLineEdit()
        self.ed_icon.setPlaceholderText("icon image path (PNG/JPEG)")
        ib = QPushButton("Browse…")
        ib.setIcon(self.style().standardIcon(
            QStyle.StandardPixmap.SP_DialogOpenButton))
        ib.clicked.connect(self.browse_icon)
        self.ed_icon_clear = QCheckBox("Clear")
        icon_row.addWidget(self.ed_icon, 1)
        icon_row.addWidget(ib)
        icon_row.addWidget(self.ed_icon_clear)
        iw = QWidget()
        iw.setLayout(icon_row)
        form.addRow("Icon:", iw)
        lay.addWidget(box)
        lay.addStretch(1)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        btn = QPushButton("Apply changes")
        btn.setProperty("primary", True)
        btn.setIcon(self.style().standardIcon(
            QStyle.StandardPixmap.SP_DialogApplyButton))
        btn.clicked.connect(self.run_edit)
        btn_row.addWidget(btn)
        bw = QWidget()
        bw.setLayout(btn_row)
        lay.addWidget(bw)
        self.ed_btn = btn
        self._btns.append(btn)
        return w

    def _editable_row(self, form: QFormLayout, caption: str,
                      placeholder: str) -> tuple[QLineEdit, QCheckBox]:
        row = QHBoxLayout()
        row.setSpacing(6)
        edit = QLineEdit()
        edit.setPlaceholderText(placeholder)
        clear = QCheckBox("Clear")
        row.addWidget(edit, 1)
        row.addWidget(clear)
        w = QWidget()
        w.setLayout(row)
        form.addRow(caption, w)
        return edit, clear

    # -- page 5: pack -------------------------------------------------------

    def _build_pack_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(2, 4, 2, 4)
        lay.setSpacing(10)
        lay.addWidget(h1("Pack a dump into .nup"))
        lay.addWidget(muted("Point at a dump directory (base/updates/dlc "
                            "layout) — everything else is optional."))

        form = QFormLayout()
        form.setSpacing(10)

        src_row = QHBoxLayout()
        src_row.setSpacing(6)
        self.pk_src = QLineEdit()
        self.pk_src.setPlaceholderText(
            "dump directory (base/updates/dlc, or a content dir)")
        sb = QPushButton("Browse…")
        sb.setIcon(self.style().standardIcon(
            QStyle.StandardPixmap.SP_DirOpenIcon))
        sb.clicked.connect(self.browse_pack_src)
        src_row.addWidget(self.pk_src, 1)
        src_row.addWidget(sb)
        sw = QWidget()
        sw.setLayout(src_row)
        form.addRow("Source:", sw)

        out_row = QHBoxLayout()
        out_row.setSpacing(6)
        self.pk_out = QLineEdit()
        self.pk_out.setPlaceholderText("game.nup")
        ob = QPushButton("Save as…")
        ob.setIcon(self.style().standardIcon(
            QStyle.StandardPixmap.SP_DialogSaveButton))
        ob.clicked.connect(self.browse_pack_out)
        out_row.addWidget(self.pk_out, 1)
        out_row.addWidget(ob)
        ow = QWidget()
        ow.setLayout(out_row)
        form.addRow("Output:", ow)

        self.pk_level = QSpinBox()
        self.pk_level.setRange(1, 22)
        self.pk_level.setValue(int(self.settings.value("zstd_level", 3)))
        self.pk_level.setToolTip("zstd compression level (default 3)")
        form.addRow("Compression level:", self.pk_level)

        self.pk_tid = QLineEdit()
        self.pk_tid.setPlaceholderText(
            "1-16 hex digits — read from main.npdm by default")
        form.addRow("Title ID (optional):", self.pk_tid)
        self.pk_name = QLineEdit()
        self.pk_name.setPlaceholderText("display title (TLV 0x0005)")
        form.addRow("Title:", self.pk_name)
        self.pk_pub = QLineEdit()
        self.pk_pub.setPlaceholderText("publisher (TLV 0x0006)")
        form.addRow("Publisher:", self.pk_pub)
        self.pk_dispver = QLineEdit()
        self.pk_dispver.setPlaceholderText("e.g. 1.2.3 (TLV 0x0004)")
        form.addRow("Display version:", self.pk_dispver)
        self.pk_icon = QLineEdit()
        self.pk_icon.setPlaceholderText("icon image path (optional)")
        form.addRow("Icon:", self.pk_icon)

        flags = QHBoxLayout()
        flags.setSpacing(16)
        self.pk_split = QCheckBox(
            "Split: base, each update and dlc as separate files")
        self.pk_keep = QCheckBox("Keep .listing files")
        flags.addWidget(self.pk_split)
        flags.addWidget(self.pk_keep)
        flags.addStretch(1)
        fw = QWidget()
        fw.setLayout(flags)
        form.addRow("", fw)
        lay.addLayout(form)

        self.pk_summary = QLabel(" ")
        self.pk_summary.setProperty("ok", True)
        self.pk_summary.setWordWrap(True)
        lay.addWidget(self.pk_summary)
        lay.addStretch(1)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        btn = QPushButton("Start packing")
        btn.setProperty("primary", True)
        btn.setIcon(self.style().standardIcon(
            QStyle.StandardPixmap.SP_MediaPlay))
        btn.clicked.connect(self.run_pack)
        btn_row.addWidget(btn)
        bw = QWidget()
        bw.setLayout(btn_row)
        lay.addWidget(bw)
        self.pk_btn = btn
        self._btns.append(btn)
        return w

    # -- page 6: unpack -----------------------------------------------------

    def _build_unpack_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(2, 4, 2, 4)
        lay.setSpacing(10)

        head = QHBoxLayout()
        head.addWidget(h1("Convert & Unpack Game Dump"))
        head.addStretch(1)
        self.un_elapsed_lbl = QLabel("")
        self.un_elapsed_lbl.setProperty("muted", True)
        head.addWidget(self.un_elapsed_lbl)
        hw = QWidget()
        hw.setLayout(head)
        lay.addWidget(hw)

        lay.addWidget(muted("Directly convert Nintendo Switch dumps (NSP/NSZ/XCI/XCZ/NCA) into "
                            ".nup containers, or unpack into standard base/updates/dlc folders."))

        # Mode selector: Direct Convert vs Unpack
        mode_row = QHBoxLayout()
        mode_row.setSpacing(18)
        self.un_mode_group = QButtonGroup(self)
        self.un_mode_convert = QRadioButton("Direct Convert to .nup (Stream directly, saves 50%+ disk)")
        self.un_mode_unpack = QRadioButton("Unpack to Folder (Extract base/, updates/, dlc/)")
        self.un_mode_convert.setChecked(True)
        self.un_mode_group.addButton(self.un_mode_convert)
        self.un_mode_group.addButton(self.un_mode_unpack)
        self.un_mode_convert.toggled.connect(self._on_unpack_mode_changed)
        mode_row.addWidget(self.un_mode_convert)
        mode_row.addWidget(self.un_mode_unpack)
        mode_row.addStretch(1)
        mw = QWidget()
        mw.setLayout(mode_row)
        lay.addWidget(mw)

        form = QFormLayout()
        form.setSpacing(10)

        src_row = QHBoxLayout()
        src_row.setSpacing(6)
        self.un_src = QLineEdit()
        self.un_src.setPlaceholderText(
            "source dump file (.nsp, .nsz, .xci, .xcz, .nca) or directory")
        sb = QPushButton("Browse File…")
        sb.setIcon(self.style().standardIcon(
            QStyle.StandardPixmap.SP_DialogOpenButton))
        sb.clicked.connect(self.browse_unpack_src)
        s_dir_b = QPushButton("Browse Folder…")
        s_dir_b.setIcon(self.style().standardIcon(
            QStyle.StandardPixmap.SP_DirOpenIcon))
        s_dir_b.clicked.connect(self.browse_unpack_src_folder)
        src_row.addWidget(self.un_src, 1)
        src_row.addWidget(sb)
        src_row.addWidget(s_dir_b)
        sw = QWidget()
        sw.setLayout(src_row)
        form.addRow("Source dump:", sw)

        out_row = QHBoxLayout()
        out_row.setSpacing(6)
        self.un_out = QLineEdit()
        self.un_out.setPlaceholderText(
            "output container (e.g. D:/Game.nup)")
        ob = QPushButton("Browse…")
        ob.setIcon(self.style().standardIcon(
            QStyle.StandardPixmap.SP_DirOpenIcon))
        ob.clicked.connect(self.browse_unpack_out)
        out_row.addWidget(self.un_out, 1)
        out_row.addWidget(ob)
        ow = QWidget()
        ow.setLayout(out_row)
        self.un_out_lbl = QLabel("Output container:")
        form.addRow(self.un_out_lbl, ow)

        keys_row = QHBoxLayout()
        keys_row.setSpacing(6)
        self.un_keys = QLineEdit()
        self.un_keys.setPlaceholderText(
            "prod.keys (auto-detected from Citron/Ryujinx/yuzu if left blank)")
        kb = QPushButton("Browse…")
        kb.setIcon(self.style().standardIcon(
            QStyle.StandardPixmap.SP_FileIcon))
        kb.clicked.connect(self.browse_unpack_keys)
        keys_row.addWidget(self.un_keys, 1)
        keys_row.addWidget(kb)
        kw = QWidget()
        kw.setLayout(keys_row)
        form.addRow("prod.keys (optional):", kw)

        base_row = QHBoxLayout()
        base_row.setSpacing(6)
        self.un_base = QLineEdit()
        self.un_base.setPlaceholderText(
            "matching base NSP/XCI for update RomFS merge (auto-discovered if blank)")
        bb = QPushButton("Browse…")
        bb.setIcon(self.style().standardIcon(
            QStyle.StandardPixmap.SP_DialogOpenButton))
        bb.clicked.connect(self.browse_unpack_base)
        base_row.addWidget(self.un_base, 1)
        base_row.addWidget(bb)
        bw = QWidget()
        bw.setLayout(base_row)
        form.addRow("Base package (optional):", bw)

        # Compression options (visible for Direct Convert)
        self.un_level_row = QWidget()
        lr_lay = QHBoxLayout(self.un_level_row)
        lr_lay.setContentsMargins(0, 0, 0, 0)
        lr_lay.setSpacing(10)
        self.un_level = QSpinBox()
        self.un_level.setRange(0, 22)
        self.un_level.setValue(19)
        self.un_level.setFixedWidth(70)
        lr_lay.addWidget(self.un_level)
        self.un_fast = QCheckBox("Fast / Store mode (skip Zstandard compression)")
        self.un_fast.toggled.connect(lambda checked: self.un_level.setEnabled(not checked))
        lr_lay.addWidget(self.un_fast)
        lr_lay.addStretch(1)
        self.un_level_form_label = QLabel("Compression:")
        form.addRow(self.un_level_form_label, self.un_level_row)

        self.un_merge_siblings = QCheckBox(
            "Auto-merge sibling updates and DLCs into one All-in-One container")
        self.un_merge_siblings.setChecked(True)

        self.un_multicore = QCheckBox(
            "Multi-core compression (fastest, utilizes all CPU cores)")
        self.un_multicore.setChecked(True)

        self.un_no_control = QCheckBox(
            "Skip Control NCA extraction (do not produce _meta/ folder or icon/title tags)")

        opt_box = QVBoxLayout()
        opt_box.setSpacing(6)
        opt_box.addWidget(self.un_merge_siblings)
        opt_box.addWidget(self.un_multicore)
        opt_box.addWidget(self.un_no_control)
        opt_w = QWidget()
        opt_w.setLayout(opt_box)
        form.addRow("Options:", opt_w)

        lay.addLayout(form)

        # Tracking card
        card = QFrame()
        card.setObjectName("trackCard")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(18, 14, 18, 14)
        cl.setSpacing(7)

        self.un_stage_lbl = QLabel("Ready to convert")
        self.un_stage_lbl.setStyleSheet(
            "font-size:15px; font-weight:800; color:#ffd75e;")
        cl.addWidget(self.un_stage_lbl)

        self.un_live_lbl = QLabel("—")
        self.un_live_lbl.setWordWrap(True)
        self.un_live_lbl.setStyleSheet("font-size:12px; color:#e9edf7;")
        cl.addWidget(self.un_live_lbl)

        lay.addWidget(card)
        lay.addStretch(1)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        btn_row.addStretch(1)

        self.un_cancel_btn = QPushButton("Cancel")
        self.un_cancel_btn.setEnabled(False)
        self.un_cancel_btn.clicked.connect(self.cancel_unpack)
        btn_row.addWidget(self.un_cancel_btn)

        self.un_start_btn = QPushButton("Start Direct Convert")
        self.un_start_btn.setProperty("primary", True)
        self.un_start_btn.setIcon(self.style().standardIcon(
            QStyle.StandardPixmap.SP_DialogYesButton))
        self.un_start_btn.clicked.connect(self.start_unpack)
        btn_row.addWidget(self.un_start_btn)
        self._btns.append(self.un_start_btn)

        bw_btn = QWidget()
        bw_btn.setLayout(btn_row)
        lay.addWidget(bw_btn)

        return w

    # ---- logging / status --------------------------------------------------

    def log(self, msg: str, level: str = "info") -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        color = {"err": "#ff7a86", "ok": "#58d18b"}.get(level)
        # escape ONLY for the HTML path: escaping before appendPlainText
        # used to print the HTML-escaped form ("-&gt;") literally in plain text
        if color:
            self.log_view.appendHtml(
                f'<span style="color:{color}">{ts}  {esc(msg)}</span>')
        else:
            self.log_view.appendPlainText(f"{ts}  {msg}")

    def set_status(self, text: str, ok: bool | None = None) -> None:
        self.status_lbl.setText(text)
        color = "#58d18b" if ok else ("#ff7a86" if ok is False else "#8fa0c4")
        self.status_lbl.setStyleSheet(f"color:{color}")

    # ---- job control -------------------------------------------------------

    def start_job(self, fn, label: str, on_done) -> bool:
        if self.job is not None and self.job.isRunning():
            QMessageBox.warning(
                self, "Busy",
                "An operation is already running — wait for it to finish.")
            return False
        job = Job(fn, self)
        job.prog.connect(self._on_prog)
        job.stage.connect(self._on_stage)
        job.bytesig.connect(self._on_bytes)
        job.note.connect(self.log)
        job.error.connect(lambda m, lb=label: self._on_error(m, lb))
        job.done.connect(lambda res, lb=label, cb=on_done:
                         self._on_done(res, lb, cb))
        self.job = job
        self.t0 = time.time()
        self._speed_samples.clear()
        self._update_buttons(busy=True)
        self.pbar.setRange(0, 0)
        self.set_status(f"{label} …")
        self.side_status.setText(f"● {label.lower()}…")
        self.side_status.setStyleSheet("color:#ffd75e")
        self.lamp_run.set_on(True)
        self.lamp_ok.set_on(False)
        self.lamp_err.set_on(False)
        self.pball.set_spinning(True)
        self.log(label + " …")
        job.start()
        return True

    def _update_buttons(self, busy: bool) -> None:
        self.pbar.setVisible(busy)
        loaded = self.active_file is not None
        for b in self._btns:
            b.setEnabled(not busy)
        for b in (self.ext_btn, self.vf_btn, self.ed_btn):
            b.setEnabled(not busy and loaded)
        # cancel only makes sense while the auto pipeline is running
        if hasattr(self, "au_cancel_btn"):
            self.au_cancel_btn.setEnabled(busy and self._auto_running)
        if hasattr(self, "un_cancel_btn"):
            self.un_cancel_btn.setEnabled(busy and getattr(self, "_unpack_running", False))
        if hasattr(self, "un_start_btn"):
            self.un_start_btn.setEnabled(not busy)
        if hasattr(self, "bat_cancel_btn"):
            self.bat_cancel_btn.setEnabled(busy and getattr(self, "_batch_running", False))
        if hasattr(self, "bat_start_btn"):
            self.bat_start_btn.setEnabled(not busy)
        if hasattr(self, "pat_cancel_btn"):
            self.pat_cancel_btn.setEnabled(busy and getattr(self, "_patch_running", False))
        if hasattr(self, "pat_start_btn"):
            self.pat_start_btn.setEnabled(not busy)
        if hasattr(self, "exp_cancel_btn"):
            self.exp_cancel_btn.setEnabled(busy and getattr(self, "_export_running", False))
        if hasattr(self, "exp_start_btn"):
            self.exp_start_btn.setEnabled(not busy)
        if not busy:
            self.side_status.setText("● idle")
            self.side_status.setStyleSheet("")
            self.pball.set_spinning(False)

    def _on_stage(self, stage: str) -> None:
        """Track pipeline stage chips on the AUTO screen."""
        if getattr(self, "_unpack_running", False):
            self._unpack_stage = stage
            is_convert = getattr(self, "un_mode_convert", None) and self.un_mode_convert.isChecked()
            act = "Converting" if is_convert else "Unpacking"
            if hasattr(self, "un_stage_lbl"):
                self.un_stage_lbl.setText(f"{act}: {stage}…")
            self.log(f"{act.lower()} stage: {stage}")
        if getattr(self, "_batch_running", False):
            if hasattr(self, "bat_stage_lbl"):
                self.bat_stage_lbl.setText(f"Batch: {stage}…")
            self.log(f"batch stage: {stage}")
        if getattr(self, "_patch_running", False):
            if hasattr(self, "pat_stage_lbl"):
                self.pat_stage_lbl.setText(f"Patch: {stage}…")
            self.log(f"patch stage: {stage}")
        if getattr(self, "_export_running", False):
            if hasattr(self, "exp_stage_lbl"):
                self.exp_stage_lbl.setText(f"Export: {stage}…")
            self.log(f"export stage: {stage}")
        if stage not in STAGES:
            return
        idx = STAGES.index(stage)
        for i, key in enumerate(STAGES):
            if key == stage:
                self.au_chips[key].setProperty(
                    "chip", "done" if stage == "done" else "active")
            elif i < idx:
                self.au_chips[key].setProperty("chip", "done")
            else:
                self.au_chips[key].setProperty("chip", "pending")
            w = self.au_chips[key]
            w.style().unpolish(w)
            w.style().polish(w)
        self.au_stage.setText(STAGE_TEXT[stage] + "…")
        self.log(f"stage: {STAGE_TEXT[stage]}")

    def _on_prog(self, done: int, total: int, name: str) -> None:
        if self.pbar.maximum() != 100:
            self.pbar.setRange(0, 100)
        if total:
            pct = done * 100 // total
            self.pbar.setValue(pct)
            self._set_hp(self.pbar, pct)
        shown = name if len(name) <= 70 else "…" + name[-67:]
        self.set_status(f"{done:,}/{total:,} — {shown}")

        # AUTO screen tracking: files row + current file
        if self._auto_running and total:
            pct = done * 100 // total
            self.au_files.setText(f"{done:,} / {total:,}  ({pct}%)")
            self.au_cur.setText(shown)
            self.au_bar.setValue(pct)
            self._set_hp(self.au_bar, pct)

        if getattr(self, "_unpack_running", False):
            self._unpack_done_files = done
            self._unpack_total_files = total
            self._unpack_current = shown
            self._update_unpack_live_line()

        if getattr(self, "_batch_running", False) and hasattr(self, "bat_bar"):
            pct = done * 100 // total if total else 0
            self.bat_bar.setValue(pct)
            self._set_hp(self.bat_bar, pct)
            self.bat_live_lbl.setText(f"[{done}/{total}] {shown}")

        if getattr(self, "_patch_running", False) and hasattr(self, "pat_bar"):
            pct = done * 100 // total if total else 0
            self.pat_bar.setValue(pct)
            self._set_hp(self.pat_bar, pct)
            self.pat_live_lbl.setText(f"[{done}/{total}] {shown}")

        if getattr(self, "_export_running", False) and hasattr(self, "exp_bar"):
            pct = done * 100 // total if total else 0
            self.exp_bar.setValue(pct)
            self._set_hp(self.exp_bar, pct)
            self.exp_live_lbl.setText(f"[{done}/{total}] {shown}")

    def _on_bytes(self, done: float, total: float) -> None:
        """Byte progress + speed/ETA for the AUTO tracking card.

        The signal carries floats (32-bit int signals overflow past 2 GiB);
        convert back to exact ints right away — float64 holds them exactly.
        """
        done = int(done)
        total = int(total)
        now = time.time()
        self._track_bytes = done
        self._track_total_bytes = total
        self._speed_samples.append((now, done))
        while len(self._speed_samples) > 2 and \
                now - self._speed_samples[0][0] > 5.0:
            self._speed_samples.popleft()

        if getattr(self, "_unpack_running", False):
            self.un_elapsed_lbl.setText(f"elapsed {fmt_eta(now - self.t0)}")
            self._update_unpack_live_line()

        if not self._auto_running:
            return
        self.au_elapsed_lbl.setText(f"elapsed {fmt_eta(now - self.t0)}")
        if total:
            pct = done * 100 // total
            self.au_bytes.setText(f"{fmt_bytes(done)} / {fmt_bytes(total)}"
                                  f"  ({pct}%)")
            self.au_bar.setValue(pct)
            self._set_hp(self.au_bar, pct)

        # speed: bytes/s over the 5s sliding window
        first_t, first_b = self._speed_samples[0]
        dt = now - first_t
        speed = 0.0
        if dt >= 1.0 and done >= first_b:
            speed = (done - first_b) / dt
        if speed > 0:
            self.au_speed.setText(f"{fmt_bytes(int(speed))}/s")
            if total > done:
                self.au_eta.setText(fmt_eta((total - done) / speed))
            else:
                self.au_eta.setText("0s")

    def _set_hp(self, bar: QProgressBar, pct: int) -> None:
        """Color an HP-bar: green > 40%, yellow > 15%, red below."""
        level = "" if pct > 40 else ("mid" if pct > 15 else "low")
        if bar.property("pct") != level:
            bar.setProperty("pct", level)
            bar.style().unpolish(bar)
            bar.style().polish(bar)

    def _update_unpack_live_line(self) -> None:
        if not getattr(self, "_unpack_running", False):
            return
        now = time.time()
        done = self._track_bytes
        total = self._track_total_bytes
        pct = done * 100 // total if total else 0
        speed = 0.0
        if self._speed_samples:
            first_t, first_b = self._speed_samples[0]
            dt = now - first_t
            if dt >= 1.0 and done >= first_b:
                speed = (done - first_b) / dt
        speed_str = f"{fmt_bytes(int(speed))}/s" if speed > 0 else "—"
        eta_str = fmt_eta((total - done) / speed) if (speed > 0 and total > done) else "—"
        stage_str = getattr(self, "_unpack_stage", "extract")
        cur_file = getattr(self, "_unpack_current", "")
        d_files = getattr(self, "_unpack_done_files", 0)
        t_files = getattr(self, "_unpack_total_files", 0)
        line = (f"Stage: {stage_str} | Contents: {d_files}/{t_files} | "
                f"Bytes: {fmt_bytes(done)} / {fmt_bytes(total)} ({pct}%) | "
                f"Speed: {speed_str} | ETA: {eta_str}\n{cur_file}")
        if hasattr(self, "un_live_lbl"):
            self.un_live_lbl.setText(line)

    def _on_error(self, msg: str, label: str) -> None:
        cancelled = self._auto_cancelled or (
            getattr(self, "_unpack_running", False) and self.job is not None
            and self.job.cancelled.is_set())
        if getattr(self, "_unpack_running", False):
            self._unpack_running = False
            is_convert = getattr(self, "un_mode_convert", None) and self.un_mode_convert.isChecked()
            op = "Conversion" if is_convert else "Unpack"
            if hasattr(self, "un_stage_lbl"):
                self.un_stage_lbl.setText(f"{op} cancelled" if cancelled else f"{op} failed")
            if hasattr(self, "un_cancel_btn"):
                self.un_cancel_btn.setEnabled(False)
            if hasattr(self, "un_start_btn"):
                self.un_start_btn.setEnabled(True)
        self._update_buttons(busy=False)
        self.pbar.setRange(0, 100)
        self.pbar.setValue(0)
        self.lamp_run.set_on(False)
        if cancelled:
            # user-initiated stop: neutral lamps/status, not a failure
            self.lamp_err.set_on(False)
            self.set_status("Cancelled")
        else:
            self.lamp_err.set_on(True)
            self.set_status(f"FAILED: {label}", ok=False)
        self.log(f"{label}: {msg}", "info" if cancelled else "err")
        if self._auto_running:
            self._auto_running = False
            self._auto_cancelled = False        # one-shot: clear for next run
            for chip in self.au_chips.values():
                if chip.property("chip") == "active":
                    chip.setProperty(
                        "chip", "cancelled" if cancelled else "failed")
                    chip.style().unpolish(chip)
                    chip.style().polish(chip)
            if cancelled:
                self.au_stage.setText(f"CANCELLED — {msg}")
                self.au_result.setText(
                    f"<span style='color:#8fa0c4'>{esc(msg)}</span>")
            else:
                self.au_stage.setText(f"FAILED — {msg}")
                self.au_result.setText(
                    f"<span style='color:#ff7a86'>Failed during "
                    f"{label}: {esc(msg)}</span>")
            self.au_result.show()
        if not self.log_view.isVisible():
            self.log_toggle.setChecked(True)

    def _on_done(self, result, label: str, on_done) -> None:
        self._update_buttons(busy=False)
        self.pbar.setRange(0, 100)
        self.pbar.setValue(0)
        self.lamp_run.set_on(False)
        self.lamp_ok.set_on(True)
        dt = time.time() - self.t0
        try:
            on_done(result)
        except Exception as e:
            self.log(f"UI update failed: {type(e).__name__}: {e}", "err")
        self.set_status(f"Done: {label} ({dt:,.1f}s)", ok=True)
        self.log(f"{label} finished in {dt:,.1f}s", "ok")

    def _toggle_log(self, on: bool) -> None:
        self.log_view.setVisible(on)
        self.log_toggle.setText("▾  Activity log" if on
                                else "▸  Activity log")

    # ---- active file / info ------------------------------------------------

    def browse_active_file(self) -> None:
        start = self.settings.value("last_dir", os.path.expanduser("~"))
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose a container file", start, "NUP (*.nup);;All files (*)")
        if path:
            self.settings.setValue("last_dir", os.path.dirname(path))
            self.file_edit.setText(path)
            self.load_info()

    def set_active_file(self, path: str, load: bool = True) -> None:
        self.file_edit.setText(path)
        if load:
            self.load_info()

    def load_info(self) -> None:
        path = self.file_edit.text().strip()
        if not path:
            self.set_status("Pick a .nup file first", ok=False)
            return
        if not os.path.isfile(path):
            QMessageBox.warning(self, "Not found",
                                f"File does not exist:\n{path}")
            return

        def run(job) -> dict:
            with NupReader(path) as r:
                s = r.super
                rows, combos, root_dirs = [], [], {}
                for p in r.packages:
                    meta = app_meta(r, p)
                    name = meta.get(F.TLV_TITLE_NAME, b"").decode(
                        "utf-8", "replace")
                    pub = meta.get(F.TLV_PUBLISHER, b"").decode(
                        "utf-8", "replace")
                    disp = meta.get(F.TLV_DISPLAY_VERSION, b"").decode(
                        "utf-8", "replace")
                    bid = build_id(r, p)
                    rows.append([
                        str(p.index), KIND_LABEL.get(p.kind, str(p.kind)),
                        f"{p.title_id:016X}", version_text(p, disp),
                        name or "-",
                        (bid.rstrip(bytes(1)).hex().upper() if bid else "-"),
                    ])
                    combos.append({
                        "idx": p.index,
                        "label": f"[{p.index}] "
                                 f"{KIND_LABEL.get(p.kind, p.kind)} — "
                                 f"{p.title_id:016X}",
                    })
                    root_dirs[p.index] = p.root_dir

                tree: dict[int, list] = {}
                seen: set[int] = set()
                stack = [p.root_dir for p in r.packages]
                while stack:
                    di = stack.pop()
                    if di in seen:
                        continue
                    seen.add(di)
                    kids = []
                    for ref in iter_children(r, di):
                        if ref.is_dir:
                            nm = ref.name.decode("utf-8", "surrogateescape")
                            kids.append((1, ref.index, nm, ""))
                            stack.append(ref.index)
                        else:
                            nm, size, _sha, _o, _e, codec = r.file_info(
                                ref.index)
                            tag = ("zstd" if codec == F.CODEC_ZSTD
                                   else ("raw" if size else "empty"))
                            kids.append(
                                (0, ref.index,
                                 nm.decode("utf-8", "surrogateescape"),
                                 f"{size:,} B · {tag}"))
                    tree[di] = kids

                return {
                    "path": path,
                    "size": s["file_size"],
                    "uuid": s["uuid"].hex(),
                    "toc": f"@{s['toc_offset']:#x} +{s['toc_size']:,} B",
                    "counts": f"{len(r.packages)} packages, "
                              f"{r.dir_count:,} dirs, {r.file_count:,} files",
                    "rows": rows,
                    "combos": combos,
                    "root_dirs": root_dirs,
                    "tree": tree,
                }

        self.start_job(run, "Loading info", self._apply_info)

    def _apply_info(self, data: dict) -> None:
        self.active_file = data["path"]
        self.info = data
        self.stats_lbls["size"].setText(f"{data['size']:,}")
        self.stats_lbls["pkgs"].setText(str(len(data["rows"])))
        self.stats_lbls["nodes"].setText(data["counts"])
        self.meta_lbl.setText(f"UUID {data['uuid']}   ·   TOC {data['toc']}")

        self.pkg_table.setRowCount(len(data["rows"]))
        for i, row in enumerate(data["rows"]):
            for j, cell in enumerate(row):
                self.pkg_table.setItem(i, j, QTableWidgetItem(cell))

        self.info_tree.clear()
        self.ext_pkg.clear()
        self.ed_pkg.clear()
        self.ed_pkg.addItem("Auto (where app metadata lives)", None)
        for c in data["combos"]:
            item = QTreeWidgetItem([f"Package [{c['idx']}]", ""])
            rd = data["root_dirs"].get(c["idx"])
            if rd is not None:
                self._populate_children(item, rd)
                item.setData(0, ROLE_DIR, rd)
                item.setData(0, ROLE_READY, True)
            self.info_tree.addTopLevelItem(item)
            self.info_tree.expandItem(item)

            self.ext_pkg.addItem(c["label"], c["idx"])
            self.ed_pkg.addItem(c["label"], str(c["idx"]))

        if not self.ext_dest.text().strip():
            stem, _ = os.path.splitext(data["path"])
            self.ext_dest.setText(stem + "_extracted")
        if hasattr(self, "pat_container"):
            self.pat_container.setText(data["path"])
        if hasattr(self, "exp_container"):
            self.exp_container.setText(data["path"])
        if hasattr(self, "pat_pkg"):
            self.pat_pkg.clear()
            self.pat_pkg.addItem("Auto (Base game or matching Atmosphere Title ID)", None)
            for c in data["combos"]:
                self.pat_pkg.addItem(c["label"], str(c["idx"]))
        if hasattr(self, "exp_pkg"):
            self.exp_pkg.clear()
            self.exp_pkg.addItem("Base game (default)", None)
            for c in data["combos"]:
                self.exp_pkg.addItem(c["label"], str(c["idx"]))

        self._update_buttons(busy=False)
        self.log(f"Loaded {data['path']} — {data['counts']}", "ok")
        self.goto_page(PAGE_INFO)

    def _populate_children(self, item: QTreeWidgetItem, dir_idx: int) -> None:
        if not self.info:
            return
        for is_dir, cidx, label, sub in self.info["tree"].get(dir_idx, []):
            child = QTreeWidgetItem([label, sub])
            if is_dir:
                child.setText(0, label + "/")
                child.setData(0, ROLE_DIR, cidx)
                if self.info["tree"].get(cidx):
                    child.setData(0, ROLE_READY, False)
                    child.addChild(QTreeWidgetItem(["…", ""]))
            item.addChild(child)

    def _tree_expanded(self, item: QTreeWidgetItem) -> None:
        if item.data(0, ROLE_READY) is not False:
            return
        dir_idx = item.data(0, ROLE_DIR)
        if dir_idx is None or not self.info:
            return
        item.setData(0, ROLE_READY, True)
        item.takeChildren()          # drop the "…" placeholder
        self._populate_children(item, dir_idx)

    # ---- extract -----------------------------------------------------------

    def browse_extract_dest(self) -> None:
        start = self.ext_dest.text().strip() or self.settings.value(
            "last_dir", os.path.expanduser("~"))
        path = QFileDialog.getExistingDirectory(self, "Destination folder",
                                                start)
        if path:
            self.ext_dest.setText(path)

    def run_extract(self) -> None:
        if not self.active_file:
            self.set_status("Load a .nup file first", ok=False)
            return
        path = self.active_file
        pkg_idx = self.ext_pkg.currentData()
        subtree = self.ext_subtree.text().strip()
        dest = self.ext_dest.text().strip()
        if not dest:
            QMessageBox.warning(self, "Missing",
                                "Choose a destination directory.")
            return
        flat = self.ext_flat.isChecked()

        def run(job) -> int:
            if flat:
                with NupReader(path) as r:
                    os.makedirs(dest, exist_ok=True)
                    total = r.file_count
                    for fi in range(total):
                        name, _size, _sha, _o, _e, _c = r.file_info(fi)
                        label = sanitize_label(name)
                        target = os.path.join(dest, f"{fi:05d}_{label}")
                        data = r.read_file(fi)
                        with open(target, "wb") as fh:
                            fh.write(data)
                        job.prog.emit(fi + 1, total, label)
                    return total
            with NupReader(path) as r:
                if pkg_idx is None or pkg_idx >= len(r.packages):
                    raise SystemExit("selected package does not exist")
                pkg = r.packages[pkg_idx]
                dir_idx = pkg.root_dir
                if subtree:
                    ref = resolve_path(r, pkg, subtree)
                    if ref is None:
                        raise SystemExit(f"no such subtree: {subtree!r}")
                    if not ref.is_dir:
                        raise SystemExit(
                            f"{subtree!r} is a file, not a directory")
                    dir_idx = ref.index
                total = count_files(r, dir_idx)

                def prog(n, ref):
                    job.prog.emit(n, total,
                                  ref.name.decode("utf-8", "surrogateescape"))

                return extract_tree(r, dest, dir_idx, progress=prog)

        def ok(n: int) -> None:
            self.ext_result.setText(f"Extracted {n:,} files → {dest}")
            self.log(f"Extract: {n:,} files → {dest}", "ok")

        self.start_job(run, "Extract", ok)

    # ---- verify ------------------------------------------------------------

    def run_verify(self) -> None:
        if not self.active_file:
            self.set_status("Load a .nup file first", ok=False)
            return
        path = self.active_file
        deep = self.vf_deep.isChecked()

        def run(job):
            return nup_verify(path, deep=deep)

        def ok(res) -> None:
            ok_flag, problems = res
            if ok_flag:
                self.vf_verdict.setText("OK ✓")
                self.vf_verdict.setStyleSheet(
                    "font-size:22px; font-weight:800; color:#58d18b")
                self.vf_problems.setPlainText("")
                self.log(f"Verify (deep={deep}): OK", "ok")
            else:
                self.vf_verdict.setText("FAILED ✗")
                self.vf_verdict.setStyleSheet(
                    "font-size:22px; font-weight:800; color:#ff7a86")
                self.vf_problems.setPlainText("\n".join(problems))
                self.log(f"Verify: {len(problems)} problem(s)", "err")
                if not self.log_view.isVisible():
                    self.log_toggle.setChecked(True)

        self.start_job(run,
                       "Deep verify" if deep else "Fast verify",
                       ok)

    # ---- edit --------------------------------------------------------------

    def browse_icon(self) -> None:
        start = self.settings.value("last_dir", os.path.expanduser("~"))
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose an icon", start,
            "Images (*.png *.jpg *.jpeg);;All files (*)")
        if path:
            self.ed_icon.setText(path)

    def run_edit(self) -> None:
        if not self.active_file:
            self.set_status("Load a .nup file first", ok=False)
            return
        path = self.active_file
        kw: dict = {}
        pkg = self.ed_pkg.currentData()
        if pkg is not None:
            kw["package"] = pkg
        if self.ed_name.text().strip():
            kw["name"] = self.ed_name.text().strip()
        if self.ed_pub.text().strip():
            kw["publisher"] = self.ed_pub.text().strip()
        if self.ed_ver.text().strip():
            kw["display_version"] = self.ed_ver.text().strip()
        if self.ed_icon.text().strip():
            kw["icon"] = self.ed_icon.text().strip()
        if self.ed_name_clear.isChecked():
            kw["clear_name"] = True
        if self.ed_pub_clear.isChecked():
            kw["clear_publisher"] = True
        if self.ed_ver_clear.isChecked():
            kw["clear_display_version"] = True
        if self.ed_icon_clear.isChecked():
            kw["clear_icon"] = True
        if set(kw) == {"package"}:
            QMessageBox.warning(self, "Nothing to edit",
                                "Set at least one field (or a Clear flag).")
            return

        def run(job):
            return nup_edit(path, **kw)

        def ok(p) -> None:
            self.log(f"Edited {KIND_LABEL.get(p.kind, p.kind)} package "
                     f"{p.title_id:016X}", "ok")
            self.load_info()          # refresh stats/table/tree

        self.start_job(run, "Edit metadata", ok)

    # ---- pack --------------------------------------------------------------

    def browse_pack_src(self) -> None:
        start = self.pk_src.text().strip() or self.settings.value(
            "last_dir", os.path.expanduser("~"))
        path = QFileDialog.getExistingDirectory(self, "Dump directory", start)
        if path:
            self.pk_src.setText(path)
            if not self.pk_out.text().strip():
                self.pk_out.setText(os.path.join(
                    os.path.dirname(path), os.path.basename(path) + ".nup"))

    def browse_pack_out(self) -> None:
        start = self.pk_out.text().strip() or self.settings.value(
            "last_dir", os.path.expanduser("~"))
        path, _ = QFileDialog.getSaveFileName(
            self, "Save container", start, "NUP (*.nup)")
        if path:
            if not path.lower().endswith(".nup"):
                path += ".nup"
            self.pk_out.setText(path)

    def run_pack(self) -> None:
        src = self.pk_src.text().strip()
        out = self.pk_out.text().strip()
        if not src or not os.path.isdir(src):
            QMessageBox.warning(self, "Not found",
                                "The source directory does not exist.")
            return
        if not out:
            QMessageBox.warning(self, "Missing", "Choose an output path.")
            return
        if not out.lower().endswith(".nup"):
            out += ".nup"
        out = os.path.abspath(out)
        self.pk_out.setText(out)
        # never pack inside the dump tree - pack walks the source and would
        # swallow its own growing output (content-dir dumps)
        out_dir = os.path.normcase(os.path.normpath(os.path.dirname(out)))
        src_n = os.path.normcase(os.path.normpath(os.path.abspath(src)))
        if out_dir == src_n or out_dir.startswith(src_n + os.sep):
            QMessageBox.warning(
                self, "Invalid output",
                "The output file cannot live inside the dump folder —\n"
                "choose a destination outside the source (next to it).")
            return
        replacing = os.path.exists(out)
        if replacing:
            answer = QMessageBox.question(
                self, "Output exists",
                f"{out}\nalready exists. Replace it?\n"
                "(the old file is kept until the new pack succeeds)",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if answer != QMessageBox.StandardButton.Yes:
                self.log("Pack cancelled — output exists")
                return
        tid_text = self.pk_tid.text().strip()
        tid = None
        if tid_text:
            if not (1 <= len(tid_text) <= 16) or any(
                    c not in "0123456789abcdefABCDEF" for c in tid_text):
                QMessageBox.warning(
                    self, "Invalid title ID",
                    "Enter 1-16 hexadecimal digits only.")
                return
            tid = int(tid_text, 16)
        level = self.pk_level.value()
        name = self.pk_name.text().strip()
        pub = self.pk_pub.text().strip()
        dispver = self.pk_dispver.text().strip()
        icon = self.pk_icon.text().strip()
        split = self.pk_split.isChecked()
        keep = self.pk_keep.isChecked()
        self.settings.setValue("zstd_level", level)

        def run(job):
            def prog(done, total, fnode):
                job.prog.emit(done, total,
                              fnode.name.decode("utf-8", "surrogateescape"))

            return nup_pack(
                out, src, level=level, keep_listings=keep, base_title_id=tid,
                display_version=dispver, publisher=pub,
                names={None: name} if name else {},
                icons={None: icon} if icon else {},
                split=split, replace=replacing, progress=prog)

        def ok(packages) -> None:
            lines = [f"{F.KIND_NAMES[p.kind]:<8} {p.title_id:016X} "
                     f"v{p.version} <- {p.src}" for p in packages]
            for ln in lines:
                self.log("  " + ln)
            size = os.path.getsize(out) if os.path.exists(out) else 0
            self.pk_summary.setText(
                f"Packed {len(lines)} package(s), {size:,} bytes\n" +
                "\n".join(lines))
            self.log(f"Wrote {out} ({size:,} bytes)", "ok")
            if os.path.exists(out):
                self.set_active_file(out)

        self.start_job(run, "Pack", ok)

    # ---- unpack & direct convert ------------------------------------------

    def _on_unpack_mode_changed(self) -> None:
        is_convert = self.un_mode_convert.isChecked()
        self.un_out_lbl.setText("Output container:" if is_convert else "Output folder:")
        self.un_out.setPlaceholderText(
            "output container (e.g. D:/Game.nup)" if is_convert else
            "output folder (will contain base/, updates/, dlc/, _meta/)"
        )
        self.un_level_form_label.setVisible(is_convert)
        self.un_level_row.setVisible(is_convert)
        self.un_merge_siblings.setVisible(is_convert)
        self.un_multicore.setVisible(is_convert)
        self.un_start_btn.setText("Start Direct Convert" if is_convert else "Start Unpack")
        if not getattr(self, "_unpack_running", False):
            self.un_stage_lbl.setText("Ready to convert" if is_convert else "Ready to unpack")
        src = self.un_src.text().strip()
        if src:
            p = Path(src)
            cur = self.un_out.text().strip()
            stem = p.name if p.is_dir() else p.stem
            if is_convert and (not cur or cur.endswith("_dump")):
                self.un_out.setText(str(p.parent / f"{stem}.nup"))
            elif not is_convert and (not cur or cur.endswith(".nup")):
                self.un_out.setText(str(p.parent / f"{stem}_dump"))

    def browse_unpack_src(self) -> None:
        start = self.settings.value("last_dir", os.path.expanduser("~"))
        path, _ = QFileDialog.getOpenFileName(
            self, "Select game dump to convert / unpack", start,
            "Switch dumps (*.nsp *.nsz *.xci *.xcz *.nca *.ncz);;All files (*)")
        if path:
            self.settings.setValue("last_dir", os.path.dirname(path))
            self.un_src.setText(path)
            cur = self.un_out.text().strip()
            p = Path(path)
            is_convert = self.un_mode_convert.isChecked()
            if not cur or cur.endswith(".nup") or cur.endswith("_dump"):
                self.un_out.setText(str(p.parent / (f"{p.stem}.nup" if is_convert else f"{p.stem}_dump")))

    def browse_unpack_src_folder(self) -> None:
        start = self.settings.value("last_dir", os.path.expanduser("~"))
        path = QFileDialog.getExistingDirectory(self, "Select dump directory to convert", start)
        if path:
            self.settings.setValue("last_dir", path)
            self.un_src.setText(path)
            cur = self.un_out.text().strip()
            p = Path(path)
            is_convert = self.un_mode_convert.isChecked()
            if not cur or cur.endswith(".nup") or cur.endswith("_dump"):
                self.un_out.setText(str(p.parent / (f"{p.name}.nup" if is_convert else f"{p.name}_dump")))

    def browse_unpack_out(self) -> None:
        start = self.settings.value("last_dir", os.path.expanduser("~"))
        if self.un_mode_convert.isChecked():
            path, _ = QFileDialog.getSaveFileName(
                self, "Save .nup container", start, "NUP containers (*.nup);;All files (*)")
            if path:
                if not path.lower().endswith(".nup"):
                    path += ".nup"
                self.un_out.setText(path)
        else:
            d = QFileDialog.getExistingDirectory(self, "Select output folder", start)
            if d:
                self.un_out.setText(d)

    def browse_unpack_keys(self) -> None:
        start = self.settings.value("last_dir", os.path.expanduser("~"))
        path, _ = QFileDialog.getOpenFileName(
            self, "Select prod.keys", start, "Key files (*.keys *.txt);;All files (*)")
        if path:
            self.un_keys.setText(path)

    def browse_unpack_base(self) -> None:
        start = self.settings.value("last_dir", os.path.expanduser("~"))
        path, _ = QFileDialog.getOpenFileName(
            self, "Select base package", start,
            "Switch dumps (*.nsp *.nsz *.xci *.xcz);;All files (*)")
        if path:
            self.un_base.setText(path)

    def start_unpack(self) -> None:
        src = self.un_src.text().strip()
        out = self.un_out.text().strip()
        if not src or (not os.path.isfile(src) and not os.path.isdir(src)):
            QMessageBox.warning(self, "Not found",
                                "The source dump file or directory does not exist.")
            return

        is_convert = self.un_mode_convert.isChecked()
        if is_convert:
            if not out:
                QMessageBox.warning(self, "Missing",
                                    "Choose an output .nup file for the container.")
                return
            if not out.lower().endswith(".nup"):
                out += ".nup"
            out_p = Path(out)
            if out_p.is_file() and not getattr(self, "auto_confirm_overwrite", False):
                reply = QMessageBox.question(
                    self,
                    "Container Exists",
                    f"The output container already exists:\n{out}\n\n"
                    "Do you want to overwrite and replace it?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if reply != QMessageBox.StandardButton.Yes:
                    return

            from nup.convert import convert
            from nup.switchfs import Progress
            level = 0 if self.un_fast.isChecked() else self.un_level.value()
            fast = self.un_fast.isChecked()
            keys = Path(self.un_keys.text().strip()) if self.un_keys.text().strip() else None
            base = Path(self.un_base.text().strip()) if self.un_base.text().strip() else None
            no_control = self.un_no_control.isChecked()
            merge_siblings = self.un_merge_siblings.isChecked()
            threads = -1 if self.un_multicore.isChecked() else 0

            self._unpack_running = True
            self._unpack_stage = "scan"
            self._unpack_current = ""
            self._unpack_done_files = 0
            self._unpack_total_files = 0
            self.un_stage_lbl.setText("Starting direct conversion…")
            self.un_cancel_btn.setEnabled(True)
            self.un_start_btn.setEnabled(False)

            def convert_worker(job: Job) -> dict[str, object]:
                def cb(p: Progress) -> None:
                    self._unpack_stage = p.stage
                    job.prog.emit(p.done, p.total, p.current)
                    job.bytesig.emit(float(p.bytes_done), float(p.bytes_total))
                    job.stage.emit(p.stage)
                    for w in p.warnings:
                        job.note.emit(f"warning: {w}", "warn")

                pkgs = convert(
                    Path(src),
                    Path(out),
                    keys_path=keys,
                    base=base,
                    compression_level=level,
                    fast=fast,
                    no_control=no_control,
                    merge_siblings=merge_siblings,
                    threads=threads,
                    replace=True,
                    progress=cb,
                    cancel=job.cancelled.is_set,
                )
                return {"src": src, "out": out, "count": len(pkgs)}

            def on_convert_done(res: dict[str, object]) -> None:
                self._unpack_running = False
                self.un_cancel_btn.setEnabled(False)
                self.un_start_btn.setEnabled(True)
                self.un_stage_lbl.setText("Conversion complete!")
                pkg_count = res.get("count", 1)
                self.un_live_lbl.setText(f"Container created: {res['out']} ({pkg_count} package(s))")
                self.log(f"Direct convert succeeded: {res['out']} ({pkg_count} package(s))", "ok")
                if not getattr(self, "auto_confirm_overwrite", False):
                    reply = QMessageBox.question(
                        self,
                        "Conversion Finished",
                        f"Successfully converted dump to:\n{res['out']}\n({pkg_count} package(s))\n\n"
                        "Would you like to open and inspect this container now?",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                        QMessageBox.StandardButton.Yes,
                    )
                    if reply == QMessageBox.StandardButton.Yes:
                        self.set_active_file(str(res["out"]))
                        self.goto_page(PAGE_INFO)

            self.start_job(convert_worker, f"Convert {Path(src).name}", on_convert_done)
            return

        # Traditional unpack to directory
        if not out:
            QMessageBox.warning(self, "Missing",
                                "Choose an output folder for the unpacked dump.")
            return

        out_p = Path(out)
        if out_p.is_dir() and any(out_p.iterdir()):
            if not getattr(self, "auto_confirm_overwrite", False):
                reply = QMessageBox.question(
                    self,
                    "Directory Not Empty",
                    f"The output directory is not empty:\n{out}\n\n"
                    "Do you want to overwrite and replace its contents?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if reply != QMessageBox.StandardButton.Yes:
                    return

        from nup.switchfs import unpack, Progress
        keys = Path(self.un_keys.text().strip()) if self.un_keys.text().strip() else None
        base = Path(self.un_base.text().strip()) if self.un_base.text().strip() else None
        no_control = self.un_no_control.isChecked()

        self._unpack_running = True
        self._unpack_stage = "scan"
        self._unpack_current = ""
        self._unpack_done_files = 0
        self._unpack_total_files = 0
        self.un_stage_lbl.setText("Starting unpack…")
        self.un_cancel_btn.setEnabled(True)
        self.un_start_btn.setEnabled(False)

        def worker(job: Job) -> dict[str, str]:
            def cb(p: Progress) -> None:
                self._unpack_stage = p.stage
                job.prog.emit(p.done, p.total, p.current)
                job.bytesig.emit(float(p.bytes_done), float(p.bytes_total))
                job.stage.emit(p.stage)
                for w in p.warnings:
                    job.note.emit(f"warning: {w}", "warn")

            unpack(
                Path(src),
                Path(out),
                keys_path=keys,
                base=base,
                no_control=no_control,
                replace=True,
                progress=cb,
                cancel=job.cancelled.is_set,
            )
            return {"src": src, "out": out}

        def on_done(res: dict[str, str]) -> None:
            self._unpack_running = False
            self.un_cancel_btn.setEnabled(False)
            self.un_start_btn.setEnabled(True)
            self.un_stage_lbl.setText("Unpack complete!")
            self.un_live_lbl.setText(f"Dump extracted to: {res['out']}")
            self.log(f"Unpack succeeded: {res['out']}", "ok")
            if not getattr(self, "auto_confirm_overwrite", False):
                reply = QMessageBox.question(
                    self,
                    "Unpack Finished",
                    f"Successfully unpacked dump to:\n{res['out']}\n\n"
                    "Would you like to hand off this directory to Auto Build to pack into .nup?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.Yes,
                )
                if reply == QMessageBox.StandardButton.Yes:
                    self.goto_page(PAGE_AUTO)
                    self.start_auto(res["out"])

        self.start_job(worker, f"Unpack {Path(src).name}", on_done)

    def cancel_unpack(self) -> None:
        if self.job and self.job.isRunning():
            self.job.cancelled.set()
            self.un_cancel_btn.setEnabled(False)
            self.un_stage_lbl.setText("Cancelling…")
            self.log("Unpack cancelled by user", "warn")

    # ---- batch convert ----------------------------------------------------

    def _build_batch_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(14)

        h = QLabel("BATCH CONVERT")
        h.setProperty("h1", True)
        sub = QLabel("Scan an entire folder of mixed Switch dumps (.nsp, .nsz, .xci, .xcz), "
                     "group bases with updates and DLCs, and convert all into verified All-in-One .nup containers.")
        sub.setProperty("muted", True)
        sub.setWordWrap(True)
        lay.addWidget(h)
        lay.addWidget(sub)

        # Directory Configuration Card
        box_dirs = QGroupBox("Directory Configuration")
        form = QFormLayout(box_dirs)
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        # Source folder
        s_row = QHBoxLayout()
        s_row.setSpacing(6)
        self.bat_src = QLineEdit()
        self.bat_src.setPlaceholderText("Directory containing Switch game dumps (.nsp, .nsz, .xci, .xcz)…")
        sb = QPushButton("Browse…")
        sb.setIcon(QIcon(create_nav_icon("extract")))
        sb.clicked.connect(self.browse_batch_src)
        s_row.addWidget(self.bat_src, 1)
        s_row.addWidget(sb)
        sw = QWidget()
        sw.setLayout(s_row)
        form.addRow("Dumps directory:", sw)

        # Destination folder
        o_row = QHBoxLayout()
        o_row.setSpacing(6)
        self.bat_out = QLineEdit()
        self.bat_out.setPlaceholderText("Directory where .nup containers will be written…")
        ob = QPushButton("Browse…")
        ob.setIcon(QIcon(create_nav_icon("extract")))
        ob.clicked.connect(self.browse_batch_out)
        o_row.addWidget(self.bat_out, 1)
        o_row.addWidget(ob)
        ow = QWidget()
        ow.setLayout(o_row)
        form.addRow("Output folder:", ow)
        lay.addWidget(box_dirs)

        # Conversion Options Card
        box_opts = QGroupBox("Performance && Filtering")
        opt_lay = QVBoxLayout(box_opts)
        opt_lay.setSpacing(7)
        self.bat_multicore = QCheckBox("Multi-core compression (fastest, parallel Zstandard across all CPU cores)")
        self.bat_multicore.setChecked(True)
        self.bat_fast = QCheckBox("Fast mode (skip deep SHA-256 recompute)")
        self.bat_force = QCheckBox("Overwrite existing containers if they exist")
        self.bat_no_ctrl = QCheckBox("Skip Control NCA metadata and icons")
        opt_lay.addWidget(self.bat_multicore)
        opt_lay.addWidget(self.bat_fast)
        opt_lay.addWidget(self.bat_force)
        opt_lay.addWidget(self.bat_no_ctrl)
        lay.addWidget(box_opts)

        # Tracking Card
        card = QFrame()
        card.setObjectName("trackCard")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(18, 14, 18, 14)
        cl.setSpacing(8)

        self.bat_stage_lbl = QLabel("Ready to batch convert")
        self.bat_stage_lbl.setStyleSheet("font-size:15px; font-weight:800; color:#ffd75e;")
        cl.addWidget(self.bat_stage_lbl)

        self.bat_live_lbl = QLabel("—")
        self.bat_live_lbl.setProperty("muted", True)
        self.bat_live_lbl.setWordWrap(True)
        cl.addWidget(self.bat_live_lbl)

        self.bat_bar = QProgressBar()
        self.bat_bar.setRange(0, 100)
        self.bat_bar.setValue(0)
        cl.addWidget(self.bat_bar)

        lay.addWidget(card)

        # Action Buttons
        row = QHBoxLayout()
        row.setSpacing(10)
        self.bat_start_btn = QPushButton("  Start Batch Convert")
        self.bat_start_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))
        self.bat_start_btn.setProperty("primary", True)
        self.bat_start_btn.setFixedHeight(40)
        self.bat_start_btn.clicked.connect(self.start_batch)

        self.bat_cancel_btn = QPushButton("Cancel")
        self.bat_cancel_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogCancelButton))
        self.bat_cancel_btn.setEnabled(False)
        self.bat_cancel_btn.setFixedHeight(40)
        self.bat_cancel_btn.clicked.connect(self.cancel_batch)

        row.addWidget(self.bat_start_btn)
        row.addWidget(self.bat_cancel_btn)
        row.addStretch(1)
        lay.addLayout(row)

        lay.addStretch(1)
        return w

    def browse_batch_src(self) -> None:
        start = self.settings.value("last_dir", os.path.expanduser("~"))
        path = QFileDialog.getExistingDirectory(self, "Select dumps directory", start)
        if path:
            self.settings.setValue("last_dir", path)
            self.bat_src.setText(path)
            if not self.bat_out.text().strip():
                p = Path(path)
                self.bat_out.setText(str(p.parent / f"{p.name}_nup"))

    def browse_batch_out(self) -> None:
        start = self.settings.value("last_dir", os.path.expanduser("~"))
        d = QFileDialog.getExistingDirectory(self, "Select output folder", start)
        if d:
            self.bat_out.setText(d)

    def start_batch(self) -> None:
        src = self.bat_src.text().strip()
        out = self.bat_out.text().strip()
        if not src or not os.path.isdir(src):
            QMessageBox.warning(self, "Not found", "The source dumps directory does not exist.")
            return
        if not out:
            QMessageBox.warning(self, "Missing", "Choose an output directory for converted containers.")
            return

        from nup.batch import batch_convert
        from nup.switchfs import Progress
        threads = -1 if self.bat_multicore.isChecked() else 0
        fast = self.bat_fast.isChecked()
        force = self.bat_force.isChecked()
        no_ctrl = self.bat_no_ctrl.isChecked()

        self._batch_running = True
        self.bat_stage_lbl.setText("Starting batch conversion…")
        self.bat_cancel_btn.setEnabled(True)
        self.bat_start_btn.setEnabled(False)

        def worker(job: Job) -> dict[str, object]:
            def cb(p: Progress) -> None:
                job.prog.emit(p.done, p.total, p.current)
                job.bytesig.emit(float(p.bytes_done), float(p.bytes_total))
                job.stage.emit(p.stage)

            res = batch_convert(
                Path(src),
                Path(out),
                threads=threads,
                fast=fast,
                replace=force,
                no_control=no_ctrl,
                progress=cb,
                cancel=job.cancelled.is_set,
            )
            return {"total": res.total_games, "succeeded": res.succeeded, "failed": res.failed, "containers": res.containers}

        def on_done(res: dict[str, object]) -> None:
            self._batch_running = False
            self.bat_cancel_btn.setEnabled(False)
            self.bat_start_btn.setEnabled(True)
            self.bat_stage_lbl.setText("Batch conversion complete!")
            succ = res.get("succeeded", 0)
            tot = res.get("total", 0)
            fail = res.get("failed", 0)
            self.bat_live_lbl.setText(f"Batch finished: {succ}/{tot} game(s) converted ({fail} failed)")
            self.log(f"Batch convert: {succ}/{tot} succeeded, {fail} failed", "ok" if fail == 0 else "warn")
            containers = res.get("containers", [])
            if containers and isinstance(containers, list):
                self.set_active_file(str(containers[0]))

        self.start_job(worker, f"Batch {Path(src).name}", on_done)

    def cancel_batch(self) -> None:
        if self.job and self.job.isRunning():
            self.job.cancelled.set()
            self.bat_cancel_btn.setEnabled(False)
            self.bat_stage_lbl.setText("Cancelling…")
            self.log("Batch cancelled by user", "warn")

    # ---- mod patch --------------------------------------------------------

    def _build_patch_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(14)

        h = QLabel("MOD MANAGER & PATCHER")
        h.setProperty("h1", True)
        sub = QLabel("Apply LayeredFS mod directories, Atmosphere contents folders, or translations "
                     "directly onto an existing .nup container with virtual in-memory streaming and atomic verification.")
        sub.setProperty("muted", True)
        sub.setWordWrap(True)
        lay.addWidget(h)
        lay.addWidget(sub)

        # Target Container & Mod Files Card
        box_dirs = QGroupBox("Target Container && Mod Files")
        form = QFormLayout(box_dirs)
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        # Target container
        c_row = QHBoxLayout()
        c_row.setSpacing(6)
        self.pat_container = QLineEdit()
        self.pat_container.setPlaceholderText("Select target .nup container file to patch…")
        cb = QPushButton("Browse…")
        cb.setIcon(QIcon(create_nav_icon("extract")))
        cb.clicked.connect(self.browse_patch_container)
        c_row.addWidget(self.pat_container, 1)
        c_row.addWidget(cb)
        cw = QWidget()
        cw.setLayout(c_row)
        form.addRow("Target container:", cw)

        # Mod directory
        m_row = QHBoxLayout()
        m_row.setSpacing(6)
        self.pat_mod = QLineEdit()
        self.pat_mod.setPlaceholderText("Directory containing LayeredFS romfs/exefs or Atmosphere contents/<tid>…")
        mb = QPushButton("Browse…")
        mb.setIcon(QIcon(create_nav_icon("extract")))
        mb.clicked.connect(self.browse_patch_mod)
        m_row.addWidget(self.pat_mod, 1)
        m_row.addWidget(mb)
        mw = QWidget()
        mw.setLayout(m_row)
        form.addRow("Mod directory:", mw)

        # Destination container (optional)
        o_row = QHBoxLayout()
        o_row.setSpacing(6)
        self.pat_out = QLineEdit()
        self.pat_out.setPlaceholderText("Output .nup path (leave blank for safe in-place atomic update)…")
        ob = QPushButton("Browse…")
        ob.setIcon(QIcon(create_nav_icon("extract")))
        ob.clicked.connect(self.browse_patch_out)
        o_row.addWidget(self.pat_out, 1)
        o_row.addWidget(ob)
        ow = QWidget()
        ow.setLayout(o_row)
        form.addRow("Output container:", ow)

        # Target package
        self.pat_pkg = QComboBox()
        self.pat_pkg.addItem("Auto (Base game or matching Atmosphere Title ID)", None)
        form.addRow("Target package:", self.pat_pkg)
        lay.addWidget(box_dirs)

        # Options Card
        box_opts = QGroupBox("Patching Configuration")
        popt_lay = QVBoxLayout(box_opts)
        popt_lay.setSpacing(7)
        self.pat_multicore = QCheckBox("Multi-core compression (fastest, parallel Zstandard across all CPU cores)")
        self.pat_multicore.setChecked(True)
        self.pat_fast = QCheckBox("Fast mode (skip deep SHA-256 re-verification)")
        popt_lay.addWidget(self.pat_multicore)
        popt_lay.addWidget(self.pat_fast)
        lay.addWidget(box_opts)

        # Tracking Card
        card = QFrame()
        card.setObjectName("trackCard")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(18, 14, 18, 14)
        cl.setSpacing(8)

        self.pat_stage_lbl = QLabel("Ready to apply mod")
        self.pat_stage_lbl.setStyleSheet("font-size:15px; font-weight:800; color:#ffd75e;")
        cl.addWidget(self.pat_stage_lbl)

        self.pat_live_lbl = QLabel("—")
        self.pat_live_lbl.setProperty("muted", True)
        self.pat_live_lbl.setWordWrap(True)
        cl.addWidget(self.pat_live_lbl)

        self.pat_bar = QProgressBar()
        self.pat_bar.setRange(0, 100)
        self.pat_bar.setValue(0)
        cl.addWidget(self.pat_bar)

        lay.addWidget(card)

        # Action Buttons
        row = QHBoxLayout()
        row.setSpacing(10)
        self.pat_start_btn = QPushButton("  Apply Mod Patch")
        self.pat_start_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogApplyButton))
        self.pat_start_btn.setProperty("primary", True)
        self.pat_start_btn.setFixedHeight(40)
        self.pat_start_btn.clicked.connect(self.start_patch)

        self.pat_cancel_btn = QPushButton("Cancel")
        self.pat_cancel_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogCancelButton))
        self.pat_cancel_btn.setEnabled(False)
        self.pat_cancel_btn.setFixedHeight(40)
        self.pat_cancel_btn.clicked.connect(self.cancel_patch)

        row.addWidget(self.pat_start_btn)
        row.addWidget(self.pat_cancel_btn)
        row.addStretch(1)
        lay.addLayout(row)

        lay.addStretch(1)
        return w

    def browse_patch_container(self) -> None:
        start = self.settings.value("last_dir", os.path.expanduser("~"))
        path, _ = QFileDialog.getOpenFileName(
            self, "Select .nup container to patch", start, "NUP containers (*.nup);;All files (*)")
        if path:
            self.pat_container.setText(path)

    def browse_patch_mod(self) -> None:
        start = self.settings.value("last_dir", os.path.expanduser("~"))
        path = QFileDialog.getExistingDirectory(self, "Select mod directory", start)
        if path:
            self.pat_mod.setText(path)

    def browse_patch_out(self) -> None:
        start = self.settings.value("last_dir", os.path.expanduser("~"))
        path, _ = QFileDialog.getSaveFileName(
            self, "Save patched container as", start, "NUP containers (*.nup);;All files (*)")
        if path:
            if not path.lower().endswith(".nup"):
                path += ".nup"
            self.pat_out.setText(path)

    def start_patch(self) -> None:
        cont = self.pat_container.text().strip()
        mod = self.pat_mod.text().strip()
        out = self.pat_out.text().strip() or None
        if not cont or not os.path.isfile(cont):
            QMessageBox.warning(self, "Not found", "The target .nup container does not exist.")
            return
        if not mod or not os.path.isdir(mod):
            QMessageBox.warning(self, "Not found", "The mod directory does not exist.")
            return

        from nup.patch import patch
        from nup.switchfs import Progress
        threads = -1 if self.pat_multicore.isChecked() else 0
        fast = self.pat_fast.isChecked()
        pkg = self.pat_pkg.currentData()

        self._patch_running = True
        self.pat_stage_lbl.setText("Starting mod patch…")
        self.pat_cancel_btn.setEnabled(True)
        self.pat_start_btn.setEnabled(False)

        def worker(job: Job) -> dict[str, object]:
            def cb(p: Progress) -> None:
                job.prog.emit(p.done, p.total, p.current)
                job.bytesig.emit(float(p.bytes_done), float(p.bytes_total))
                job.stage.emit(p.stage)

            res = patch(
                Path(cont),
                Path(mod),
                Path(out) if out else None,
                package=pkg,
                threads=threads,
                fast=fast,
                replace=True,
                progress=cb,
                cancel=job.cancelled.is_set,
            )
            return {"replaced": res.files_replaced, "added": res.files_added, "total": res.total_files, "out": str(res.container_path)}

        def on_done(res: dict[str, object]) -> None:
            self._patch_running = False
            self.pat_cancel_btn.setEnabled(False)
            self.pat_start_btn.setEnabled(True)
            self.pat_stage_lbl.setText("Mod patch complete!")
            rep = res.get("replaced", 0)
            add = res.get("added", 0)
            tot = res.get("total", 0)
            out_p = res.get("out", "")
            self.pat_live_lbl.setText(f"Mod applied: {rep} replaced, {add} added ({tot} total files)")
            self.log(f"Patch applied: {rep} replaced, {add} added -> {out_p}", "ok")
            if out_p:
                self.set_active_file(str(out_p))

        self.start_job(worker, f"Patch {Path(cont).name}", on_done)

    def cancel_patch(self) -> None:
        if self.job and self.job.isRunning():
            self.job.cancelled.set()
            self.pat_cancel_btn.setEnabled(False)
            self.pat_stage_lbl.setText("Cancelling…")
            self.log("Patch cancelled by user", "warn")

    # ---- export -----------------------------------------------------------

    def _build_export_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(14)

        h = QLabel("BIDIRECTIONAL EXPORTER")
        h.setProperty("h1", True)
        sub = QLabel("Export a .nup container back into Atmosphere SD card layout (ready for MicroSD), "
                     "standard multi-package dump directory, or installable Nintendo Submission Package (.nsp).")
        sub.setProperty("muted", True)
        sub.setWordWrap(True)
        lay.addWidget(h)
        lay.addWidget(sub)

        # Container & Target Directory Card
        box_dirs = QGroupBox("Container && Target Directory")
        form = QFormLayout(box_dirs)
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        # Source container
        c_row = QHBoxLayout()
        c_row.setSpacing(6)
        self.exp_container = QLineEdit()
        self.exp_container.setPlaceholderText("Select .nup container file to export from…")
        cb = QPushButton("Browse…")
        cb.setIcon(QIcon(create_nav_icon("extract")))
        cb.clicked.connect(self.browse_export_container)
        c_row.addWidget(self.exp_container, 1)
        c_row.addWidget(cb)
        cw = QWidget()
        cw.setLayout(c_row)
        form.addRow("Source container:", cw)

        # Destination folder / file
        o_row = QHBoxLayout()
        o_row.setSpacing(6)
        self.exp_out = QLineEdit()
        self.exp_out.setPlaceholderText("Destination directory (or MicroSD drive letter, e.g. E:\\)…")
        ob = QPushButton("Browse…")
        ob.setIcon(QIcon(create_nav_icon("extract")))
        ob.clicked.connect(self.browse_export_out)
        o_row.addWidget(self.exp_out, 1)
        o_row.addWidget(ob)
        ow = QWidget()
        ow.setLayout(o_row)
        form.addRow("Destination:", ow)
        lay.addWidget(box_dirs)

        # Format & Package Card
        box_fmt = QGroupBox("Export Configuration")
        form_fmt = QFormLayout(box_fmt)
        form_fmt.setSpacing(10)
        form_fmt.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        # Format selector
        self.exp_fmt = QComboBox()
        self.exp_fmt.addItem("Atmosphere SD Structure (atmosphere/contents/<tid>/...)", "atmosphere")
        self.exp_fmt.addItem("Installable NSP Package (.nsp)", "nsp")
        self.exp_fmt.addItem("Standard Multi-Package Dump Layout", "dump")
        form_fmt.addRow("Export format:", self.exp_fmt)

        # Package selector
        self.exp_pkg = QComboBox()
        self.exp_pkg.addItem("Base game (default)", None)
        form_fmt.addRow("Package to export:", self.exp_pkg)
        lay.addWidget(box_fmt)

        # Tracking Card
        card = QFrame()
        card.setObjectName("trackCard")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(18, 14, 18, 14)
        cl.setSpacing(8)

        self.exp_stage_lbl = QLabel("Ready to export")
        self.exp_stage_lbl.setStyleSheet("font-size:15px; font-weight:800; color:#ffd75e;")
        cl.addWidget(self.exp_stage_lbl)

        self.exp_live_lbl = QLabel("—")
        self.exp_live_lbl.setProperty("muted", True)
        self.exp_live_lbl.setWordWrap(True)
        cl.addWidget(self.exp_live_lbl)

        self.exp_bar = QProgressBar()
        self.exp_bar.setRange(0, 100)
        self.exp_bar.setValue(0)
        cl.addWidget(self.exp_bar)

        lay.addWidget(card)

        # Action Buttons
        row = QHBoxLayout()
        row.setSpacing(10)
        self.exp_start_btn = QPushButton("  Export Container")
        self.exp_start_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ArrowUp))
        self.exp_start_btn.setProperty("primary", True)
        self.exp_start_btn.setFixedHeight(40)
        self.exp_start_btn.clicked.connect(self.start_export)

        self.exp_cancel_btn = QPushButton("Cancel")
        self.exp_cancel_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogCancelButton))
        self.exp_cancel_btn.setEnabled(False)
        self.exp_cancel_btn.setFixedHeight(40)
        self.exp_cancel_btn.clicked.connect(self.cancel_export)

        row.addWidget(self.exp_start_btn)
        row.addWidget(self.exp_cancel_btn)
        row.addStretch(1)
        lay.addLayout(row)

        lay.addStretch(1)
        return w

    def browse_export_container(self) -> None:
        start = self.settings.value("last_dir", os.path.expanduser("~"))
        path, _ = QFileDialog.getOpenFileName(
            self, "Select .nup container to export", start, "NUP containers (*.nup);;All files (*)")
        if path:
            self.exp_container.setText(path)

    def browse_export_out(self) -> None:
        start = self.settings.value("last_dir", os.path.expanduser("~"))
        fmt = self.exp_fmt.currentData()
        if fmt == "nsp":
            path, _ = QFileDialog.getSaveFileName(
                self, "Save .nsp package as", start, "NSP packages (*.nsp);;All files (*)")
            if path:
                if not path.lower().endswith(".nsp"):
                    path += ".nsp"
                self.exp_out.setText(path)
        else:
            d = QFileDialog.getExistingDirectory(self, "Select destination directory", start)
            if d:
                self.exp_out.setText(d)

    def start_export(self) -> None:
        cont = self.exp_container.text().strip()
        out = self.exp_out.text().strip()
        if not cont or not os.path.isfile(cont):
            QMessageBox.warning(self, "Not found", "The source .nup container does not exist.")
            return
        if not out:
            QMessageBox.warning(self, "Missing", "Choose a destination directory or file.")
            return

        from nup.export import export_container
        from nup.switchfs import Progress
        fmt = self.exp_fmt.currentData() or "atmosphere"
        pkg = self.exp_pkg.currentData()

        self._export_running = True
        self.exp_stage_lbl.setText(f"Starting {fmt} export…")
        self.exp_cancel_btn.setEnabled(True)
        self.exp_start_btn.setEnabled(False)

        def worker(job: Job) -> dict[str, object]:
            def cb(p: Progress) -> None:
                job.prog.emit(p.done, p.total, p.current)
                job.bytesig.emit(float(p.bytes_done), float(p.bytes_total))
                job.stage.emit(p.stage)

            res = export_container(
                Path(cont),
                Path(out),
                fmt=fmt,
                package=pkg,
                replace=True,
                progress=cb,
                cancel=job.cancelled.is_set,
            )
            return {"files": res.files_exported, "out": str(res.output_path), "fmt": res.format}

        def on_done(res: dict[str, object]) -> None:
            self._export_running = False
            self.exp_cancel_btn.setEnabled(False)
            self.exp_start_btn.setEnabled(True)
            self.exp_stage_lbl.setText("Export complete!")
            files = res.get("files", 0)
            out_p = res.get("out", "")
            fmt_name = res.get("fmt", "")
            self.exp_live_lbl.setText(f"Exported {files} files ({fmt_name}) -> {out_p}")
            self.log(f"Exported {files} files ({fmt_name}) to {out_p}", "ok")

        self.start_job(worker, f"Export {Path(cont).name}", on_done)

    def cancel_export(self) -> None:
        if self.job and self.job.isRunning():
            self.job.cancelled.set()
            self.exp_cancel_btn.setEnabled(False)
            self.exp_stage_lbl.setText("Cancelling…")
            self.log("Export cancelled by user", "warn")

    # ---- auto pipeline (one-shot) -----------------------------------------

    def browse_auto_src(self) -> None:
        start = self.settings.value("last_dir", os.path.expanduser("~"))
        path = QFileDialog.getExistingDirectory(self, "Dump directory", start)
        if path:
            self.settings.setValue("last_dir", path)
            self.start_auto(path)

    def cancel_auto(self) -> None:
        """Request a cooperative stop of the running auto pipeline.

        Workers check the flag at file boundaries: pack then drops its
        .partial output, verify stops early - nothing is left half-written
        at the final path either way.
        """
        if not self._auto_running or self._auto_cancelled:
            return
        if self.job is None or not self.job.isRunning():
            return
        self._auto_cancelled = True
        self.job.cancelled.set()
        self.au_cancel_btn.setEnabled(False)
        self.set_status("Cancelling …")
        self.log("Cancel requested — stopping at the next file boundary …")

    def browse_auto_out(self) -> None:
        start = self.au_out.text().strip() or os.path.join(
            self.settings.value("last_dir", os.path.expanduser("~")), "")
        path, _ = QFileDialog.getSaveFileName(
            self, "Save container as", start, "NUP (*.nup)")
        if path:
            if not path.lower().endswith(".nup"):
                path += ".nup"
            self.au_out.setText(path)

    def start_auto(self, src: str) -> None:
        """Validate, resolve output (asking about overwrites) and launch the
        scan -> pack -> verify -> done pipeline. The output path comes from
        the OUTPUT field when filled, otherwise defaults next to the dump."""
        if not os.path.isdir(src):
            QMessageBox.warning(self, "Not found",
                                f"Directory does not exist:\n{src}")
            return
        out = self.au_out.text().strip()
        if not out:
            out = os.path.join(os.path.dirname(os.path.abspath(src)),
                               os.path.basename(os.path.abspath(src)) + ".nup")
        if not out.lower().endswith(".nup"):
            out += ".nup"
        out = os.path.abspath(out)
        if os.path.isdir(out):
            QMessageBox.warning(self, "Invalid output",
                                f"Output path is a directory:\n{out}")
            return
        if os.path.normcase(os.path.normpath(out)) == \
                os.path.normcase(os.path.normpath(os.path.abspath(src))):
            QMessageBox.warning(self, "Invalid output",
                                "Output cannot be the source directory.")
            return
        # never write the .nup inside the dump: pack walks the source, so a
        # file growing there can be swallowed mid-write (content-dir dumps)
        out_dir = os.path.normcase(os.path.normpath(os.path.dirname(out)))
        src_n = os.path.normcase(os.path.normpath(os.path.abspath(src)))
        if out_dir == src_n or out_dir.startswith(src_n + os.sep):
            QMessageBox.warning(
                self, "Invalid output",
                "The output file cannot live inside the dump folder —\n"
                "choose a destination outside the source (next to it).")
            return
        self.au_out.setText(out)          # show the resolved path
        parent = os.path.dirname(out)
        if parent and not os.path.isdir(parent):
            try:
                os.makedirs(parent, exist_ok=True)
            except OSError as e:
                QMessageBox.warning(
                    self, "Cannot create folder",
                    f"{parent}\n{e}")
                return
        if os.path.exists(out):
            if getattr(self, "auto_confirm_overwrite", False):
                self.log(f"Replacing existing output: {out}")
            else:
                answer = QMessageBox.question(
                    self, "Output exists",
                    f"{out}\nalready exists. Replace it?",
                    QMessageBox.StandardButton.Yes
                    | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No)
                if answer != QMessageBox.StandardButton.Yes:
                    self.log("Auto build cancelled — output exists")
                    return

        # reset the AUTO screen
        self._auto_running = True
        self._auto_cancelled = False
        self._auto_result = None
        self._auto_out = out
        for key in STAGES:
            chip = self.au_chips[key]
            chip.setProperty("chip", "pending")
            chip.style().unpolish(chip)
            chip.style().polish(chip)
        self.au_stage.setText("Starting…")
        self.au_files.setText("—")
        self.au_bytes.setText("—")
        self.au_speed.setText("—")
        self.au_eta.setText("—")
        self.au_cur.setText("—")
        self.au_bar.setValue(0)
        self._set_hp(self.au_bar, 100)
        self.au_result.hide()
        self.au_reveal.hide()
        self.au_elapsed_lbl.setText("")
        self.goto_page(PAGE_AUTO)
        self.log(f"Auto build: {src} -> {out}")

        level = int(self.settings.value("zstd_level", 3))

        def run(job) -> dict:
            # -- stage 1: scan (mirror Tree._walk: artifacts excluded) -----
            job.stage.emit("scan")
            total_files, total_bytes = scan_source(src)
            if total_files == 0:
                raise SystemExit("no packable files found in dump")
            job.prog.emit(0, total_files, "scan complete")
            job.bytesig.emit(0, total_bytes)
            if job.cancelled.is_set():
                raise SystemExit("cancelled during scan")
            # warn early instead of dying on disk-full minutes into the pack
            # (heuristic: a packed container is typically under half the dump)
            try:
                free = shutil.disk_usage(
                    os.path.dirname(out) or os.curdir).free
            except OSError:
                free = -1
            if 0 <= free < max(total_bytes // 2, 1 << 30):
                job.note.emit(
                    f"warning: only {free / (1 << 30):.1f} GB free for a "
                    f"{total_bytes / (1 << 30):.1f} GB dump — the output "
                    "may not fit", "err")

            # -- stage 2: pack (bytes accumulate from fnode.size) ----------
            job.stage.emit("pack")
            # replacement was confirmed on the UI side: pack writes a
            # .partial and swaps it in atomically, so if anything fails the
            # previous good output (if any) is still intact
            bdone = [0]
            last = [0.0]

            def prog(done: int, total: int, fnode) -> None:
                if job.cancelled.is_set():
                    raise SystemExit(
                        "cancelled during pack — partial output removed")
                bdone[0] += fnode.size
                now = time.time()
                if now - last[0] >= 0.1 or done == total:
                    last[0] = now
                    job.prog.emit(
                        done, total,
                        fnode.name.decode("utf-8", "surrogateescape"))
                    job.bytesig.emit(min(bdone[0], total_bytes), total_bytes)

            packages_built = nup_pack(out, src, level=level, replace=True,
                                      progress=prog)

            # -- stage 3: deep verify (with byte progress) -----------------
            job.stage.emit("verify")

            def vprog(done: int, total: int, bytes_done: int) -> None:
                if job.cancelled.is_set():
                    raise SystemExit(
                        "cancelled during verify — container kept, "
                        "not fully verified")
                now = time.time()
                if now - last[0] >= 0.1 or done == total:
                    last[0] = now
                    job.prog.emit(done, total, "verifying hashes")
                    job.bytesig.emit(min(bytes_done, total_bytes),
                                     total_bytes)

            ok_flag, problems = nup_verify(out, deep=True, progress=vprog)
            if not ok_flag:
                raise SystemExit(
                    "verify failed: " + "; ".join(problems[:3]))

            # -- stage 4: done --------------------------------------------
            job.stage.emit("done")
            return {
                "out": out,
                "packages": len(packages_built),
                "files": total_files,
                "bytes": total_bytes,
                "size": os.path.getsize(out),
            }

        def ok(res: dict) -> None:
            self._auto_running = False
            self._auto_result = res
            self.au_result.setText(
                f"<span style='color:#58d18b;font-weight:700'>✓ "
                f"{esc(res['out'])}</span><br>"
                f"{res['packages']} package(s) · {res['files']:,} files · "
                f"{fmt_bytes(res['bytes'])} packed → "
                f"{fmt_bytes(res['size'])} (deep-verified)")
            self.au_result.show()
            self.au_reveal.show()
            self.au_stage.setText("Complete — .nup is ready")
            self.au_eta.setText("0s")
            self.au_speed.setText("—")
            # open Info shortly after (the worker thread must be idle first)
            QTimer.singleShot(
                400, lambda p=res["out"]: self.set_active_file(p))

        self.start_job(run, "Auto build", ok)

    def _reveal_output(self) -> None:
        if not self._auto_out or not os.path.exists(self._auto_out):
            return
        if sys.platform == "win32":
            os.startfile(  # noqa: S606 (local explorer, user action)
                f'explorer /select,"{os.path.normpath(self._auto_out)}"')

    # ---- drag & drop -------------------------------------------------------

    def dragEnterEvent(self, event) -> None:  # noqa: N802 (Qt naming)
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:  # noqa: N802
        for url in event.mimeData().urls():
            p = url.toLocalFile()
            if not p:
                continue
            if os.path.isdir(p):
                # one-shot automation: dropping a dump starts the pipeline
                self.start_auto(p)
            elif p.lower().endswith(".nup"):
                self.set_active_file(p)
            break

    def closeEvent(self, event) -> None:  # noqa: N802
        if self.job is not None and self.job.isRunning():
            QMessageBox.warning(
                self, "Operation running",
                "Cannot close while a job is running — wait for it to finish.\n"
                "Killing the program mid-pack leaves a partial output file "
                "that you would have to delete manually.")
            event.ignore()
            return
        self.settings.setValue("geometry", self.saveGeometry())
        event.accept()


# ---- entry point -----------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="NUP GUI")
    parser.add_argument("--smoke", action="store_true",
                        help="open the window, then quit automatically")
    parser.add_argument("--file", help="container to open on startup")
    parser.add_argument("--auto", metavar="DUMP_DIR",
                        help="start the one-shot auto pipeline on this dump "
                             "(with --smoke: run it to completion and quit)")
    parser.add_argument("--out", metavar="NUP_PATH",
                        help="with --auto: where to write the .nup "
                             "(default: next to the dump folder)")
    parser.add_argument("--page",
                        choices=["auto", "info", "extract", "verify",
                                 "edit", "pack", "unpack", "convert", "batch", "patch", "export"],
                        help="open this page on startup")
    args = parser.parse_args(argv)

    app = QApplication([sys.argv[0]])
    app.setApplicationName("NUP GUI")
    families = QFontDatabase.families()
    for family in ("Segoe UI Variable Display", "Segoe UI"):
        if family in families:
            app.setFont(QFont(family, 10))
            break
    app.setStyleSheet(THEME)

    settings = QSettings("nupull", "Nupull")
    if not settings.contains("last_file"):
        old_s = QSettings("nup-gui", "NUP GUI")
        if old_s.contains("last_file"):
            settings.setValue("last_file", old_s.value("last_file"))
    win = MainWindow(settings)
    if args.smoke and args.auto:
        # e2e runs unattended: never pop a modal Replace/Cancel question
        win.auto_confirm_overwrite = True
    win.show()

    file_to_open = None
    if args.auto:
        pass                       # auto pipeline owns the screen
    elif args.file and os.path.isfile(args.file):
        file_to_open = args.file
    elif not args.file:
        last = settings.value("last_file", "")
        if last and os.path.isfile(str(last)):
            file_to_open = str(last)
    if file_to_open:
        QTimer.singleShot(200, lambda: win.set_active_file(file_to_open))

    if args.page:
        page_idx = {"auto": PAGE_AUTO, "info": PAGE_INFO,
                    "extract": PAGE_EXTRACT, "verify": PAGE_VERIFY,
                    "edit": PAGE_EDIT, "pack": PAGE_PACK,
                    "unpack": PAGE_UNPACK,
                    "convert": PAGE_UNPACK,
                    "batch": PAGE_BATCH,
                    "patch": PAGE_PATCH,
                    "export": PAGE_EXPORT}[args.page]
        delay = 1200 if file_to_open else 100
        QTimer.singleShot(delay, lambda: win.goto_page(page_idx))

    if args.auto:
        if not os.path.isdir(args.auto):
            print(f"SMOKE-FAIL: not a directory: {args.auto}")
            if args.smoke:
                return 1
            sys.exit(f"--auto: not a directory: {args.auto}")
        if args.out:
            win.au_out.setText(args.out)
        QTimer.singleShot(300, lambda: win.start_auto(args.auto))

    if args.smoke:
        # wait for the info job when a file was requested, else just quit
        waited = {"ms": 0}
        # auto pipeline e2e: deep-verify of a real dump can take minutes
        limit = 600_000 if args.auto else 20_000

        def tick():
            if args.auto:
                if win._auto_result is not None:
                    res = win._auto_result
                    print(f"SMOKE-AUTO-OK out={res['out']} "
                          f"files={res['files']} size={res['size']}")
                    app.quit()
                    return
                if not win._auto_running and waited["ms"] >= 4000:
                    # pipeline ended without a result = it failed
                    print("SMOKE-AUTO-FAIL: pipeline reported failure")
                    app.quit()
                    return
                if waited["ms"] >= limit:
                    print("SMOKE-AUTO-FAIL: timed out")
                    app.quit()
                    return
                waited["ms"] += 250
                QTimer.singleShot(250, tick)
                return
            loaded = win.active_file is not None
            if args.page and waited["ms"] < (1500 if file_to_open else 300):
                waited["ms"] += 250
                QTimer.singleShot(250, tick)
                return
            done = loaded or file_to_open is None or waited["ms"] >= limit
            if done:
                if file_to_open and not loaded:
                    print("SMOKE-FAIL: file did not load")
                    app.quit()
                    return
                print(f"SMOKE-OK loaded={loaded}")
                app.quit()
                return
            waited["ms"] += 250
            QTimer.singleShot(250, tick)

        QTimer.singleShot(300, tick)

    def excepthook(t, v, tb):
        msg = "".join(traceback.format_exception(t, v, tb))
        win.log(f"Unhandled exception:\n{msg}", "err")
        sys.__excepthook__(t, v, tb)

    sys.excepthook = excepthook
    rc = app.exec()
    if win.active_file:
        settings.setValue("last_file", win.active_file)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
