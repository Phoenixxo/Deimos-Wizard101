"""Per-account window size / resolution editor.

A popup opened from each launcher account row (the "proportions" icon). It shows a
mock of the current multi-monitor layout (physical screen coords) with a draggable,
resizable rectangle representing the game window. A lock toggle links the render
resolution to the window client size (crisp 1:1). Saving stores the config in the
account's wizlaunch metadata; it is applied automatically when the account launches.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QSpinBox, QWidget,
    QFormLayout, QCheckBox,
)
from PyQt6.QtCore import Qt, QRect, QPoint, pyqtSignal
from PyQt6.QtGui import QPainter, QColor, QPen, QBrush, QFont

import wizlaunch


# ---- physical monitor enumeration (matches SetWindowPos screen coords) ----
_user32 = ctypes.windll.user32


class _MONITORINFO(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("rcMonitor", wintypes.RECT),
                ("rcWork", wintypes.RECT), ("dwFlags", wintypes.DWORD)]


_MONENUMPROC = ctypes.WINFUNCTYPE(
    ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(wintypes.RECT), ctypes.c_double
)


def enum_monitors():
    """Return [(x, y, w, h, is_primary), ...] in physical virtual-desktop coords."""
    out = []

    def _cb(hmon, hdc, lprc, lparam):
        mi = _MONITORINFO()
        mi.cbSize = ctypes.sizeof(_MONITORINFO)
        _user32.GetMonitorInfoW(hmon, ctypes.byref(mi))
        r = mi.rcMonitor
        out.append((r.left, r.top, r.right - r.left, r.bottom - r.top, bool(mi.dwFlags & 1)))
        return 1

    _user32.EnumDisplayMonitors(None, None, _MONENUMPROC(_cb), 0)
    if not out:
        out.append((0, 0, _user32.GetSystemMetrics(0), _user32.GetSystemMetrics(1), True))
    return out


_HANDLE = 9  # px hit-radius for resize handles
_MIN_W, _MIN_H = 320, 240


class _MonitorCanvas(QWidget):
    """Draws the monitor layout + a draggable/resizable window rect (virtual coords)."""

    changed = pyqtSignal()

    def __init__(self, monitors, win_rect, parent=None):
        super().__init__(parent)
        self.monitors = monitors                       # [(x,y,w,h,primary)]
        self.win = list(win_rect)                       # [x, y, w, h] mutable
        self.setMinimumSize(460, 280)
        self.setMouseTracking(True)
        self._drag = None                               # ('move'|edge code) or None
        self._press = None                              # (mouse virt x,y, win snapshot)
        # virtual-desktop bounds
        xs = [m[0] for m in monitors] + [m[0] + m[2] for m in monitors]
        ys = [m[1] for m in monitors] + [m[1] + m[3] for m in monitors]
        self.vx, self.vy = min(xs), min(ys)
        self.vw, self.vh = max(xs) - self.vx, max(ys) - self.vy
        self._clamp_size_pos()

    # --- keep the window rect inside the monitor union (its bounding box) ---
    def _clamp_pos(self):
        x, y, w, h = self.win
        x = max(self.vx, min(x, self.vx + self.vw - w))
        y = max(self.vy, min(y, self.vy + self.vh - h))
        self.win[0], self.win[1] = x, y

    def _clamp_size_pos(self):
        # The window can be at most the size of the whole monitor area.
        self.win[2] = max(_MIN_W, min(self.win[2], self.vw))
        self.win[3] = max(_MIN_H, min(self.win[3], self.vh))
        self._clamp_pos()

    # --- coordinate mapping (virtual <-> canvas pixels) ---
    def _scale(self):
        pad = 16
        w = self.width() - 2 * pad
        h = self.height() - 2 * pad
        s = min(w / max(self.vw, 1), h / max(self.vh, 1))
        ox = pad + (w - self.vw * s) / 2
        oy = pad + (h - self.vh * s) / 2
        return s, ox, oy

    def _v2c(self, x, y):
        s, ox, oy = self._scale()
        return QPoint(int(ox + (x - self.vx) * s), int(oy + (y - self.vy) * s))

    def _c2v(self, px, py):
        s, ox, oy = self._scale()
        return ((px - ox) / s + self.vx, (py - oy) / s + self.vy)

    def _win_canvas_rect(self):
        tl = self._v2c(self.win[0], self.win[1])
        br = self._v2c(self.win[0] + self.win[2], self.win[1] + self.win[3])
        return QRect(tl, br)

    # --- painting ---
    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor(0, 0, 0, 0))
        f = QFont(); f.setPointSize(8); p.setFont(f)
        for (mx, my, mw, mh, primary) in self.monitors:
            tl = self._v2c(mx, my); br = self._v2c(mx + mw, my + mh)
            r = QRect(tl, br)
            p.setPen(QPen(QColor(255, 255, 255, 90), 1))
            p.setBrush(QBrush(QColor(255, 255, 255, 18) if primary else QColor(255, 255, 255, 10)))
            p.drawRoundedRect(r, 4, 4)
            p.setPen(QColor(255, 255, 255, 130))
            p.drawText(r.adjusted(4, 2, -4, -2), Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft,
                       f"{mw}x{mh}" + (" ★" if primary else ""))
        # window rect
        wr = self._win_canvas_rect()
        p.setPen(QPen(QColor(120, 170, 255), 2))
        p.setBrush(QBrush(QColor(120, 170, 255, 70)))
        p.drawRect(wr)
        p.setPen(QColor(255, 255, 255))
        p.drawText(wr, Qt.AlignmentFlag.AlignCenter, f"{self.win[2]}x{self.win[3]}")
        # corner handles
        p.setBrush(QBrush(QColor(120, 170, 255)))
        p.setPen(QPen(QColor(255, 255, 255), 1))
        for cx, cy in self._handle_points(wr):
            p.drawRect(cx - 3, cy - 3, 6, 6)
        p.end()

    def _handle_points(self, wr):
        return [(wr.left(), wr.top()), (wr.right(), wr.top()),
                (wr.left(), wr.bottom()), (wr.right(), wr.bottom())]

    # --- interaction ---
    def _hit_handle(self, pos):
        wr = self._win_canvas_rect()
        names = ['tl', 'tr', 'bl', 'br']
        for (cx, cy), name in zip(self._handle_points(wr), names):
            if abs(pos.x() - cx) <= _HANDLE and abs(pos.y() - cy) <= _HANDLE:
                return name
        if wr.contains(pos):
            return 'move'
        return None

    def mouseMoveEvent(self, e):
        if self._drag is None:
            h = self._hit_handle(e.position().toPoint())
            cur = {'tl': Qt.CursorShape.SizeFDiagCursor, 'br': Qt.CursorShape.SizeFDiagCursor,
                   'tr': Qt.CursorShape.SizeBDiagCursor, 'bl': Qt.CursorShape.SizeBDiagCursor,
                   'move': Qt.CursorShape.SizeAllCursor}.get(h, Qt.CursorShape.ArrowCursor)
            self.setCursor(cur)
            return
        vx, vy = self._c2v(e.position().x(), e.position().y())
        px, py, snap = self._press
        ox, oy, ow, oh = snap
        dx, dy = int(vx - px), int(vy - py)
        bx0, by0 = self.vx, self.vy
        bx1, by1 = self.vx + self.vw, self.vy + self.vh
        if self._drag == 'move':
            # Move at fixed size, clamped so no edge leaves the monitor union.
            self.win[0] = min(max(ox + dx, bx0), bx1 - ow)
            self.win[1] = min(max(oy + dy, by0), by1 - oh)
        else:
            # Resize: clamp the dragged edge to the bounds, keep the opposite edge.
            x, y, w, h = ox, oy, ow, oh
            right, bottom = ox + ow, oy + oh
            if 'l' in self._drag:
                x = min(max(ox + dx, bx0), right - _MIN_W); w = right - x
            if 'r' in self._drag:
                w = min(max(ow + dx, _MIN_W), bx1 - x)
            if 't' in self._drag:
                y = min(max(oy + dy, by0), bottom - _MIN_H); h = bottom - y
            if 'b' in self._drag:
                h = min(max(oh + dy, _MIN_H), by1 - y)
            self.win = [x, y, w, h]
        self.update()
        self.changed.emit()

    def mousePressEvent(self, e):
        h = self._hit_handle(e.position().toPoint())
        if h is None:
            return
        vx, vy = self._c2v(e.position().x(), e.position().y())
        self._drag = h
        self._press = (vx, vy, tuple(self.win))

    def mouseReleaseEvent(self, _):
        self._drag = None

    def set_win(self, x, y, w, h):
        self.win = [int(x), int(y), int(w), int(h)]
        self._clamp_size_pos()
        self.update()
        self.changed.emit()


def show_window_config_dialog(ctx, nickname: str):
    tl = ctx.tl if hasattr(ctx, 'tl') else (lambda s: s)
    monitors = enum_monitors()

    existing = None
    try:
        existing = wizlaunch.get_window_config(nickname)
    except Exception:
        existing = None

    if existing:
        x, y, w, h, res_w, res_h, locked = existing
    else:
        # default: 1280x720 centered on the primary monitor
        prim = next((m for m in monitors if m[4]), monitors[0])
        w, h = 1280, 720
        x = prim[0] + (prim[2] - w) // 2
        y = prim[1] + (prim[3] - h) // 2
        res_w, res_h, locked = w, h, True

    dlg = QDialog(ctx.window)
    dlg.setWindowTitle(tl('window_config_title').format(nickname) if hasattr(ctx, 'tl') else f"Window — {nickname}")
    dlg.setModal(True)
    dlg.setStyleSheet(f"QWidget {{ background-color: {ctx.bg_color}; color: {ctx.text_color}; }}")
    layout = QVBoxLayout(dlg)

    canvas = _MonitorCanvas(monitors, [x, y, w, h])
    layout.addWidget(canvas, 1)
    # The canvas clamps the rect into the monitor union on construction; mirror it.
    w, h = canvas.win[2], canvas.win[3]
    if locked:
        res_w, res_h = w, h

    form = QFormLayout()
    form.setSpacing(6)

    def _spin(val, mx=32000):
        s = QSpinBox(); s.setRange(1, mx); s.setValue(int(val)); return s

    win_w = _spin(w); win_h = _spin(h)
    res_w_s = _spin(res_w); res_h_s = _spin(res_h)

    win_row = QHBoxLayout(); win_row.addWidget(win_w); win_row.addWidget(QLabel("×")); win_row.addWidget(win_h)
    form.addRow(tl('window_size') if hasattr(ctx, 'tl') else "Window size", _wrap(win_row))

    res_row = QHBoxLayout()
    lock_btn = QPushButton(); lock_btn.setFixedSize(24, 24); lock_btn.setCheckable(True)
    lock_btn.setStyleSheet(ctx.icon_btn_style); lock_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    res_row.addWidget(res_w_s); res_row.addWidget(QLabel("×")); res_row.addWidget(res_h_s); res_row.addWidget(lock_btn)
    form.addRow(tl('resolution') if hasattr(ctx, 'tl') else "Resolution", _wrap(res_row))
    layout.addLayout(form)

    state = {'sync': False}

    def _update_lock_icon():
        ic = ctx.svgs['lock'] if lock_btn.isChecked() else ctx.svgs['lock_open']
        lock_btn.setIcon(ctx.titlebar_svg_icon(ic, 16))
        lock_btn.setToolTip((tl('lock_res_to_window') if hasattr(ctx, 'tl') else
                             "Lock render resolution to window size (crisp 1:1)"))

    def _apply_lock():
        locked_now = lock_btn.isChecked()
        res_w_s.setEnabled(not locked_now)
        res_h_s.setEnabled(not locked_now)
        if locked_now:
            res_w_s.setValue(win_w.value()); res_h_s.setValue(win_h.value())
        _update_lock_icon()

    lock_btn.setChecked(bool(locked))
    lock_btn.toggled.connect(_apply_lock)

    def _on_canvas_change():
        state['sync'] = True
        win_w.setValue(canvas.win[2]); win_h.setValue(canvas.win[3])
        if lock_btn.isChecked():
            res_w_s.setValue(canvas.win[2]); res_h_s.setValue(canvas.win[3])
        state['sync'] = False

    def _on_fields_change():
        if state['sync']:
            return
        canvas.set_win(canvas.win[0], canvas.win[1], win_w.value(), win_h.value())
        if lock_btn.isChecked():
            res_w_s.setValue(win_w.value()); res_h_s.setValue(win_h.value())

    canvas.changed.connect(_on_canvas_change)
    win_w.valueChanged.connect(_on_fields_change)
    win_h.valueChanged.connect(_on_fields_change)
    _apply_lock()

    btn_row = QHBoxLayout(); btn_row.addStretch()
    clear_btn = QPushButton(tl('clear') if hasattr(ctx, 'tl') else "Clear")
    clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    save_btn = QPushButton(tl('settings_save') if hasattr(ctx, 'tl') else "Save")
    save_btn.setStyleSheet(ctx.btn_style); save_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    btn_row.addWidget(clear_btn); btn_row.addWidget(save_btn)
    layout.addLayout(btn_row)

    def _save():
        cx, cy = canvas.win[0], canvas.win[1]
        ww, wh = win_w.value(), win_h.value()
        if lock_btn.isChecked():
            rw, rh = ww, wh
        else:
            rw, rh = res_w_s.value(), res_h_s.value()
        try:
            wizlaunch.set_window_config(nickname, int(cx), int(cy), int(ww), int(wh),
                                        int(rw), int(rh), bool(lock_btn.isChecked()))
        except Exception:
            pass
        dlg.accept()

    def _clear():
        try:
            wizlaunch.clear_window_config(nickname)
        except Exception:
            pass
        dlg.accept()

    save_btn.clicked.connect(_save)
    clear_btn.clicked.connect(_clear)

    dlg.resize(540, 460)
    dlg.exec()


def _wrap(layout):
    w = QWidget(); w.setStyleSheet("background: transparent;"); w.setLayout(layout)
    return w
