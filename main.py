#!/usr/bin/env python3
"""
Hidden File Hunter 2.0
======================

A safe, read-only scanner that finds hidden (and optionally system) files on
your drives, lists them in a sortable/filterable table, and can save the paths
to TXT/CSV or copy the discovered files somewhere else.

The app never modifies or deletes the files it finds.

Requires: Python 3.9+ and PySide6  (pip install PySide6)
Made by jozmoz | wraith
"""

from __future__ import annotations

import csv
import os
import shutil
import string
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import (
    QAbstractTableModel,
    QByteArray,
    QModelIndex,
    QSettings,
    QSortFilterProxyModel,
    QStandardPaths,
    Qt,
    QThread,
    QTimer,
    QUrl,
    Signal,
)
from PySide6.QtGui import (
    QAction,
    QBrush,
    QColor,
    QDesktopServices,
    QFont,
    QFontDatabase,
    QFontMetrics,
    QGuiApplication,
    QIcon,
    QKeySequence,
    QLinearGradient,
    QPainter,
    QPen,
    QPixmap,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

APP_NAME = "Hidden File Hunter"
APP_VERSION = "2.0"
ORG_NAME = "jozmoz"

IS_WINDOWS = os.name == "nt"
IS_MACOS = sys.platform == "darwin"

# Windows file attribute flags (also used as a portable internal representation)
ATTR_HIDDEN = 0x00000002
ATTR_SYSTEM = 0x00000004
ATTR_DIRECTORY = 0x00000010
ATTR_REPARSE_POINT = 0x00000400
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

UF_HIDDEN = 0x00008000  # macOS "hidden" flag

DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4

# UI/thread tuning: results are delivered in batches so the GUI never floods.
BATCH_SIZE = 250
BATCH_INTERVAL = 0.25
PROGRESS_INTERVAL = 0.20
MAX_TABLE_ROWS = 250_000


# ---------------------------------------------------------------------------
# Platform layer
# ---------------------------------------------------------------------------

if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    # NOTE: declaring restype is essential. Without it ctypes returns a signed
    # int, so the INVALID_FILE_ATTRIBUTES (0xFFFFFFFF) error value came back as
    # -1 and every unreadable file looked "hidden + system".
    _k32.GetLogicalDrives.argtypes = []
    _k32.GetLogicalDrives.restype = wintypes.DWORD

    _k32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    _k32.GetDriveTypeW.restype = wintypes.UINT

    _k32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    _k32.GetFileAttributesW.restype = wintypes.DWORD

    _k32.GetVolumeInformationW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    _k32.GetVolumeInformationW.restype = wintypes.BOOL

    _k32.SetErrorMode.argtypes = [wintypes.UINT]
    _k32.SetErrorMode.restype = wintypes.UINT


def silence_os_error_dialogs() -> None:
    """Stop Windows from popping "There is no disk in the drive" dialogs."""
    if not IS_WINDOWS:
        return
    try:
        _k32.SetErrorMode(0x0001 | 0x0002 | 0x8000)
    except OSError:
        pass


def long_path(path: str) -> str:
    """Return a Windows path that is safe to use beyond the 260 char limit."""
    if not IS_WINDOWS:
        return path
    try:
        p = os.path.abspath(path)
    except (OSError, ValueError):
        return path
    if p.startswith("\\\\?\\"):
        return p
    if p.startswith("\\\\"):
        return "\\\\?\\UNC" + p[1:]
    return "\\\\?\\" + p


def path_attributes(path: str):
    """File attributes for a path, or None when the path cannot be read."""
    if IS_WINDOWS:
        try:
            attrs = _k32.GetFileAttributesW(long_path(path))
        except (OSError, ValueError):
            return None
        if attrs == INVALID_FILE_ATTRIBUTES:
            return None
        return int(attrs)

    try:
        st = os.stat(path, follow_symlinks=False)
    except (OSError, ValueError):
        return None
    return posix_attributes(os.path.basename(path.rstrip("/")) or path, st)


def posix_attributes(name: str, st) -> int:
    """Translate POSIX metadata into the same attribute bit layout."""
    attrs = 0
    if name.startswith("."):
        attrs |= ATTR_HIDDEN
    if IS_MACOS and getattr(st, "st_flags", 0) & UF_HIDDEN:
        attrs |= ATTR_HIDDEN
    import stat as _stat

    if _stat.S_ISDIR(st.st_mode):
        attrs |= ATTR_DIRECTORY
    if _stat.S_ISLNK(st.st_mode):
        attrs |= ATTR_REPARSE_POINT
    return attrs


def entry_attributes(entry: os.DirEntry):
    """Attributes for a scandir entry, reusing the data from the directory read."""
    try:
        st = entry.stat(follow_symlinks=False)
    except (OSError, ValueError):
        return path_attributes(entry.path)

    if IS_WINDOWS:
        attrs = getattr(st, "st_file_attributes", None)
        if attrs is None:
            return path_attributes(entry.path)
        return int(attrs)

    return posix_attributes(entry.name, st)


@dataclass(frozen=True)
class RootInfo:
    path: str
    label: str = ""
    total: int = 0
    free: int = 0


def volume_label(root: str) -> str:
    if not IS_WINDOWS:
        return ""
    try:
        name = ctypes.create_unicode_buffer(261)
        fs = ctypes.create_unicode_buffer(261)
        serial = wintypes.DWORD()
        max_len = wintypes.DWORD()
        flags = wintypes.DWORD()
        ok = _k32.GetVolumeInformationW(
            root,
            name,
            len(name),
            ctypes.byref(serial),
            ctypes.byref(max_len),
            ctypes.byref(flags),
            fs,
            len(fs),
        )
        return name.value if ok else ""
    except (OSError, ValueError):
        return ""


def list_roots(include_removable: bool = False) -> list:
    """Drives (Windows) or mount roots (macOS/Linux) that can be scanned."""
    roots = []

    if IS_WINDOWS:
        try:
            bitmask = int(_k32.GetLogicalDrives())
        except OSError:
            bitmask = 0
        wanted = {DRIVE_FIXED}
        if include_removable:
            wanted.add(DRIVE_REMOVABLE)
        for index, letter in enumerate(string.ascii_uppercase):
            if not bitmask & (1 << index):
                continue
            root = f"{letter}:\\"
            try:
                kind = int(_k32.GetDriveTypeW(root))
            except OSError:
                continue
            if kind not in wanted:
                continue
            total = free = 0
            try:
                usage = shutil.disk_usage(root)
                total, free = usage.total, usage.free
            except OSError:
                pass
            roots.append(RootInfo(root, volume_label(root), total, free))
        return roots

    candidates = [os.path.expanduser("~"), "/"]
    for extra in ("/Volumes", "/media", "/mnt"):
        try:
            if os.path.isdir(extra):
                for name in sorted(os.listdir(extra)):
                    candidates.append(os.path.join(extra, name))
        except OSError:
            pass

    seen = set()
    for candidate in candidates:
        if not candidate or not os.path.isdir(candidate):
            continue
        key = os.path.normcase(os.path.abspath(candidate))
        if key in seen:
            continue
        seen.add(key)
        total = free = 0
        try:
            usage = shutil.disk_usage(candidate)
            total, free = usage.total, usage.free
        except OSError:
            pass
        roots.append(RootInfo(candidate, "", total, free))
    return roots


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def human_size(num: float) -> str:
    try:
        num = float(num)
    except (TypeError, ValueError):
        return "-"
    if num < 1024:
        return f"{int(num)} B"
    for unit in ("KB", "MB", "GB", "TB", "PB"):
        num /= 1024.0
        if num < 1024 or unit == "PB":
            return f"{num:,.1f} {unit}"
    return f"{num:,.1f} PB"


def format_timestamp(mtime: float) -> str:
    """Never crash on broken/negative timestamps (they exist in the wild)."""
    if not mtime:
        return "-"
    try:
        return datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return "-"


def format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours:d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


LTR_ISOLATE = "\u2066"
POP_ISOLATE = "\u2069"


def isolate(value) -> str:
    """Keep Latin runs (paths, drive letters, numbers) readable inside RTL text.

    Without an isolate, Windows paths embedded in a Persian sentence get
    reordered by the bidi algorithm and look scrambled.
    """
    if value is None:
        return ""
    text = str(value)
    if not text:
        return ""
    if text.startswith(LTR_ISOLATE) and text.endswith(POP_ISOLATE):
        return text  # already isolated, do not nest the markers
    return f"{LTR_ISOLATE}{text}{POP_ISOLATE}"


def build_font(family: str, point_size: float, bold: bool = False) -> QFont:
    """Build a font with the smoothing hints that keep small text sharp."""
    font = QFont(family)
    font.setPointSizeF(max(8.0, float(point_size)))
    try:
        font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
        font.setHintingPreference(QFont.HintingPreference.PreferDefaultHinting)
    except Exception:  # noqa: BLE001 - some platforms expose neither knob
        pass
    if bold:
        font.setWeight(QFont.Weight.DemiBold)
    return font


def crisp_icon_pixmap(icon: QIcon, size: int, widget=None) -> QPixmap:
    """Render an icon at the screen's real pixel density so it never looks soft."""
    ratio = 1.0
    try:
        if widget is not None:
            ratio = float(widget.devicePixelRatioF())
        else:
            screen = QGuiApplication.primaryScreen()
            if screen is not None:
                ratio = float(screen.devicePixelRatio())
    except Exception:  # noqa: BLE001 - fall back to 1x on odd platforms
        ratio = 1.0
    ratio = max(1.0, min(4.0, ratio))
    pixels = max(1, int(round(size * ratio)))
    pixmap = icon.pixmap(pixels, pixels)
    pixmap.setDevicePixelRatio(ratio)
    return pixmap


def is_inside(path: str, parent: str) -> bool:
    """True when *path* is *parent* or lives inside it."""
    if not parent:
        return False
    try:
        p = os.path.normcase(os.path.abspath(path)).rstrip("\\/")
        q = os.path.normcase(os.path.abspath(parent)).rstrip("\\/")
    except (OSError, ValueError):
        return False
    if not q:
        return False
    return p == q or p.startswith(q + os.sep)


def unique_path(path) -> Path:
    """Return a path that does not exist yet, so nothing is ever overwritten."""
    path = Path(path)
    if not os.path.exists(long_path(str(path))):
        return path
    stem, suffix, parent = path.stem, path.suffix, path.parent
    for n in range(1, 100_000):
        candidate = parent / f"{stem}_{n}{suffix}"
        if not os.path.exists(long_path(str(candidate))):
            return candidate
    return parent / f"{stem}_{int(time.time())}{suffix}"


_INVALID_CHARS = '<>:"/\\|?*'


def safe_component(name: str) -> str:
    cleaned = "".join("_" if ch in _INVALID_CHARS or ord(ch) < 32 else ch for ch in name)
    cleaned = cleaned.rstrip(" .") if IS_WINDOWS else cleaned
    return cleaned or "_"


def build_copy_target(destination: str, source: str) -> Path:
    """Mirror <drive>/<original folders>/<file> under the destination folder."""
    src = Path(source)
    drive = src.drive
    if drive.startswith("\\\\") or drive.startswith("//"):
        parts = [p for p in drive.replace("/", "\\").strip("\\").split("\\") if p]
        folder = safe_component("UNC_" + "_".join(parts))
    else:
        folder = safe_component(drive.replace(":", "").strip("\\/")) if drive else "root"

    tail = [safe_component(part) for part in src.parts[1:]]
    if not tail:
        tail = [safe_component(src.name or "file")]
    return Path(destination).joinpath(folder, *tail)


def copy_discovered_file(source: str, destination: str) -> Path:
    """Copy a found file into the destination tree without overwriting."""
    target = build_copy_target(destination, source)
    target.parent.mkdir(parents=True, exist_ok=True)
    final = unique_path(target)
    shutil.copy2(long_path(source), long_path(str(final)))
    return final


@dataclass(frozen=True)
class FileRecord:
    path: str
    size: int
    mtime: float
    is_system: bool

    @property
    def name(self) -> str:
        return os.path.basename(self.path) or self.path

    @property
    def folder(self) -> str:
        return os.path.dirname(self.path)


# ---------------------------------------------------------------------------
# Scanning core (pure Python, no Qt - easy to test and reuse)
# ---------------------------------------------------------------------------


class ScanCore:
    """Iterative, loop-safe walker that yields hidden files as it goes."""

    def __init__(
        self,
        roots,
        include_system: bool = False,
        excluded=(),
        follow_links: bool = False,
    ):
        self.roots = [str(r) for r in roots]
        self.include_system = include_system
        self.excluded = [str(e) for e in excluded if e]
        self.follow_links = follow_links

        self.stop_requested = False
        self.found = 0
        self.errors = 0
        self.scanned = 0
        self.directories = 0

    def request_stop(self) -> None:
        self.stop_requested = True

    def _excluded(self, path: str) -> bool:
        return any(is_inside(path, parent) for parent in self.excluded)

    @staticmethod
    def _dir_key(path: str) -> str:
        try:
            return os.path.normcase(os.path.realpath(path))
        except (OSError, ValueError):
            return os.path.normcase(os.path.abspath(path))

    def iterate(self):
        """Yield ("dir", path) / ("file", FileRecord) / ("error", path) events."""
        visited = set()

        for root in self.roots:
            if self.stop_requested:
                return
            stack = [root]

            while stack:
                if self.stop_requested:
                    return
                current = stack.pop()

                key = self._dir_key(current)
                if key in visited:
                    continue
                visited.add(key)

                self.directories += 1
                yield ("dir", current)

                try:
                    with os.scandir(current) as iterator:
                        entries = list(iterator)
                except (OSError, ValueError):
                    self.errors += 1
                    yield ("error", current)
                    continue

                for entry in entries:
                    if self.stop_requested:
                        return

                    try:
                        is_dir = entry.is_dir(follow_symlinks=False)
                    except (OSError, ValueError):
                        self.errors += 1
                        yield ("error", entry.path)
                        continue

                    attrs = entry_attributes(entry)

                    if is_dir:
                        # Skip junctions/symlinks: on Windows they create
                        # infinite loops (C:\Users -> C:\Documents and Settings).
                        if not self.follow_links and attrs is not None:
                            if attrs & ATTR_REPARSE_POINT:
                                continue
                        if self._excluded(entry.path):
                            continue
                        stack.append(entry.path)
                        continue

                    self.scanned += 1

                    if attrs is None:
                        self.errors += 1
                        continue
                    if not attrs & ATTR_HIDDEN:
                        continue

                    is_system = bool(attrs & ATTR_SYSTEM)
                    if is_system and not self.include_system:
                        continue
                    if self._excluded(entry.path):
                        continue

                    try:
                        stat_result = entry.stat(follow_symlinks=False)
                        size = int(stat_result.st_size)
                        mtime = float(stat_result.st_mtime)
                    except (OSError, ValueError, OverflowError):
                        size, mtime = 0, 0.0

                    self.found += 1
                    yield ("file", FileRecord(entry.path, size, mtime, is_system))


# ---------------------------------------------------------------------------
# Worker thread
# ---------------------------------------------------------------------------


class ScannerThread(QThread):
    """Runs ScanCore off the GUI thread and reports progress in batches."""

    batch_ready = Signal(object)  # list[FileRecord]
    progress = Signal(object)  # dict with counters + current folder
    scan_finished = Signal(object)  # dict summary
    failed = Signal(str)

    def __init__(
        self,
        roots,
        include_system: bool,
        follow_links: bool,
        copy_files: bool,
        destination: str,
        txt_path: str,
        parent=None,
    ):
        super().__init__(parent)
        self.copy_files = bool(copy_files)
        self.destination = os.path.abspath(destination) if destination else ""
        self.txt_path = os.path.abspath(txt_path) if txt_path else ""
        self.core = ScanCore(
            roots,
            include_system=include_system,
            excluded=[self.destination] if self.copy_files else [],
            follow_links=follow_links,
        )
        self.copied = 0
        self.saved_txt_path = ""

    def stop(self) -> None:
        self.core.request_stop()

    @property
    def stop_requested(self) -> bool:
        return self.core.stop_requested

    def _summary(self, started: float) -> dict:
        return {
            "found": self.core.found,
            "copied": self.copied,
            "errors": self.core.errors,
            "scanned": self.core.scanned,
            "directories": self.core.directories,
            "stopped": self.core.stop_requested,
            "elapsed": time.monotonic() - started,
            "txt_path": self.saved_txt_path,
            "copy_files": self.copy_files,
            "destination": self.destination,
        }

    def _emit_progress(self, current: str) -> None:
        self.progress.emit(
            {
                "current": current,
                "found": self.core.found,
                "copied": self.copied,
                "errors": self.core.errors,
                "scanned": self.core.scanned,
                "directories": self.core.directories,
            }
        )

    def run(self) -> None:  # noqa: C901 - linear but branchy by nature
        started = time.monotonic()
        batch = []
        handle = None
        current = ""

        try:
            if self.copy_files:
                Path(self.destination).mkdir(parents=True, exist_ok=True)

            if self.txt_path:
                requested = Path(self.txt_path)
                requested.parent.mkdir(parents=True, exist_ok=True)
                output = unique_path(requested)
                # Results are streamed to disk while scanning, so nothing is
                # lost if the scan is stopped or the machine goes down.
                handle = open(long_path(str(output)), "w", encoding="utf-8", newline="\n")
                self.saved_txt_path = str(output)

            last_batch = last_progress = last_flush = time.monotonic()

            for kind, payload in self.core.iterate():
                now = time.monotonic()

                if kind == "dir":
                    current = payload
                elif kind == "file":
                    record = payload

                    if handle is not None:
                        try:
                            handle.write(record.path + "\n")
                        except OSError:
                            self.core.errors += 1

                    if self.copy_files:
                        try:
                            copy_discovered_file(record.path, self.destination)
                            self.copied += 1
                        except (OSError, shutil.Error, ValueError):
                            self.core.errors += 1

                    batch.append(record)
                    if len(batch) >= BATCH_SIZE or now - last_batch >= BATCH_INTERVAL:
                        self.batch_ready.emit(batch)
                        batch = []
                        last_batch = now

                if handle is not None and now - last_flush >= 2.0:
                    try:
                        handle.flush()
                    except OSError:
                        pass
                    last_flush = now

                if now - last_progress >= PROGRESS_INTERVAL:
                    self._emit_progress(current)
                    last_progress = now

            if batch:
                self.batch_ready.emit(batch)
                batch = []

            self._emit_progress(current)
            self.scan_finished.emit(self._summary(started))

        except Exception as exc:  # noqa: BLE001 - never kill the worker silently
            if batch:
                self.batch_ready.emit(batch)
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        finally:
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# Results model
# ---------------------------------------------------------------------------


class ResultsModel(QAbstractTableModel):
    COL_KIND = 0
    COL_NAME = 1
    COL_SIZE = 2
    COL_MODIFIED = 3
    COL_FOLDER = 4
    COLUMNS = 5

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows = []
        self._headers = ["Type", "Name", "Size", "Modified", "Folder"]
        self._kind_labels = {"hidden": "HIDDEN", "system": "SYSTEM"}
        self._system_color = QColor("#f0b429")
        self._numeric_font = None
        self._truncated = False

    # -- Qt API ------------------------------------------------------------
    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else self.COLUMNS

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            if 0 <= section < len(self._headers):
                return self._headers[section]
            return None
        return section + 1

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        record = self._rows[index.row()]
        column = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if column == self.COL_KIND:
                return self._kind_labels["system" if record.is_system else "hidden"]
            if column == self.COL_NAME:
                return record.name
            if column == self.COL_SIZE:
                return human_size(record.size)
            if column == self.COL_MODIFIED:
                return format_timestamp(record.mtime)
            if column == self.COL_FOLDER:
                return record.folder
            return None

        if role == Qt.ItemDataRole.UserRole:
            # Raw values, used for correct sorting (size/date as numbers).
            if column == self.COL_KIND:
                return 1 if record.is_system else 0
            if column == self.COL_NAME:
                return record.name.lower()
            if column == self.COL_SIZE:
                return record.size
            if column == self.COL_MODIFIED:
                return record.mtime
            if column == self.COL_FOLDER:
                return record.folder.lower()
            return None

        if role == Qt.ItemDataRole.FontRole:
            # Sizes and dates read better with tabular digits.
            if column in (self.COL_SIZE, self.COL_MODIFIED):
                return self._numeric_font
            return None

        if role == Qt.ItemDataRole.ToolTipRole:
            return record.path

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if column == self.COL_SIZE:
                return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            if column in (self.COL_KIND, self.COL_MODIFIED):
                return int(Qt.AlignmentFlag.AlignCenter)
            return int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        if role == Qt.ItemDataRole.ForegroundRole and record.is_system:
            if column == self.COL_KIND:
                return QBrush(self._system_color)

        return None

    # -- helpers -----------------------------------------------------------
    def set_headers(self, headers, kind_labels) -> None:
        self._headers = list(headers)
        self._kind_labels = dict(kind_labels)
        self.headerDataChanged.emit(
            Qt.Orientation.Horizontal, 0, self.COLUMNS - 1
        )
        if self._rows:
            self.dataChanged.emit(
                self.index(0, 0),
                self.index(len(self._rows) - 1, self.COLUMNS - 1),
                [Qt.ItemDataRole.DisplayRole],
            )

    def set_system_color(self, color: str) -> None:
        self._system_color = QColor(color)

    def set_numeric_font(self, font) -> None:
        self._numeric_font = font
        if self._rows:
            self.dataChanged.emit(
                self.index(0, self.COL_SIZE),
                self.index(len(self._rows) - 1, self.COL_MODIFIED),
                [Qt.ItemDataRole.FontRole],
            )

    def add_records(self, records) -> int:
        records = [r for r in records if isinstance(r, FileRecord)]
        if not records:
            return 0
        room = MAX_TABLE_ROWS - len(self._rows)
        if room <= 0:
            self._truncated = True
            return 0
        if len(records) > room:
            records = records[:room]
            self._truncated = True
        first = len(self._rows)
        self.beginInsertRows(QModelIndex(), first, first + len(records) - 1)
        self._rows.extend(records)
        self.endInsertRows()
        return len(records)

    def clear(self) -> None:
        self.beginResetModel()
        self._rows = []
        self._truncated = False
        self.endResetModel()

    def record(self, row: int):
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None

    def records(self):
        return list(self._rows)

    @property
    def truncated(self) -> bool:
        return self._truncated


class ResultsProxy(QSortFilterProxyModel):
    """Sorts on raw values and filters on the full path."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._needle = ""
        self.setDynamicSortFilter(True)

    def set_needle(self, text: str) -> None:
        self._needle = (text or "").strip().lower()
        self.invalidateFilter()

    def lessThan(self, left, right):
        left_value = self.sourceModel().data(left, Qt.ItemDataRole.UserRole)
        right_value = self.sourceModel().data(right, Qt.ItemDataRole.UserRole)
        if left_value is None or right_value is None:
            return super().lessThan(left, right)
        try:
            return left_value < right_value
        except TypeError:
            return str(left_value) < str(right_value)

    def filterAcceptsRow(self, source_row, source_parent):
        if not self._needle:
            return True
        model = self.sourceModel()
        record = model.record(source_row) if isinstance(model, ResultsModel) else None
        if record is None:
            return True
        return self._needle in record.path.lower()


# ---------------------------------------------------------------------------
# Small custom widgets
# ---------------------------------------------------------------------------


class StatChip(QFrame):
    """A compact metric card: big value on top, caption underneath."""

    def __init__(self, caption: str = "", accent: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("StatChip")
        self.setProperty("accent", accent or "neutral")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(2)

        self.value_label = QLabel("0")
        self.value_label.setObjectName("ChipValue")
        self.caption_label = QLabel(caption)
        self.caption_label.setObjectName("ChipCaption")

        layout.addWidget(self.value_label)
        layout.addWidget(self.caption_label)

        self._caption = caption
        # Wide enough for seven-digit counters and translated captions.
        self.setMinimumWidth(138)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_value(self, value) -> None:
        self.value_label.setText(str(value))

    def set_caption(self, caption: str) -> None:
        self._caption = caption
        self.caption_label.setToolTip(caption)
        self.render_caption()

    def render_caption(self) -> None:
        """Elide long captions instead of letting them get clipped mid-glyph."""
        available = self.caption_label.width()
        if available < 40:
            self.caption_label.setText(self._caption)
            return
        metrics = QFontMetrics(self.caption_label.font())
        self.caption_label.setText(
            metrics.elidedText(self._caption, Qt.TextElideMode.ElideRight, available)
        )

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.render_caption()


def build_app_icon() -> QIcon:
    """Draw the app icon at runtime so the app stays a single file."""
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        pixmap = QPixmap(size, size)
        pixmap.fill(QColor(0, 0, 0, 0))
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        gradient = QLinearGradient(0, 0, size, size)
        gradient.setColorAt(0.0, QColor("#4f8cff"))
        gradient.setColorAt(1.0, QColor("#8b5cf6"))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(gradient))
        radius = size * 0.26
        painter.drawRoundedRect(1, 1, size - 2, size - 2, radius, radius)

        pen = QPen(QColor("#ffffff"))
        pen.setWidthF(max(1.5, size * 0.085))
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(
            size * 0.22, size * 0.20, size * 0.42, size * 0.42
        )
        painter.drawLine(
            size * 0.60, size * 0.58, size * 0.79, size * 0.77
        )
        painter.end()
        icon.addPixmap(pixmap)
    return icon


# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------

PALETTES = {
    "dark": {
        "bg": "#080c13",
        "bg_soft": "#0d1420",
        "card": "#111a27",
        "card_alt": "#16202f",
        "input": "#0b111b",
        "border": "#243244",
        "border_soft": "#1b2634",
        "text": "#e8eef6",
        "text_dim": "#9aa8ba",
        "text_faint": "#6b7a8d",
        "accent": "#4f8cff",
        "accent_hover": "#68a0ff",
        "accent_press": "#3d78e6",
        "accent_soft": "#152a40",
        "success": "#2ea043",
        "success_hover": "#38b84f",
        "danger": "#e5484d",
        "danger_hover": "#f05a5f",
        "warn": "#f0b429",
        "selection": "#1d3a5c",
        "selection_text": "#ffffff",
        "alt_row": "#0e1622",
        "scroll": "#26344a",
        "scroll_hover": "#37496a",
        "shadow": "#05070b",
    },
    "light": {
        "bg": "#f4f6fb",
        "bg_soft": "#eef1f8",
        "card": "#ffffff",
        "card_alt": "#f7f9fd",
        "input": "#ffffff",
        "border": "#d7dceb",
        "border_soft": "#e6eaf4",
        "text": "#16203a",
        "text_dim": "#5a6584",
        "text_faint": "#8b95ad",
        "accent": "#2f6feb",
        "accent_hover": "#4680f5",
        "accent_press": "#2559c4",
        "accent_soft": "#e7efff",
        "success": "#1f883d",
        "success_hover": "#28a049",
        "danger": "#cf2b31",
        "danger_hover": "#e03a40",
        "warn": "#b46b00",
        "selection": "#d8e5ff",
        "selection_text": "#16203a",
        "alt_row": "#f7f9fd",
        "scroll": "#c9d1e3",
        "scroll_hover": "#aab6d0",
        "shadow": "#dfe4f0",
    },
}

QSS = string.Template(
    """
* {
    font-family: $font_stack;
    outline: 0;
}

QMainWindow, QWidget {
    background: $bg;
    color: $text;
}

QScrollArea#Canvas, QWidget#CanvasContent {
    background: transparent;
    border: none;
}

QToolTip {
    background: $card_alt;
    color: $text;
    border: 1px solid $border;
    border-radius: 6px;
    padding: 6px 8px;
}

/* ---------- header ---------- */

QLabel#Title {
    color: $text;
    font-size: ${fs_26}px;
    font-weight: 700;
}

QLabel#Subtitle {
    color: $text_dim;
    font-size: ${fs_13}px;
}

QLabel#Hint, QLabel#Info {
    color: $text_dim;
    font-size: ${fs_13}px;
}

QLabel#Footer {
    color: $text_faint;
    font-size: ${fs_12}px;
}

QLabel#Badge {
    background: $accent_soft;
    color: $accent;
    border: 1px solid $accent;
    border-radius: 10px;
    padding: 4px 11px;
    font-size: ${fs_11}px;
    font-weight: 700;
}

QLabel#CurrentPath {
    color: $text_faint;
    font-size: ${fs_12}px;
}

/* ---------- stat chips ---------- */

QFrame#StatChip {
    background: $card;
    border: 1px solid $border_soft;
    border-radius: 12px;
}

QFrame#StatChip QLabel {
    background: transparent;
}

QLabel#ChipValue {
    color: $text;
    font-size: ${fs_21}px;
    font-weight: 700;
}

QLabel#ChipCaption {
    color: $text_faint;
    font-size: ${fs_11}px;
    font-weight: 700;
}

QFrame#StatChip[accent="accent"] QLabel#ChipValue { color: $accent; }
QFrame#StatChip[accent="success"] QLabel#ChipValue { color: $success; }
QFrame#StatChip[accent="danger"] QLabel#ChipValue { color: $danger; }
QFrame#StatChip[accent="warn"] QLabel#ChipValue { color: $warn; }

/* ---------- cards ---------- */

QGroupBox {
    background: $card;
    border: 1px solid $border_soft;
    border-radius: 14px;
    margin-top: 14px;
    padding: 16px 14px 14px 14px;
    font-size: ${fs_12}px;
    font-weight: 700;
    color: $text_dim;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 14px;
    padding: 2px 10px;
    background: $card_alt;
    border: 1px solid $border_soft;
    border-radius: 8px;
    color: $text_dim;
}

QFrame#ActionPanel {
    background: $card;
    border: 1px solid $border_soft;
    border-radius: 14px;
}

QFrame#Separator {
    background: $border_soft;
    max-height: 1px;
    border: none;
}

QLabel#StatusPill {
    border-radius: 11px;
    padding: 5px 12px;
    font-size: ${fs_12}px;
    font-weight: 700;
    background: $card_alt;
    color: $text_dim;
    border: 1px solid $border_soft;
}

QLabel#StatusPill[state="busy"] {
    background: $accent_soft;
    color: $accent;
    border: 1px solid $accent;
}

QLabel#StatusPill[state="done"] {
    color: $success;
    border: 1px solid $success;
}

QLabel#StatusPill[state="error"] {
    color: $danger;
    border: 1px solid $danger;
}

/* ---------- buttons ---------- */

QPushButton {
    min-height: ${mh_34}px;
    padding: 0 14px;
    border-radius: 9px;
    border: 1px solid $border;
    background: $card_alt;
    color: $text;
    font-size: ${fs_13}px;
    font-weight: 700;
}

QPushButton:hover {
    background: $accent_soft;
    border-color: $accent;
    color: $accent;
}

QPushButton:pressed {
    background: $border_soft;
}

QPushButton:disabled {
    background: $bg_soft;
    border-color: $border_soft;
    color: $text_faint;
}

QPushButton#Primary {
    min-width: 140px;
    min-height: ${mh_42}px;
    background: $accent;
    border: 1px solid $accent;
    color: #ffffff;
    font-size: ${fs_14}px;
    font-weight: 700;
}

QPushButton#Primary:hover {
    background: $accent_hover;
    border-color: $accent_hover;
    color: #ffffff;
}

QPushButton#Primary:pressed {
    background: $accent_press;
}

QPushButton#Primary:disabled {
    background: $bg_soft;
    border-color: $border_soft;
    color: $text_faint;
}

QPushButton#Danger {
    min-width: 104px;
    min-height: ${mh_42}px;
    background: transparent;
    border: 1px solid $danger;
    color: $danger;
    font-weight: 700;
}

QPushButton#Danger:hover {
    background: $danger;
    border-color: $danger;
    color: #ffffff;
}

QPushButton#Ghost {
    min-height: ${mh_30}px;
    padding: 0 10px;
    background: transparent;
    border: 1px solid $border;
    color: $text_dim;
    font-size: ${fs_12}px;
}

QPushButton#Ghost:hover {
    color: $accent;
    border-color: $accent;
    background: $accent_soft;
}

/* ---------- inputs ---------- */

QLineEdit, QComboBox, QListWidget, QTableView {
    background: $input;
    border: 1px solid $border;
    border-radius: 10px;
    color: $text;
    selection-background-color: $selection;
    selection-color: $selection_text;
}

QLineEdit {
    min-height: ${mh_32}px;
    padding: 0 10px;
}

QLineEdit:focus, QComboBox:focus {
    border-color: $accent;
}

QLineEdit:disabled {
    background: $bg_soft;
    color: $text_faint;
    border-color: $border_soft;
}

QLineEdit#Filter {
    min-height: ${mh_30}px;
}

QComboBox {
    min-height: ${mh_32}px;
    min-width: 120px;
    padding: 0 10px;
}

QComboBox::drop-down {
    border: none;
    width: 22px;
}

QComboBox QAbstractItemView {
    background: $card_alt;
    border: 1px solid $border;
    border-radius: 8px;
    padding: 4px;
    color: $text;
    selection-background-color: $accent;
    selection-color: #ffffff;
}

QListWidget {
    padding: 6px;
}

QListWidget::item {
    padding: 8px 6px;
    border-radius: 8px;
    color: $text;
}

QListWidget::item:hover {
    background: $card_alt;
}

QListWidget::item:selected {
    background: $selection;
    color: $selection_text;
}

QCheckBox, QRadioButton {
    spacing: 9px;
    padding: 5px 2px;
    color: $text;
    background: transparent;
    font-size: ${fs_13}px;
    font-weight: 600;
}

QCheckBox:disabled, QRadioButton:disabled {
    color: $text_faint;
}

QCheckBox::indicator, QRadioButton::indicator, QListWidget::indicator {
    width: 17px;
    height: 17px;
    background: $input;
    border: 2px solid $border;
}

QCheckBox::indicator, QListWidget::indicator {
    border-radius: 5px;
}

QRadioButton::indicator {
    border-radius: 10px;
}

QCheckBox::indicator:hover, QRadioButton::indicator:hover,
QListWidget::indicator:hover {
    border-color: $accent;
}

QCheckBox::indicator:checked, QListWidget::indicator:checked {
    background: $accent;
    border: 2px solid $accent;
}

QRadioButton::indicator:checked {
    background: $card;
    border: 5px solid $accent;
}

/* ---------- table ---------- */

QTableView {
    gridline-color: $border_soft;
    alternate-background-color: $alt_row;
}

QTableView::item {
    padding: 4px 8px;
    border: none;
}

QTableView::item:selected {
    background: $selection;
    color: $selection_text;
}

QHeaderView::section {
    background: $card_alt;
    color: $text_dim;
    border: none;
    border-right: 1px solid $border_soft;
    border-bottom: 1px solid $border_soft;
    padding: 8px 8px;
    font-size: ${fs_12}px;
    font-weight: 700;
}

QHeaderView::section:hover {
    color: $accent;
}

QTableCornerButton::section {
    background: $card_alt;
    border: none;
}

/* ---------- misc ---------- */

QProgressBar {
    min-height: 6px;
    max-height: 6px;
    border: none;
    border-radius: 3px;
    background: $border_soft;
}

QProgressBar::chunk {
    border-radius: 3px;
    background: $accent;
}

QScrollBar:vertical {
    background: transparent;
    width: 11px;
    margin: 4px 2px 4px 2px;
}

QScrollBar::handle:vertical {
    background: $scroll;
    border-radius: 5px;
    min-height: ${mh_30}px;
}

QScrollBar::handle:vertical:hover {
    background: $scroll_hover;
}

QScrollBar:horizontal {
    background: transparent;
    height: 11px;
    margin: 2px 4px 2px 4px;
}

QScrollBar::handle:horizontal {
    background: $scroll;
    border-radius: 5px;
    min-width: ${mh_30}px;
}

QScrollBar::handle:horizontal:hover {
    background: $scroll_hover;
}

QScrollBar::add-line, QScrollBar::sub-line {
    height: 0;
    width: 0;
}

QScrollBar::add-page, QScrollBar::sub-page {
    background: transparent;
}

QSplitter::handle {
    background: transparent;
    height: 10px;
}

QMenu {
    background: $card_alt;
    border: 1px solid $border;
    border-radius: 10px;
    padding: 6px;
    color: $text;
}

QMenu::item {
    padding: 7px 18px;
    border-radius: 6px;
}

QMenu::item:selected {
    background: $accent;
    color: #ffffff;
}

QMessageBox, QFileDialog {
    background: $bg;
    color: $text;
}
"""
)


# ---------------------------------------------------------------------------
# Translations
# ---------------------------------------------------------------------------

TEXTS = {
    "en": {
        "title": "Hidden File Hunter",
        "subtitle": "Safe, read-only scanner for hidden and system files",
        "safe_badge": "READ-ONLY",
        "language": "Language",
        "theme_dark": "Dark",
        "theme_light": "Light",
        "stat_found": "FOUND",
        "stat_copied": "COPIED",
        "stat_errors": "SKIPPED",
        "stat_scanned": "FILES CHECKED",
        "stat_elapsed": "ELAPSED",
        "drives_title": "SCAN SOURCES",
        "drives_hint": "Pick the drives you want to search.",
        "select_all": "Select all",
        "clear": "Clear",
        "refresh": "Refresh",
        "removable": "Show removable drives",
        "options_title": "SCAN OPTIONS",
        "options_hint": "Hidden files are always included.",
        "include_system": "Also include system files",
        "follow_links": "Follow junctions and symlinks (slow, can loop)",
        "safety_note": "Files are only read or copied \u2014 never changed or deleted.",
        "output_title": "OUTPUT",
        "output_hint": "How should results be saved?",
        "mode_paths": "Save file paths to TXT while scanning",
        "mode_copy": "Copy the discovered files to a folder",
        "txt_file": "TXT file",
        "destination": "Destination",
        "browse": "Browse",
        "start": "START SCAN",
        "stop": "STOP",
        "ready": "Ready",
        "scanning": "Scanning\u2026",
        "stopping": "Stopping\u2026",
        "completed": "Completed",
        "stopped": "Stopped",
        "error": "Error",
        "results_title": "RESULTS",
        "filter_placeholder": "Filter by name or path\u2026",
        "rows_shown": "{shown} of {total} shown",
        "export_csv": "Export CSV",
        "export_txt": "Export TXT",
        "open_folder": "Open output folder",
        "clear_results": "Clear list",
        "col_type": "Type",
        "col_name": "Name",
        "col_size": "Size",
        "col_modified": "Modified",
        "col_folder": "Folder",
        "kind_hidden": "HIDDEN",
        "kind_system": "SYSTEM",
        "ctx_copy_path": "Copy full path",
        "ctx_copy_folder": "Copy folder path",
        "ctx_open_folder": "Open containing folder",
        "msg_select_drive": "Select at least one drive to scan.",
        "msg_choose_txt": "Choose where the TXT result file should be saved.",
        "msg_choose_destination": "Choose a destination folder for the copied files.",
        "msg_bad_destination": "That destination folder cannot be created or written to.",
        "msg_no_results": "No hidden files were found with these settings.",
        "msg_copied": "{copied} file(s) copied to:\n{destination}\n\nThe originals were not modified.",
        "msg_saved_txt": "Paths were saved to:\n{path}",
        "msg_nothing_export": "There is nothing to export yet.",
        "msg_exported": "Saved to:\n{path}",
        "msg_truncated": "The list shows the first {limit} results; the saved file contains everything.",
        "msg_no_output": "No output folder yet \u2014 run a scan first.",
        "msg_running_title": "Scan in progress",
        "msg_running_close": "A scan is still running. Stop it and quit?",
        "summary": "{found} found \u2022 {scanned} files checked \u2022 {errors} skipped \u2022 {elapsed}",
        "drive_free": "{free} free of {total}",
        "footer": "Hidden File Hunter {version} \u2014 made by jozmoz | wraith",
    },
    "fa": {
        "title": "\u0634\u06a9\u0627\u0631\u0686\u06cc \u0641\u0627\u06cc\u0644\u200c\u0647\u0627\u06cc \u0645\u062e\u0641\u06cc",
        "subtitle": "\u0627\u0628\u0632\u0627\u0631 \u0627\u0645\u0646 \u0648 \u0641\u0642\u0637\u200c\u062e\u0648\u0627\u0646\u062f\u0646\u06cc \u0628\u0631\u0627\u06cc \u067e\u06cc\u062f\u0627 \u06a9\u0631\u062f\u0646 \u0641\u0627\u06cc\u0644\u200c\u0647\u0627\u06cc \u0645\u062e\u0641\u06cc \u0648 \u0633\u06cc\u0633\u062a\u0645\u06cc",
        "safe_badge": "\u0641\u0642\u0637 \u062e\u0648\u0627\u0646\u062f\u0646",
        "language": "\u0632\u0628\u0627\u0646",
        "theme_dark": "\u062a\u06cc\u0631\u0647",
        "theme_light": "\u0631\u0648\u0634\u0646",
        "stat_found": "\u067e\u06cc\u062f\u0627 \u0634\u062f\u0647",
        "stat_copied": "\u06a9\u067e\u06cc \u0634\u062f\u0647",
        "stat_errors": "\u0631\u062f \u0634\u062f\u0647",
        "stat_scanned": "\u0628\u0631\u0631\u0633\u06cc \u0634\u062f\u0647",
        "stat_elapsed": "\u0632\u0645\u0627\u0646",
        "drives_title": "\u0645\u0646\u0627\u0628\u0639 \u0627\u0633\u06a9\u0646",
        "drives_hint": "\u062f\u0631\u0627\u06cc\u0648\u0647\u0627\u06cc\u06cc \u0631\u0627 \u06a9\u0647 \u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u06cc\u062f \u0628\u0631\u0631\u0633\u06cc \u0634\u0648\u0646\u062f \u0627\u0646\u062a\u062e\u0627\u0628 \u06a9\u0646\u06cc\u062f.",
        "select_all": "\u0627\u0646\u062a\u062e\u0627\u0628 \u0647\u0645\u0647",
        "clear": "\u067e\u0627\u06a9 \u06a9\u0631\u062f\u0646",
        "refresh": "\u0628\u0647\u200c\u0631\u0648\u0632\u0631\u0633\u0627\u0646\u06cc",
        "removable": "\u0646\u0645\u0627\u06cc\u0634 \u062f\u0631\u0627\u06cc\u0648\u0647\u0627\u06cc \u062c\u062f\u0627\u0634\u062f\u0646\u06cc",
        "options_title": "\u062a\u0646\u0632\u06cc\u0645\u0627\u062a \u0627\u0633\u06a9\u0646",
        "options_hint": "\u0641\u0627\u06cc\u0644\u200c\u0647\u0627\u06cc \u0645\u062e\u0641\u06cc \u0647\u0645\u06cc\u0634\u0647 \u0628\u0631\u0631\u0633\u06cc \u0645\u06cc\u200c\u0634\u0648\u0646\u062f.",
        "include_system": "\u0641\u0627\u06cc\u0644\u200c\u0647\u0627\u06cc \u0633\u06cc\u0633\u062a\u0645\u06cc \u0647\u0645 \u0628\u0631\u0631\u0633\u06cc \u0634\u0648\u0646\u062f",
        "follow_links": "\u062f\u0646\u0628\u0627\u0644 \u06a9\u0631\u062f\u0646 \u0644\u06cc\u0646\u06a9\u200c\u0647\u0627 \u0648 Junction\u200c\u0647\u0627 (\u06a9\u0646\u062f \u0648 \u0645\u0645\u06a9\u0646 \u0627\u0633\u062a \u062d\u0644\u0642\u0647 \u0634\u0648\u062f)",
        "safety_note": "\u0641\u0627\u06cc\u0644\u200c\u0647\u0627 \u0641\u0642\u0637 \u062e\u0648\u0627\u0646\u062f\u0647 \u06cc\u0627 \u06a9\u067e\u06cc \u0645\u06cc\u200c\u0634\u0648\u0646\u062f \u2014 \u0647\u0631\u06af\u0632 \u062a\u063a\u06cc\u06cc\u0631 \u06cc\u0627 \u062d\u0630\u0641 \u0646\u0645\u06cc\u200c\u0634\u0648\u0646\u062f.",
        "output_title": "\u062e\u0631\u0648\u062c\u06cc",
        "output_hint": "\u0646\u062a\u0627\u06cc\u062c \u0686\u06af\u0648\u0646\u0647 \u0630\u062e\u06cc\u0631\u0647 \u0634\u0648\u0646\u062f\u061f",
        "mode_paths": "\u0630\u062e\u06cc\u0631\u0647 \u0645\u0633\u06cc\u0631 \u0641\u0627\u06cc\u0644\u200c\u0647\u0627 \u062f\u0631 \u0641\u0627\u06cc\u0644 TXT \u062f\u0631 \u0647\u0646\u06af\u0627\u0645 \u0627\u0633\u06a9\u0646",
        "mode_copy": "\u06a9\u067e\u06cc \u06a9\u0631\u062f\u0646 \u0641\u0627\u06cc\u0644\u200c\u0647\u0627\u06cc \u067e\u06cc\u062f\u0627\u0634\u062f\u0647 \u062f\u0631 \u06cc\u06a9 \u067e\u0648\u0634\u0647",
        "txt_file": "\u0641\u0627\u06cc\u0644 TXT",
        "destination": "\u067e\u0648\u0634\u0647 \u0645\u0642\u0635\u062f",
        "browse": "\u0627\u0646\u062a\u062e\u0627\u0628",
        "start": "\u0634\u0631\u0648\u0639 \u0627\u0633\u06a9\u0646",
        "stop": "\u062a\u0648\u0642\u0641",
        "ready": "\u0622\u0645\u0627\u062f\u0647",
        "scanning": "\u062f\u0631 \u062d\u0627\u0644 \u0627\u0633\u06a9\u0646\u2026",
        "stopping": "\u062f\u0631 \u062d\u0627\u0644 \u062a\u0648\u0642\u0641\u2026",
        "completed": "\u062a\u0645\u0627\u0645 \u0634\u062f",
        "stopped": "\u0645\u062a\u0648\u0642\u0641 \u0634\u062f",
        "error": "\u062e\u0637\u0627",
        "results_title": "\u0646\u062a\u0627\u06cc\u062c",
        "filter_placeholder": "\u062c\u0633\u062a\u062c\u0648 \u062f\u0631 \u0646\u0627\u0645 \u06cc\u0627 \u0645\u0633\u06cc\u0631\u2026",
        "rows_shown": "\u0646\u0645\u0627\u06cc\u0634 {shown} \u0627\u0632 {total}",
        "export_csv": "\u062e\u0631\u0648\u062c\u06cc CSV",
        "export_txt": "\u062e\u0631\u0648\u062c\u06cc TXT",
        "open_folder": "\u0628\u0627\u0632 \u06a9\u0631\u062f\u0646 \u067e\u0648\u0634\u0647 \u062e\u0631\u0648\u062c\u06cc",
        "clear_results": "\u067e\u0627\u06a9 \u06a9\u0631\u062f\u0646 \u0644\u06cc\u0633\u062a",
        "col_type": "\u0646\u0648\u0639",
        "col_name": "\u0646\u0627\u0645 \u0641\u0627\u06cc\u0644",
        "col_size": "\u062d\u062c\u0645",
        "col_modified": "\u0622\u062e\u0631\u06cc\u0646 \u062a\u063a\u06cc\u06cc\u0631",
        "col_folder": "\u067e\u0648\u0634\u0647",
        "kind_hidden": "\u0645\u062e\u0641\u06cc",
        "kind_system": "\u0633\u06cc\u0633\u062a\u0645\u06cc",
        "ctx_copy_path": "\u06a9\u067e\u06cc \u0645\u0633\u06cc\u0631 \u06a9\u0627\u0645\u0644",
        "ctx_copy_folder": "\u06a9\u067e\u06cc \u0645\u0633\u06cc\u0631 \u067e\u0648\u0634\u0647",
        "ctx_open_folder": "\u0628\u0627\u0632 \u06a9\u0631\u062f\u0646 \u067e\u0648\u0634\u0647 \u0641\u0627\u06cc\u0644",
        "msg_select_drive": "\u062d\u062f\u0627\u0642\u0644 \u06cc\u06a9 \u062f\u0631\u0627\u06cc\u0648 \u0631\u0627 \u0627\u0646\u062a\u062e\u0627\u0628 \u06a9\u0646\u06cc\u062f.",
        "msg_choose_txt": "\u0645\u062d\u0644 \u0630\u062e\u06cc\u0631\u0647 \u0641\u0627\u06cc\u0644 TXT \u0631\u0627 \u0627\u0646\u062a\u062e\u0627\u0628 \u06a9\u0646\u06cc\u062f.",
        "msg_choose_destination": "\u067e\u0648\u0634\u0647 \u0645\u0642\u0635\u062f \u0628\u0631\u0627\u06cc \u06a9\u067e\u06cc \u0641\u0627\u06cc\u0644\u200c\u0647\u0627 \u0631\u0627 \u0627\u0646\u062a\u062e\u0627\u0628 \u06a9\u0646\u06cc\u062f.",
        "msg_bad_destination": "\u0627\u0645\u06a9\u0627\u0646 \u0633\u0627\u062e\u062a \u06cc\u0627 \u0646\u0648\u0634\u062a\u0646 \u062f\u0631 \u0627\u06cc\u0646 \u067e\u0648\u0634\u0647 \u0645\u0642\u0635\u062f \u0648\u062c\u0648\u062f \u0646\u062f\u0627\u0631\u062f.",
        "msg_no_results": "\u0628\u0627 \u0627\u06cc\u0646 \u062a\u0646\u0632\u06cc\u0645\u0627\u062a \u0647\u06cc\u0686 \u0641\u0627\u06cc\u0644 \u0645\u062e\u0641\u06cc\u200c\u0627\u06cc \u067e\u06cc\u062f\u0627 \u0646\u0634\u062f.",
        "msg_copied": "{copied} \u0641\u0627\u06cc\u0644 \u062f\u0631 \u0627\u06cc\u0646 \u0645\u0633\u06cc\u0631 \u06a9\u067e\u06cc \u0634\u062f:\n{destination}\n\n\u0641\u0627\u06cc\u0644\u200c\u0647\u0627\u06cc \u0627\u0635\u0644\u06cc \u062a\u063a\u06cc\u06cc\u0631 \u0646\u06a9\u0631\u062f\u0646\u062f.",
        "msg_saved_txt": "\u0645\u0633\u06cc\u0631\u0647\u0627 \u0630\u062e\u06cc\u0631\u0647 \u0634\u062f \u062f\u0631:\n{path}",
        "msg_nothing_export": "\u0641\u0639\u0644\u0627\u064b \u0686\u06cc\u0632\u06cc \u0628\u0631\u0627\u06cc \u062e\u0631\u0648\u062c\u06cc \u06af\u0631\u0641\u062a\u0646 \u0648\u062c\u0648\u062f \u0646\u062f\u0627\u0631\u062f.",
        "msg_exported": "\u0630\u062e\u06cc\u0631\u0647 \u0634\u062f \u062f\u0631:\n{path}",
        "msg_truncated": "\u0641\u0642\u0637 {limit} \u0646\u062a\u06cc\u062c\u0647 \u0627\u0648\u0644 \u062f\u0631 \u0644\u06cc\u0633\u062a \u0646\u0645\u0627\u06cc\u0634 \u062f\u0627\u062f\u0647 \u0645\u06cc\u200c\u0634\u0648\u062f\u061b \u0641\u0627\u06cc\u0644 \u0630\u062e\u06cc\u0631\u0647\u200c\u0634\u062f\u0647 \u06a9\u0627\u0645\u0644 \u0627\u0633\u062a.",
        "msg_no_output": "\u0647\u0646\u0648\u0632 \u062e\u0631\u0648\u062c\u06cc\u200c\u0627\u06cc \u0633\u0627\u062e\u062a\u0647 \u0646\u0634\u062f\u0647 \u2014 \u0627\u0648\u0644 \u06cc\u06a9 \u0627\u0633\u06a9\u0646 \u0627\u062c\u0631\u0627 \u06a9\u0646\u06cc\u062f.",
        "msg_running_title": "\u0627\u0633\u06a9\u0646 \u062f\u0631 \u062d\u0627\u0644 \u0627\u062c\u0631\u0627",
        "msg_running_close": "\u06cc\u06a9 \u0627\u0633\u06a9\u0646 \u062f\u0631 \u062d\u0627\u0644 \u0627\u062c\u0631\u0627\u0633\u062a. \u0645\u062a\u0648\u0642\u0641 \u0634\u0648\u062f \u0648 \u0628\u0631\u0646\u0627\u0645\u0647 \u0628\u0633\u062a\u0647 \u0634\u0648\u062f\u061f",
        "summary": "{found} \u067e\u06cc\u062f\u0627 \u0634\u062f \u2022 {scanned} \u0641\u0627\u06cc\u0644 \u0628\u0631\u0631\u0633\u06cc \u0634\u062f \u2022 {errors} \u0631\u062f \u0634\u062f \u2022 {elapsed}",
        "drive_free": "{free} \u0622\u0632\u0627\u062f \u0627\u0632 {total}",
        "footer": "\u0634\u06a9\u0627\u0631\u0686\u06cc \u0641\u0627\u06cc\u0644\u200c\u0647\u0627\u06cc \u0645\u062e\u0641\u06cc {version} \u2014 \u0633\u0627\u062e\u062a\u0647 jozmoz | wraith",
    },
}

FONT_CANDIDATES = {
    "en": ["Segoe UI Variable Display", "Segoe UI", "Inter", "Noto Sans", "DejaVu Sans"],
    "fa": ["Vazirmatn", "Vazir", "IRANSansX", "IRANSans", "Segoe UI", "Tahoma", "Noto Sans Arabic"],
}

MONO_CANDIDATES = ["Cascadia Mono", "Consolas", "JetBrains Mono", "DejaVu Sans Mono", "monospace"]


def pick_font(candidates) -> str:
    try:
        available = {name.lower() for name in QFontDatabase.families()}
    except Exception:  # noqa: BLE001 - font database can fail on odd systems
        available = set()
    for name in candidates:
        if name.lower() in available:
            return name
    return candidates[-1]


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------


def desktop_dir() -> str:
    for location in (
        QStandardPaths.StandardLocation.DesktopLocation,
        QStandardPaths.StandardLocation.DocumentsLocation,
        QStandardPaths.StandardLocation.HomeLocation,
    ):
        path = QStandardPaths.writableLocation(location)
        if path and os.path.isdir(path):
            return path
    return os.path.expanduser("~")


class HiddenFileHunter(QMainWindow):
    def __init__(self):
        super().__init__()

        self.settings = QSettings(ORG_NAME, APP_NAME)
        self.language = str(self.settings.value("language", "en") or "en")
        if self.language not in TEXTS:
            self.language = "en"
        self.theme = str(self.settings.value("theme", "dark") or "dark")
        if self.theme not in PALETTES:
            self.theme = "dark"

        self.scanner = None
        self.scan_copy_mode = False
        self.scan_started_at = 0.0
        self.last_output_folder = ""
        self.truncation_warned = False
        self._current_path_full = ""
        self.stats = {"found": 0, "copied": 0, "errors": 0, "scanned": 0}

        self.model = ResultsModel(self)
        self.proxy = ResultsProxy(self)
        self.proxy.setSourceModel(self.model)

        self.elapsed_timer = QTimer(self)
        self.elapsed_timer.setInterval(500)
        self.elapsed_timer.timeout.connect(self.update_elapsed)

        self.setWindowIcon(build_app_icon())
        self.resize(1240, 860)
        # A small floor only: the content scrolls instead of being squeezed.
        self.setMinimumSize(760, 480)

        self.build_ui()
        self.build_shortcuts()
        self.apply_theme()
        self.restore_preferences()
        self.retranslate()
        self.refresh_drives()
        self.update_output_mode()
        self.set_status("ready", "idle")

    # ------------------------------------------------------------------ i18n
    def t(self, key: str) -> str:
        return TEXTS.get(self.language, TEXTS["en"]).get(key, TEXTS["en"].get(key, key))

    # -------------------------------------------------------------------- UI
    def build_ui(self) -> None:
        # Everything lives inside a scroll area. Without it, a window shorter
        # than the content makes Qt squeeze rows on top of each other, so
        # labels end up clipped and covered by the next row.
        canvas = QWidget()
        canvas.setObjectName("CanvasContent")

        outer = QVBoxLayout(canvas)
        outer.setContentsMargins(24, 20, 24, 16)
        outer.setSpacing(14)

        outer.addLayout(self.build_header())
        outer.addLayout(self.build_chips())

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(10)

        top = QWidget()
        top_layout = QVBoxLayout(top)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(14)
        top_layout.addLayout(self.build_cards())
        top_layout.addWidget(self.build_action_panel())
        splitter.addWidget(top)

        splitter.addWidget(self.build_results_card())
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        self.splitter = splitter
        outer.addWidget(splitter, 1)

        self.footer_label = QLabel()
        self.footer_label.setObjectName("Footer")
        self.footer_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        outer.addWidget(self.footer_label)

        scroll = QScrollArea()
        scroll.setObjectName("Canvas")
        scroll.setWidget(canvas)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.canvas_scroll = scroll
        self.setCentralWidget(scroll)

    def build_header(self) -> QHBoxLayout:
        header = QHBoxLayout()
        header.setSpacing(14)

        self.logo_label = QLabel()
        self.logo_label.setPixmap(crisp_icon_pixmap(build_app_icon(), 46, self))
        self.logo_label.setFixedSize(46, 46)
        header.addWidget(self.logo_label)

        brand = QVBoxLayout()
        brand.setSpacing(2)

        title_row = QHBoxLayout()
        title_row.setSpacing(8)
        self.title_label = QLabel()
        self.title_label.setObjectName("Title")
        self.badge_label = QLabel()
        self.badge_label.setObjectName("Badge")
        title_row.addWidget(self.title_label)
        title_row.addWidget(self.badge_label)
        title_row.addStretch()

        self.subtitle_label = QLabel()
        self.subtitle_label.setObjectName("Subtitle")

        brand.addLayout(title_row)
        brand.addWidget(self.subtitle_label)
        header.addLayout(brand, 1)

        self.theme_button = QPushButton()
        self.theme_button.setObjectName("Ghost")
        self.theme_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.theme_button.clicked.connect(self.toggle_theme)
        header.addWidget(self.theme_button)

        self.language_combo = QComboBox()
        self.language_combo.addItem("English", "en")
        self.language_combo.addItem("\u0641\u0627\u0631\u0633\u06cc", "fa")
        self.language_combo.setCursor(Qt.CursorShape.PointingHandCursor)
        self.language_combo.currentIndexChanged.connect(self.language_changed)
        header.addWidget(self.language_combo)

        return header

    def build_chips(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(12)

        self.chip_found = StatChip(accent="accent")
        self.chip_copied = StatChip(accent="success")
        self.chip_errors = StatChip(accent="warn")
        self.chip_scanned = StatChip()
        self.chip_elapsed = StatChip()

        for chip in (
            self.chip_found,
            self.chip_copied,
            self.chip_errors,
            self.chip_scanned,
            self.chip_elapsed,
        ):
            row.addWidget(chip)
        return row

    def build_cards(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(14)

        # --- drives -------------------------------------------------------
        self.drive_card = QGroupBox()
        drive_layout = QVBoxLayout(self.drive_card)
        drive_layout.setSpacing(9)

        self.drive_hint = QLabel()
        self.drive_hint.setObjectName("Hint")
        self.drive_hint.setWordWrap(True)
        drive_layout.addWidget(self.drive_hint)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.select_all_btn = QPushButton()
        self.clear_btn = QPushButton()
        self.refresh_btn = QPushButton()
        for button in (self.select_all_btn, self.clear_btn, self.refresh_btn):
            button.setObjectName("Ghost")
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            buttons.addWidget(button)
        buttons.addStretch()
        self.select_all_btn.clicked.connect(self.select_all_drives)
        self.clear_btn.clicked.connect(self.clear_drives)
        self.refresh_btn.clicked.connect(self.refresh_drives)
        drive_layout.addLayout(buttons)

        self.drive_list = QListWidget()
        self.drive_list.setMinimumHeight(150)
        self.drive_list.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        drive_layout.addWidget(self.drive_list, 1)

        self.removable_check = QCheckBox()
        self.removable_check.toggled.connect(lambda _checked: self.refresh_drives())
        drive_layout.addWidget(self.removable_check)

        row.addWidget(self.drive_card, 1)

        # --- options + output --------------------------------------------
        right = QVBoxLayout()
        right.setSpacing(14)

        self.options_card = QGroupBox()
        options_layout = QVBoxLayout(self.options_card)
        options_layout.setSpacing(6)

        self.options_hint = QLabel()
        self.options_hint.setObjectName("Hint")
        self.options_hint.setWordWrap(True)
        options_layout.addWidget(self.options_hint)

        self.system_check = QCheckBox()
        self.links_check = QCheckBox()
        options_layout.addWidget(self.system_check)
        options_layout.addWidget(self.links_check)

        self.safety_label = QLabel()
        self.safety_label.setObjectName("Info")
        self.safety_label.setWordWrap(True)
        options_layout.addWidget(self.safety_label)
        options_layout.addStretch()

        right.addWidget(self.options_card)

        self.output_card = QGroupBox()
        output_layout = QVBoxLayout(self.output_card)
        output_layout.setSpacing(6)

        self.output_hint = QLabel()
        self.output_hint.setObjectName("Hint")
        output_layout.addWidget(self.output_hint)

        self.paths_radio = QRadioButton()
        self.copy_radio = QRadioButton()
        self.paths_radio.setChecked(True)
        self.output_group = QButtonGroup(self)
        self.output_group.addButton(self.paths_radio)
        self.output_group.addButton(self.copy_radio)
        output_layout.addWidget(self.paths_radio)

        txt_row = QHBoxLayout()
        txt_row.setSpacing(8)
        self.txt_label = QLabel()
        self.txt_label.setObjectName("Info")
        self.txt_edit = QLineEdit()
        self.txt_edit.setReadOnly(True)
        self.txt_edit.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.txt_edit.textChanged.connect(self.txt_edit.setToolTip)
        self.txt_browse = QPushButton()
        self.txt_browse.setObjectName("Ghost")
        self.txt_browse.setCursor(Qt.CursorShape.PointingHandCursor)
        self.txt_browse.clicked.connect(self.choose_txt)
        txt_row.addWidget(self.txt_label)
        txt_row.addWidget(self.txt_edit, 1)
        txt_row.addWidget(self.txt_browse)
        output_layout.addLayout(txt_row)

        output_layout.addWidget(self.copy_radio)

        copy_row = QHBoxLayout()
        copy_row.setSpacing(8)
        self.copy_label = QLabel()
        self.copy_label.setObjectName("Info")
        self.copy_edit = QLineEdit()
        self.copy_edit.setReadOnly(True)
        self.copy_edit.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.copy_edit.textChanged.connect(self.copy_edit.setToolTip)
        self.copy_browse = QPushButton()
        self.copy_browse.setObjectName("Ghost")
        self.copy_browse.setCursor(Qt.CursorShape.PointingHandCursor)
        self.copy_browse.clicked.connect(self.choose_destination)
        copy_row.addWidget(self.copy_label)
        copy_row.addWidget(self.copy_edit, 1)
        copy_row.addWidget(self.copy_browse)
        output_layout.addLayout(copy_row)

        self.paths_radio.toggled.connect(self.update_output_mode)
        right.addWidget(self.output_card)

        row.addLayout(right, 1)
        return row

    def build_action_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("ActionPanel")

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        top = QHBoxLayout()
        top.setSpacing(12)

        self.status_pill = QLabel()
        self.status_pill.setObjectName("StatusPill")
        self.status_pill.setProperty("state", "idle")
        top.addWidget(self.status_pill)

        self.current_path_label = QLabel()
        self.current_path_label.setObjectName("CurrentPath")
        self.current_path_label.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.current_path_label.setSizePolicy(
            QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred
        )
        top.addWidget(self.current_path_label, 1)

        self.stop_btn = QPushButton()
        self.stop_btn.setObjectName("Danger")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.stop_btn.clicked.connect(self.stop_scan)
        top.addWidget(self.stop_btn)

        self.start_btn = QPushButton()
        self.start_btn.setObjectName("Primary")
        self.start_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.start_btn.clicked.connect(self.start_scan)
        top.addWidget(self.start_btn)

        layout.addLayout(top)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        return panel

    def build_results_card(self) -> QGroupBox:
        self.results_card = QGroupBox()
        layout = QVBoxLayout(self.results_card)
        layout.setSpacing(9)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self.filter_edit = QLineEdit()
        self.filter_edit.setObjectName("Filter")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.filter_edit.textChanged.connect(self.filter_changed)
        toolbar.addWidget(self.filter_edit, 1)

        self.rows_label = QLabel()
        self.rows_label.setObjectName("Info")
        toolbar.addWidget(self.rows_label)

        self.export_csv_btn = QPushButton()
        self.export_txt_btn = QPushButton()
        self.open_folder_btn = QPushButton()
        self.clear_results_btn = QPushButton()
        for button, handler in (
            (self.export_csv_btn, self.export_csv),
            (self.export_txt_btn, self.export_txt),
            (self.open_folder_btn, self.open_output_folder),
            (self.clear_results_btn, self.clear_results),
        ):
            button.setObjectName("Ghost")
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(handler)
            toolbar.addWidget(button)

        layout.addLayout(toolbar)

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self.table.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_table_menu)
        self.table.doubleClicked.connect(self.open_row_folder)
        self.table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

        vertical_header = self.table.verticalHeader()
        vertical_header.setVisible(False)
        vertical_header.setDefaultSectionSize(28)
        vertical_header.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)

        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setHighlightSections(False)
        header.setMinimumSectionSize(72)
        header.setTextElideMode(Qt.TextElideMode.ElideRight)
        # Column widths are measured from the live font in refresh_column_widths().

        layout.addWidget(self.table, 1)
        return self.results_card

    def build_shortcuts(self) -> None:
        start_action = QAction(self)
        start_action.setShortcut(QKeySequence("Ctrl+Return"))
        start_action.triggered.connect(self.start_scan)
        self.addAction(start_action)

        stop_action = QAction(self)
        stop_action.setShortcut(QKeySequence("Esc"))
        stop_action.triggered.connect(self.stop_scan)
        self.addAction(stop_action)

        refresh_action = QAction(self)
        refresh_action.setShortcut(QKeySequence("F5"))
        refresh_action.triggered.connect(self.refresh_drives)
        self.addAction(refresh_action)

        find_action = QAction(self)
        find_action.setShortcut(QKeySequence("Ctrl+F"))
        find_action.triggered.connect(lambda: self.filter_edit.setFocus())
        self.addAction(find_action)

        export_action = QAction(self)
        export_action.setShortcut(QKeySequence("Ctrl+S"))
        export_action.triggered.connect(self.export_csv)
        self.addAction(export_action)

    # ----------------------------------------------------------------- theme
    def apply_theme(self) -> None:
        palette = dict(PALETTES[self.theme])
        ui_font = pick_font(FONT_CANDIDATES.get(self.language, FONT_CANDIDATES["en"]))

        # Persian glyphs carry dots and descenders, so they need a little more
        # room than Latin text at the same nominal size.
        scale = 1.08 if self.language == "fa" else 1.0
        for size in (11, 12, 13, 14, 21, 26):
            palette[f"fs_{size}"] = max(10, int(round(size * scale)))
        for height in (30, 32, 34, 42):
            palette[f"mh_{height}"] = int(round(height * scale))

        fallbacks = '"Segoe UI", "Noto Sans", "Noto Sans Arabic", "Tahoma", sans-serif'
        palette["font_stack"] = f'"{ui_font}", {fallbacks}'
        self.setStyleSheet(QSS.safe_substitute(palette))
        self.model.set_system_color(palette["warn"])

        base_size = 10.5 * scale
        app = QApplication.instance()
        if app is not None:
            app.setFont(build_font(ui_font, base_size))

        table_font = build_font(ui_font, base_size - 0.5)
        self.table.setFont(table_font)
        self.table.horizontalHeader().setFont(
            build_font(ui_font, base_size - 1.5, bold=True)
        )

        # Sizes and dates use a monospaced font so their digits line up.
        self.model.set_numeric_font(
            build_font(pick_font(MONO_CANDIDATES), base_size - 1.0)
        )

        metrics = QFontMetrics(table_font)
        self.table.verticalHeader().setDefaultSectionSize(max(28, metrics.height() + 12))

        # Checkboxes and radios keep room for a full line plus padding, so
        # descenders and Persian dots are never cut off.
        row_metrics = QFontMetrics(build_font(ui_font, base_size))
        control_height = max(26, row_metrics.height() + 12)
        for control in (
            self.removable_check,
            self.system_check,
            self.links_check,
            self.paths_radio,
            self.copy_radio,
        ):
            control.setMinimumHeight(control_height)

        self.refresh_column_widths()
        self.set_current_path(self._current_path_full)

    def refresh_column_widths(self) -> None:
        """Measure headers and sample values so no column cuts its text off."""
        metrics = QFontMetrics(self.table.font())
        header_metrics = QFontMetrics(self.table.horizontalHeader().font())
        headers = {
            ResultsModel.COL_KIND: self.t("col_type"),
            ResultsModel.COL_NAME: self.t("col_name"),
            ResultsModel.COL_SIZE: self.t("col_size"),
            ResultsModel.COL_MODIFIED: self.t("col_modified"),
        }
        samples = {
            ResultsModel.COL_KIND: (self.t("kind_hidden"), self.t("kind_system")),
            ResultsModel.COL_NAME: ("a-hidden-file-name.config",),
            ResultsModel.COL_SIZE: ("1023.9 MB",),
            ResultsModel.COL_MODIFIED: (format_timestamp(time.time()),),
        }
        for column, header_text in headers.items():
            # The extra room covers cell padding plus the sort indicator.
            width = header_metrics.horizontalAdvance(str(header_text)) + 48
            for sample in samples[column]:
                width = max(width, metrics.horizontalAdvance(str(sample)) + 30)
            self.table.setColumnWidth(column, width)

    def toggle_theme(self) -> None:
        self.theme = "light" if self.theme == "dark" else "dark"
        self.settings.setValue("theme", self.theme)
        self.apply_theme()
        self.retranslate()

    def set_status(self, key: str, state: str, suffix: str = "") -> None:
        text = self.t(key)
        if suffix:
            text = f"{text}  {suffix}"
        self.status_pill.setText(text)
        self.status_pill.setProperty("state", state)
        self.status_pill.style().unpolish(self.status_pill)
        self.status_pill.style().polish(self.status_pill)
        self._status_key = key
        self._status_state = state

    # ----------------------------------------------------------- retranslate
    def bidi(self, value) -> str:
        """Keep Latin fragments upright and in order inside Persian sentences."""
        return isolate(value) if self.language == "fa" else str(value)

    def fmt(self, key: str, **values) -> str:
        """Translate and fill a message, isolating embedded paths and numbers."""
        return self.t(key).format(
            **{name: self.bidi(value) for name, value in values.items()}
        )

    def retranslate(self) -> None:
        self.setWindowTitle(f"{self.t('title')}  \u2014  {self.bidi(APP_VERSION)}")
        self.title_label.setText(self.t("title"))
        self.subtitle_label.setText(self.t("subtitle"))
        self.badge_label.setText(self.t("safe_badge"))
        self.theme_button.setText(
            self.t("theme_light") if self.theme == "dark" else self.t("theme_dark")
        )
        self.language_combo.setToolTip(self.t("language"))

        self.chip_found.set_caption(self.t("stat_found"))
        self.chip_copied.set_caption(self.t("stat_copied"))
        self.chip_errors.set_caption(self.t("stat_errors"))
        self.chip_scanned.set_caption(self.t("stat_scanned"))
        self.chip_elapsed.set_caption(self.t("stat_elapsed"))

        self.drive_card.setTitle(self.t("drives_title"))
        self.drive_hint.setText(self.t("drives_hint"))
        self.select_all_btn.setText(self.t("select_all"))
        self.clear_btn.setText(self.t("clear"))
        self.refresh_btn.setText(self.t("refresh"))
        self.removable_check.setText(self.t("removable"))

        self.options_card.setTitle(self.t("options_title"))
        self.options_hint.setText(self.t("options_hint"))
        self.system_check.setText(self.t("include_system"))
        self.links_check.setText(self.t("follow_links"))
        self.safety_label.setText(self.t("safety_note"))

        self.output_card.setTitle(self.t("output_title"))
        self.output_hint.setText(self.t("output_hint"))
        self.paths_radio.setText(self.t("mode_paths"))
        self.copy_radio.setText(self.t("mode_copy"))
        self.txt_label.setText(self.t("txt_file"))
        self.copy_label.setText(self.t("destination"))
        self.txt_browse.setText(self.t("browse"))
        self.copy_browse.setText(self.t("browse"))

        self.start_btn.setText(self.t("start"))
        self.stop_btn.setText(self.t("stop"))

        self.results_card.setTitle(self.t("results_title"))
        self.filter_edit.setPlaceholderText(self.t("filter_placeholder"))
        self.export_csv_btn.setText(self.t("export_csv"))
        self.export_txt_btn.setText(self.t("export_txt"))
        self.open_folder_btn.setText(self.t("open_folder"))
        self.clear_results_btn.setText(self.t("clear_results"))

        self.model.set_headers(
            [
                self.t("col_type"),
                self.t("col_name"),
                self.t("col_size"),
                self.t("col_modified"),
                self.t("col_folder"),
            ],
            {"hidden": self.t("kind_hidden"), "system": self.t("kind_system")},
        )

        self.footer_label.setText(self.fmt("footer", version=APP_VERSION))

        index = self.language_combo.findData(self.language)
        if index >= 0 and index != self.language_combo.currentIndex():
            self.language_combo.blockSignals(True)
            self.language_combo.setCurrentIndex(index)
            self.language_combo.blockSignals(False)

        self.setLayoutDirection(
            Qt.LayoutDirection.RightToLeft
            if self.language == "fa"
            else Qt.LayoutDirection.LeftToRight
        )

        # Keep counters and status text intact when the language changes.
        self.set_status(getattr(self, "_status_key", "ready"), getattr(self, "_status_state", "idle"))
        self.render_stats()
        self.update_rows_label()
        self.refresh_drive_labels()
        self.refresh_column_widths()

    def language_changed(self, index: int) -> None:
        data = self.language_combo.itemData(index)
        self.language = data if data in TEXTS else "en"
        self.settings.setValue("language", self.language)
        self.apply_theme()
        self.retranslate()

    # ---------------------------------------------------------------- drives
    def refresh_drives(self) -> None:
        previous = {
            self.drive_list.item(i).data(Qt.ItemDataRole.UserRole)
            for i in range(self.drive_list.count())
            if self.drive_list.item(i).checkState() == Qt.CheckState.Checked
        }

        self.drive_list.clear()
        for root in list_roots(include_removable=self.removable_check.isChecked()):
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, root.path)
            item.setData(Qt.ItemDataRole.UserRole + 1, root.label)
            item.setData(Qt.ItemDataRole.UserRole + 2, root.total)
            item.setData(Qt.ItemDataRole.UserRole + 3, root.free)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(
                Qt.CheckState.Checked if root.path in previous else Qt.CheckState.Unchecked
            )
            self.drive_list.addItem(item)

        self.refresh_drive_labels()

    def refresh_drive_labels(self) -> None:
        for i in range(self.drive_list.count()):
            item = self.drive_list.item(i)
            path = item.data(Qt.ItemDataRole.UserRole) or ""
            label = item.data(Qt.ItemDataRole.UserRole + 1) or ""
            total = item.data(Qt.ItemDataRole.UserRole + 2) or 0
            free = item.data(Qt.ItemDataRole.UserRole + 3) or 0

            parts = [self.bidi(path)]
            if label:
                parts.append(str(label))
            if total:
                parts.append(
                    self.fmt("drive_free", free=human_size(free), total=human_size(total))
                )
            item.setText("   \u2022   ".join(parts))
            item.setToolTip(path)

    def select_all_drives(self) -> None:
        for i in range(self.drive_list.count()):
            self.drive_list.item(i).setCheckState(Qt.CheckState.Checked)

    def clear_drives(self) -> None:
        for i in range(self.drive_list.count()):
            self.drive_list.item(i).setCheckState(Qt.CheckState.Unchecked)

    def selected_drives(self) -> list:
        drives = []
        for i in range(self.drive_list.count()):
            item = self.drive_list.item(i)
            if item.checkState() == Qt.CheckState.Checked:
                drives.append(item.data(Qt.ItemDataRole.UserRole))
        return drives

    # ------------------------------------------------------------ output mode
    def update_output_mode(self) -> None:
        paths_mode = self.paths_radio.isChecked()
        busy = self.scanner is not None and self.scanner.isRunning()

        self.txt_edit.setEnabled(paths_mode and not busy)
        self.txt_browse.setEnabled(paths_mode and not busy)
        self.txt_label.setEnabled(paths_mode)

        self.copy_edit.setEnabled(not paths_mode and not busy)
        self.copy_browse.setEnabled(not paths_mode and not busy)
        self.copy_label.setEnabled(not paths_mode)

    def choose_txt(self) -> None:
        start_dir = self.txt_edit.text().strip() or os.path.join(
            desktop_dir(), "hidden_files.txt"
        )
        filename, _ = QFileDialog.getSaveFileName(
            self, self.t("txt_file"), start_dir, "Text files (*.txt)"
        )
        if not filename:
            return
        if not filename.lower().endswith(".txt"):
            filename += ".txt"
        self.txt_edit.setText(os.path.normpath(filename))

    def choose_destination(self) -> None:
        start_dir = self.copy_edit.text().strip() or desktop_dir()
        folder = QFileDialog.getExistingDirectory(
            self,
            self.t("destination"),
            start_dir,
            QFileDialog.Option.ShowDirsOnly,
        )
        if folder:
            self.copy_edit.setText(os.path.normpath(folder))

    # ------------------------------------------------------------------ scan
    def set_busy(self, busy: bool) -> None:
        self.start_btn.setEnabled(not busy)
        self.stop_btn.setEnabled(busy)
        self.progress.setVisible(busy)

        for widget in (
            self.drive_list,
            self.select_all_btn,
            self.clear_btn,
            self.refresh_btn,
            self.removable_check,
            self.system_check,
            self.links_check,
            self.paths_radio,
            self.copy_radio,
        ):
            widget.setEnabled(not busy)

        self.update_output_mode()

    def start_scan(self) -> None:
        if self.scanner is not None and self.scanner.isRunning():
            return

        drives = self.selected_drives()
        if not drives:
            self.warn(self.t("msg_select_drive"))
            return

        copy_files = self.copy_radio.isChecked()
        destination = ""
        txt_path = ""

        if copy_files:
            destination = self.copy_edit.text().strip()
            if not destination:
                self.warn(self.t("msg_choose_destination"))
                return
            try:
                Path(destination).mkdir(parents=True, exist_ok=True)
                if not os.access(destination, os.W_OK):
                    raise OSError("destination is not writable")
            except OSError:
                self.warn(self.t("msg_bad_destination"))
                return
            self.last_output_folder = os.path.abspath(destination)
        else:
            txt_path = self.txt_edit.text().strip()
            if not txt_path:
                self.warn(self.t("msg_choose_txt"))
                return
            self.last_output_folder = os.path.dirname(os.path.abspath(txt_path))

        self.model.clear()
        self.stats = {"found": 0, "copied": 0, "errors": 0, "scanned": 0}
        self.truncation_warned = False
        self.render_stats()
        self.update_rows_label()
        self.set_current_path("")

        # The mode is captured here, so changing the radio buttons mid-scan
        # can no longer send the results to the wrong place.
        self.scan_copy_mode = copy_files
        self.scan_started_at = time.monotonic()

        self.scanner = ScannerThread(
            drives,
            include_system=self.system_check.isChecked(),
            follow_links=self.links_check.isChecked(),
            copy_files=copy_files,
            destination=destination,
            txt_path=txt_path,
            parent=self,
        )
        self.scanner.batch_ready.connect(self.on_batch)
        self.scanner.progress.connect(self.on_progress)
        self.scanner.scan_finished.connect(self.on_scan_finished)
        self.scanner.failed.connect(self.on_failed)
        self.scanner.finished.connect(self.on_thread_finished)

        self.set_busy(True)
        self.set_status("scanning", "busy")
        self.elapsed_timer.start()
        self.scanner.start()

    def stop_scan(self) -> None:
        if self.scanner is not None and self.scanner.isRunning():
            self.scanner.stop()
            self.stop_btn.setEnabled(False)
            self.set_status("stopping", "busy")

    def on_batch(self, records) -> None:
        added = self.model.add_records(records)
        if added:
            self.update_rows_label()
        if self.model.truncated and not self.truncation_warned:
            self.truncation_warned = True
            self.current_path_label.setText(
                self.fmt("msg_truncated", limit=f"{MAX_TABLE_ROWS:,}")
            )

    def on_progress(self, info) -> None:
        self.stats.update(
            {
                "found": info.get("found", 0),
                "copied": info.get("copied", 0),
                "errors": info.get("errors", 0),
                "scanned": info.get("scanned", 0),
            }
        )
        self.render_stats()
        if not self.truncation_warned:
            self.set_current_path(info.get("current", ""))

    def set_current_path(self, path: str) -> None:
        self._current_path_full = path or ""
        if not self._current_path_full:
            self.current_path_label.setText("")
            self.current_path_label.setToolTip("")
            return
        metrics = QFontMetrics(self.current_path_label.font())
        width = max(160, self.current_path_label.width() - 12)
        self.current_path_label.setText(
            metrics.elidedText(
                self._current_path_full, Qt.TextElideMode.ElideMiddle, width
            )
        )
        self.current_path_label.setToolTip(self._current_path_full)

    def on_scan_finished(self, summary) -> None:
        self.elapsed_timer.stop()
        self.stats.update(
            {
                "found": summary.get("found", 0),
                "copied": summary.get("copied", 0),
                "errors": summary.get("errors", 0),
                "scanned": summary.get("scanned", 0),
            }
        )
        elapsed = summary.get("elapsed", 0.0)
        self.render_stats(elapsed)
        self.set_busy(False)

        stopped = bool(summary.get("stopped"))
        self.set_status(
            "stopped" if stopped else "completed",
            "done",
            self.fmt(
                "summary",
                found=f"{summary.get('found', 0):,}",
                scanned=f"{summary.get('scanned', 0):,}",
                errors=f"{summary.get('errors', 0):,}",
                elapsed=format_duration(elapsed),
            ),
        )
        self.set_current_path("")

        txt_path = summary.get("txt_path") or ""
        if txt_path:
            self.txt_edit.setText(txt_path)
            self.last_output_folder = os.path.dirname(txt_path)

        messages = []
        if txt_path and summary.get("found"):
            messages.append(self.fmt("msg_saved_txt", path=txt_path))
        if summary.get("copied"):
            messages.append(
                self.fmt(
                    "msg_copied",
                    copied=f"{summary.get('copied', 0):,}",
                    destination=summary.get("destination", ""),
                )
            )
        if not summary.get("found") and not stopped:
            messages.append(self.t("msg_no_results"))
        if self.model.truncated:
            messages.append(self.fmt("msg_truncated", limit=f"{MAX_TABLE_ROWS:,}"))

        if messages:
            self.inform("\n\n".join(messages))

    def on_failed(self, message: str) -> None:
        self.elapsed_timer.stop()
        self.set_busy(False)
        self.set_status("error", "error")
        QMessageBox.critical(self, self.t("title"), message)

    def on_thread_finished(self) -> None:
        thread, self.scanner = self.scanner, None
        if thread is not None:
            thread.deleteLater()
        self.set_busy(False)
        self.update_output_mode()

    # --------------------------------------------------------------- display
    def render_stats(self, elapsed=None) -> None:
        self.chip_found.set_value(f"{self.stats['found']:,}")
        self.chip_copied.set_value(f"{self.stats['copied']:,}")
        self.chip_errors.set_value(f"{self.stats['errors']:,}")
        self.chip_scanned.set_value(f"{self.stats['scanned']:,}")
        if elapsed is None:
            elapsed = (
                time.monotonic() - self.scan_started_at if self.scan_started_at else 0.0
            )
        self.chip_elapsed.set_value(format_duration(elapsed))

    def update_elapsed(self) -> None:
        self.render_stats()

    def update_rows_label(self) -> None:
        self.rows_label.setText(
            self.fmt(
                "rows_shown",
                shown=f"{self.proxy.rowCount():,}",
                total=f"{self.model.rowCount():,}",
            )
        )

    def filter_changed(self, text: str) -> None:
        self.proxy.set_needle(text)
        self.update_rows_label()

    def clear_results(self) -> None:
        self.model.clear()
        self.truncation_warned = False
        self.update_rows_label()

    # ---------------------------------------------------------------- export
    def export_csv(self) -> None:
        records = self.model.records()
        if not records:
            self.inform(self.t("msg_nothing_export"))
            return

        filename, _ = QFileDialog.getSaveFileName(
            self,
            self.t("export_csv"),
            os.path.join(desktop_dir(), "hidden_files.csv"),
            "CSV files (*.csv)",
        )
        if not filename:
            return
        if not filename.lower().endswith(".csv"):
            filename += ".csv"

        output = unique_path(filename)
        try:
            with open(
                long_path(str(output)), "w", newline="", encoding="utf-8-sig"
            ) as handle:
                writer = csv.writer(handle)
                writer.writerow(
                    [
                        self.t("col_type"),
                        self.t("col_name"),
                        "Path",
                        self.t("col_size"),
                        self.t("col_modified"),
                    ]
                )
                for record in records:
                    writer.writerow(
                        [
                            self.t("kind_system") if record.is_system else self.t("kind_hidden"),
                            record.name,
                            record.path,
                            record.size,
                            format_timestamp(record.mtime),
                        ]
                    )
        except OSError as exc:
            QMessageBox.critical(self, self.t("title"), str(exc))
            return

        self.last_output_folder = str(Path(output).parent)
        self.inform(self.fmt("msg_exported", path=str(output)))

    def export_txt(self) -> None:
        records = self.model.records()
        if not records:
            self.inform(self.t("msg_nothing_export"))
            return

        filename, _ = QFileDialog.getSaveFileName(
            self,
            self.t("export_txt"),
            os.path.join(desktop_dir(), "hidden_files.txt"),
            "Text files (*.txt)",
        )
        if not filename:
            return
        if not filename.lower().endswith(".txt"):
            filename += ".txt"

        output = unique_path(filename)
        try:
            with open(
                long_path(str(output)), "w", encoding="utf-8", newline="\n"
            ) as handle:
                for record in records:
                    handle.write(record.path + "\n")
        except OSError as exc:
            QMessageBox.critical(self, self.t("title"), str(exc))
            return

        self.last_output_folder = str(Path(output).parent)
        self.inform(self.fmt("msg_exported", path=str(output)))

    def open_output_folder(self) -> None:
        folder = self.last_output_folder
        if not folder or not os.path.isdir(folder):
            self.inform(self.t("msg_no_output"))
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(folder))

    # ------------------------------------------------------------ table menu
    def selected_records(self) -> list:
        records = []
        for index in self.table.selectionModel().selectedRows():
            source = self.proxy.mapToSource(index)
            record = self.model.record(source.row())
            if record is not None:
                records.append(record)
        return records

    def show_table_menu(self, position) -> None:
        records = self.selected_records()
        if not records:
            return

        menu = QMenu(self)
        copy_path = menu.addAction(self.t("ctx_copy_path"))
        copy_folder = menu.addAction(self.t("ctx_copy_folder"))
        menu.addSeparator()
        open_folder = menu.addAction(self.t("ctx_open_folder"))

        chosen = menu.exec(self.table.viewport().mapToGlobal(position))
        if chosen is None:
            return

        clipboard = QGuiApplication.clipboard()
        if chosen == copy_path:
            clipboard.setText("\n".join(r.path for r in records))
        elif chosen == copy_folder:
            clipboard.setText("\n".join(dict.fromkeys(r.folder for r in records)))
        elif chosen == open_folder:
            folder = records[0].folder
            if os.path.isdir(folder):
                QDesktopServices.openUrl(QUrl.fromLocalFile(folder))

    def open_row_folder(self, index) -> None:
        source = self.proxy.mapToSource(index)
        record = self.model.record(source.row())
        if record and os.path.isdir(record.folder):
            QDesktopServices.openUrl(QUrl.fromLocalFile(record.folder))

    # -------------------------------------------------------------- messages
    def warn(self, message: str) -> None:
        QMessageBox.warning(self, self.t("title"), message)

    def inform(self, message: str) -> None:
        QMessageBox.information(self, self.t("title"), message)

    # ----------------------------------------------------------- preferences
    @staticmethod
    def to_bool(value, default: bool = False) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return default
        return str(value).strip().lower() in ("1", "true", "yes", "on")

    def restore_preferences(self) -> None:
        geometry = self.settings.value("geometry")
        if isinstance(geometry, (QByteArray, bytes, bytearray)):
            try:
                self.restoreGeometry(geometry)
            except (TypeError, ValueError):
                pass

        self.system_check.setChecked(self.to_bool(self.settings.value("include_system"), False))
        self.links_check.setChecked(self.to_bool(self.settings.value("follow_links"), False))
        self.removable_check.blockSignals(True)
        self.removable_check.setChecked(self.to_bool(self.settings.value("removable"), False))
        self.removable_check.blockSignals(False)

        txt_path = self.settings.value("txt_path", "")
        if isinstance(txt_path, str):
            self.txt_edit.setText(txt_path)
        destination = self.settings.value("destination", "")
        if isinstance(destination, str):
            self.copy_edit.setText(destination)

        if self.to_bool(self.settings.value("copy_mode"), False):
            self.copy_radio.setChecked(True)
        else:
            self.paths_radio.setChecked(True)

    def save_preferences(self) -> None:
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("language", self.language)
        self.settings.setValue("theme", self.theme)
        self.settings.setValue("include_system", self.system_check.isChecked())
        self.settings.setValue("follow_links", self.links_check.isChecked())
        self.settings.setValue("removable", self.removable_check.isChecked())
        self.settings.setValue("copy_mode", self.copy_radio.isChecked())
        self.settings.setValue("txt_path", self.txt_edit.text().strip())
        self.settings.setValue("destination", self.copy_edit.text().strip())
        self.settings.sync()

    # ------------------------------------------------------------ life cycle
    def resizeEvent(self, event):
        super().resizeEvent(event)
        # Re-elide from the original path: re-eliding elided text loses the middle.
        self.set_current_path(self._current_path_full)

    def closeEvent(self, event):
        scanner = self.scanner
        if scanner is not None and scanner.isRunning():
            answer = QMessageBox.question(
                self,
                self.t("msg_running_title"),
                self.t("msg_running_close"),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return

            scanner.stop()
            if not scanner.wait(4000):
                # Last resort: never leave a running QThread behind on exit.
                scanner.terminate()
                scanner.wait(1500)

        self.elapsed_timer.stop()
        self.save_preferences()
        event.accept()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    silence_os_error_dialogs()

    # Keep the real fractional scale factor so text stays sharp at 125%/150%.
    try:
        QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
        )
    except Exception:  # noqa: BLE001 - older Qt builds simply ignore this
        pass

    app = QApplication(sys.argv)
    try:
        # Fusion honours stylesheet metrics, so labels are not clipped.
        app.setStyle("Fusion")
    except Exception:  # noqa: BLE001 - fall back to the platform style
        pass
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName(ORG_NAME)
    app.setWindowIcon(build_app_icon())

    window = HiddenFileHunter()
    window.show()

    if not IS_WINDOWS:
        QMessageBox.information(
            window,
            APP_NAME,
            "Windows hidden/system attributes are only available on Windows.\n"
            "On this system, files starting with a dot are treated as hidden.",
        )

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
