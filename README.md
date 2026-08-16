# Hidden File Hunter

A desktop app that hunts down **hidden and system files** across your drives, then
either saves the full list to a TXT file or copies the files into a folder of your
choice. It is read-only by design: files are only read or copied, never changed or
deleted.

Built with Python and PySide6 (Qt 6). Version 2.0.

## Features

- **Drive picker** - scan any combination of drives; removable and network drives are optional.
- **Scan options** - hidden files are always included; system files and junction/symlink following are opt-in.
- **Two output modes** - stream every path into a TXT file while scanning, or copy the discovered
  files into a destination folder (the original folder structure is mirrored, name clashes get a suffix).
- **Live feedback** - found / copied / errors / scanned counters, elapsed timer, progress bar and the
  path currently being scanned.
- **Results table** - type, name, size, modified date and folder, with instant filtering,
  CSV/TXT export and a right-click menu to copy the path or open the containing folder.
- **Safe and resilient** - long path support, unreadable folders are counted instead of crashing the
  scan, OS error dialogs are suppressed, and a scan can be stopped at any moment.
- **Themes and languages** - dark and light themes, English and Persian (full right-to-left layout).
- **Remembers your setup** - window size, theme, language, options and paths are restored on next launch.

The table renders up to 250,000 rows to stay responsive; the TXT list and the file copy
output always contain every match.

## Keyboard shortcuts

| Shortcut | Action |
| --- | --- |
| `Ctrl` + `Enter` | Start scan |
| `Esc` | Stop scan |
| `F5` | Refresh drive list |
| `Ctrl` + `F` | Jump to the results filter |
| `Ctrl` + `S` | Export results to CSV |

## Requirements

- Python 3.9 or newer
- PySide6

## Run from source

Windows:

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

## Build a standalone Windows executable

```bat
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed --name HiddenFileHunter main.py
```

The result is `dist/HiddenFileHunter.exe`. Pushing a tag such as `v2.0` also builds it on
GitHub Actions (see `.github/workflows/build-windows.yml`).

## Platform notes

On Windows the real NTFS attributes are read through `kernel32`, so both *hidden* and
*system* files are detected. On macOS and Linux the app falls back to dot-files plus the
`UF_HIDDEN` flag.

## License

MIT - see [LICENSE](LICENSE).

---

## فارسی

**Hidden File Hunter** برنامه‌ای گرافیکی برای پیدا کردن فایل‌های مخفی و سیستمی در درایوهاست.
نتیجه را می‌توانی در یک فایل TXT ذخیره کنی یا فایل‌های پیداشده را در پوشه‌ای دلخواه کپی کنی.
برنامه هیچ فایلی را تغییر نمی‌دهد و حذف نمی‌کند؛ فقط می‌خواند و کپی می‌کند.

- انتخاب دلخواه درایوها، همراه با گزینهٔ درایوهای جداشدنی
- گزینهٔ افزودن فایل‌های سیستمی و دنبال‌کردن جانکشن‌ها و سیم‌لینک‌ها
- شمارندهٔ زندهٔ پیدا‌شده / کپی‌شده / خطاها / بررسی‌شده و زمان سپری‌شده
- جدول نتایج با فیلتر فوری، خروجی CSV و TXT و منوی راست‌کلیک برای باز کردن پوشهٔ فایل
- تم تیره و روشن، زبان انگلیسی و فارسی با چیدمان راست‌به‌چپ

اجرا: `pip install -r requirements.txt` و بعد `python main.py`
