#!/usr/bin/env python3
"""
bakhunt - backup file and source leak hunter

Finds exposed backups, archives, database dumps and source-code leaks on web
hosts, with aggressive false-positive filtering:

  * soft-404 calibration   - fingerprints how each host answers for files that
                             do not exist, then discards anything matching it
  * magic byte validation  - inspects the first bytes of the response instead
                             of trusting Content-Type
  * ranged requests        - downloads only the first 2 KB of any candidate

Standard library only. No installation required.
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
import random
import re
import ssl
import string
import shutil
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

NAME = "lucille"
VERSION = "1.6"
UA = "Mozilla/5.0 (X11; Linux x86_64) %s/%s" % (NAME, VERSION)
PROBE_BYTES = 2048

# A host answering every path with the same page yields a wall of identical
# findings. These control when that wall is recognised and dropped.
CATCHALL_MIN = 12       # findings on one host before the guard even runs
CATCHALL_RATIO = 0.8    # share of them that must share a size to drop them all

# ------------------------------------------------------------------ extensions

# Tier 1: most common. Use this for scans across 1000+ hosts.
EXT_QUICK = [
    "zip", "tar.gz", "sql", "bak", "old", "rar", "7z", "tgz",
    "tar", "gz", "sql.gz", "backup",
]

# Tier 2: reasonable coverage. Suitable for a few hundred hosts.
EXT_NORMAL = EXT_QUICK + [
    "tar.bz2", "tar.xz", "bz2", "xz", "zst", "tar.zst", "lz4", "z",
    "sql.zip", "sql.bz2", "sql.xz", "dump", "dmp", "db", "sqlite",
    "sqlite3", "mdb", "bkp", "bk", "orig", "save", "copy", "tmp",
    "temp", "swp", "new", "prev", "war", "jar", "cab", "iso",
]

# Tier 3: everything. Only for a small hand-picked host list.
EXT_FULL = EXT_NORMAL + [
    "tbz", "tbz2", "txz", "tar.z", "tar.lz", "tar.lz4", "tar.lzma",
    "lz", "lzma", "arj", "ace", "alz", "egg", "pak", "pea", "s7z",
    "zipx", "sit", "sitx", "cpio", "shar", "lzo", "rz", "sz", "zpaq",
    "ear", "apk", "aar", "nupkg", "whl", "gem", "deb", "rpm",
    "bacpac", "myd", "frm", "ibd", "accdb", "mdf", "ldf", "ndf",
    "backup1", "back", "bac", "saved", "previous", "older", "last",
    "swo", "swn", "rej", "part", "partial", "inprogress",
    "0", "1", "2", "3", "_bak", "-bak", "bak2", "bakup",
    "conf", "config", "ini", "inc", "log", "txt", "csv", "json", "xml",
    "vhd", "vmdk", "ova", "img", "dd", "e01",
]

# Fixed paths that do not follow the base.ext pattern.
FIXED_PATHS = [
    ".git/HEAD", ".git/config", ".git/index", ".gitignore",
    ".env", ".env.bak", ".env.old", ".env.local", ".env.production",
    ".DS_Store", ".svn/entries", ".hg/store",
    "web.config", "composer.json", "package.json", "yarn.lock",
    ".htpasswd", "id_rsa", "id_dsa", ".bash_history", ".npmrc",
    "wp-config.php.bak", "wp-config.php.old", "wp-config.php~",
]

# Source-file backups: filename + suffix combinations.
SOURCE_FILES = [
    "index.php", "config.php", "configuration.php", "settings.php",
    "database.php", "db.php", "connect.php", "wp-config.php",
    "index.html", "index.asp", "index.aspx", "index.jsp",
    "app.py", "settings.py", "config.py", "manage.py",
    "config.js", "app.js", "server.js", "config.json",
    "web.config", "application.properties", "docker-compose.yml",
]
SOURCE_SUFFIXES = ["~", ".bak", ".old", ".orig", ".save", ".txt", ".inc", ".1", ".swp"]

# Generic bases tried in addition to hostname-derived ones.
# Generic bases, tried with every extension, so each entry costs one
# request per extension per host. Kept to names a site archive is really
# dumped under; content words like "musteri" or "fatura" name data, not
# files, and never paid for themselves.
COMMON_BASES_EN = [
    "backup", "backups", "bak", "db", "database", "dump", "www",
    "site", "web", "public_html", "htdocs", "old", "archive", "dist",
]

# Turkish names, written the way they actually appear in filenames: ASCII
# transliterations, since s/g/i/o/u with diacritics need percent-encoding in a
# URL and almost nobody does that. Disabled with --no-tr.
# Turkish equivalents, seen on shared hosting. Dropped with --no-tr.
COMMON_BASES_TR = [
    "yedek", "yedekler", "yedekleme", "sonyedek", "tamyedek",
    "arsiv", "eski", "veritabani",
]

COMMON_BASES = COMMON_BASES_EN + COMMON_BASES_TR

# ------------------------------------------------------------------ signatures

# (magic bytes, offset, label)
SIGNATURES = [
    (b"PK\x03\x04", 0, "zip"),
    (b"PK\x05\x06", 0, "zip-empty"),
    (b"\x1f\x8b", 0, "gzip"),
    (b"\x1f\x9d", 0, "compress-Z"),
    (b"Rar!\x1a\x07", 0, "rar"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7z"),
    (b"BZh", 0, "bzip2"),
    (b"\xfd7zXZ\x00", 0, "xz"),
    (b"\x28\xb5\x2f\xfd", 0, "zstd"),
    (b"\x04\x22\x4d\x18", 0, "lz4"),
    (b"\x60\xea", 0, "arj"),
    (b"MSCF", 0, "cab"),
    (b"ALZ\x01", 0, "alz"),
    (b"EGGA", 0, "egg"),
    (b"**ACE**", 7, "ace"),
    (b"SQLite format 3", 0, "sqlite"),
    (b"\x00\x01\x00\x00Standard Jet DB", 0, "ms-access"),
    (b"\x00\x01\x00\x00Standard ACE DB", 0, "ms-access"),
    (b"ustar", 257, "tar"),
    (b"\x00\x00\x00\x01Bud1", 0, "ds_store"),
    (b"DIRC", 0, "git-index"),
    (b"conectix", 0, "vhd"),
    (b"KDMV", 0, "vmdk"),
]

# Text-based signatures: (pattern, label)
TEXT_SIGNATURES = [
    (re.compile(rb"^ref:\s+refs/"), "git-head"),
    (re.compile(rb"\[core\]", re.I), "git-config"),
    (re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private-key"),
    (re.compile(rb"^\s*<\?php", re.M), "php-source"),
    (re.compile(rb"^\s*<%[@!]?", re.M), "asp-jsp-source"),
    (re.compile(rb"^#!/(bin|usr)/"), "script-source"),
    (re.compile(rb"(CREATE TABLE|INSERT INTO|MySQL dump|PostgreSQL database dump)", re.I), "sql-dump"),
    (re.compile(rb"(DB_PASSWORD|DATABASE_URL|SECRET_KEY|AWS_SECRET|API_KEY)\s*=", re.I), "credentials"),
    (re.compile(rb"AKIA[0-9A-Z]{16}"), "aws-key"),
    (re.compile(rb"^\s*[A-Z][A-Z0-9_]{2,}\s*=", re.M), "env-file"),
    (re.compile(rb"<configuration", re.I), "web-config"),
    (re.compile(rb"^\s*\{\s*\"(name|dependencies|scripts)\"", re.M), "package-json"),
]

# Vowels for abbreviation generation (English + Turkish).
VOWELS = set("aeiouıöüâîûáéíóú")

# Meaningless as a filename base (TLDs and generic fragments).
SKIP_BASES = {
    "com", "net", "org", "gov", "edu", "mil", "int", "info", "biz",
    "io", "co", "app", "dev", "cloud", "tech", "online", "site",
    "com.tr", "gov.tr", "edu.tr", "org.tr", "net.tr", "co.uk",
    "www", "http", "https",
}

# Placeholder replaced with a fresh session id per host, for rotating-proxy
# providers that pin one exit IP per session (Bright Data, Oxylabs, ...).
SESSION_TOKEN = "{SESSION}"

# Turkish help, shown with -tr / --tr / --help-tr. Intercepted before argparse
# because "-tr" would otherwise be parsed as "-t r".
HELP_TR = """
bakhunt - yedek dosya ve kaynak sızıntısı avcısı

KULLANIM
  python3 lucille -l HEDEFLER [seçenekler]

EN BASİT KULLANIM
  python3 lucille -l live.txt --ext full -r 20 -o hits.jsonl

    -l     hedef listesi (httpx çıktısı veya düz hostname listesi)
    --ext full  her şeye bak
    -r     saniyedeki toplam istek
    -o     sonuçların yazılacağı dosya

ZORUNLU
  -l, --list DOSYA      Hedef listesi. httpx çıktısını da düz hostname
                        listesini de kabul eder. # ile başlayan satırları
                        atlar.

ÇIKTI
  -o, --output DOSYA    Sonuç dosyası (JSONL). Varsayılan: hits.jsonl
  --all                 Düşük güvenli bulguları da yaz (gürültülü)
  -s, --silent          Banner'ı gizle

NE ARANACAK
  --ext full            HER ŞEY: 120 uzantı + kaynak yedekleri.
                        Host başına ~11290 yol. Kısa listede kullan.
  --ext quick           12 uzantı (varsayılan)
  --ext normal          43 uzantı
  --ext full            120 uzantı + kaynak yedekleri (her şey)
  --source              Kaynak dosya yedekleri (full ve max zaten içerir)
  --no-derive           Hostname'den isim üretmeyi kapat
  --no-common           Genel isimleri kapat (backup, db, www, htdocs...)
  -p, --paths DOSYA     Kendi yol listen. Verirsen yukarıdakiler devre dışı.
  --max-per-host N      Host başına istek tavanı (0 = sınırsız)

  Not: --no-derive --no-common birlikte verilirse geriye sadece 24 sabit yol
  kalır (.git/HEAD, .env, .htpasswd, id_rsa...). En hızlı ve en yüksek
  isabetli tarama budur.

HIZ
  -r, --rate N          TOPLAM saniyedeki istek (host başına değil).
                        Proxy yoksa 20, proxy varsa 50 önerilir.
  -t, --threads N       Aynı anda taranacak host sayısı (varsayılan 10)
  --timeout N           İstek zaman aşımı, saniye (varsayılan 8)

  Not: -r bir tavan, -t paralellik. -r 20 -t 100 dersen 100 thread açılır
  ama hepsi sırada bekler, hız yine 20 kalır.

PROXY
  --proxy ADRES         Tek proxy.
                        Örnek: http://kullanici:sifre@1.2.3.4:8080
                        Döngüsel (rotating) sağlayıcılarda kullanıcı adına
                        {SESSION} koy; her host'a ayrı sticky oturum açılır:
                        http://customer-AD-sessid-{SESSION}:SIFRE@host:7777
  --proxy-file DOSYA    Her satırda bir proxy. Host başına biri seçilir ve
                        o host'un tüm taraması boyunca sabit kalır.

  Not: SOCKS desteklenmiyor, araç uyarıp atlar. HTTP proxy kullan.

DEVAM ETME
  --state DOSYA         Durum dosyası (varsayılan: <çıktı>.state)
  --restart             Durum dosyasını yoksay, baştan başla

  Ctrl+C güvenlidir. Biten her host durum dosyasına yazılır, aynı komutu
  tekrar çalıştırınca kaldığı yerden devam eder.

KONTROL
  --dry-run             İstek atma, üretilecek yolları ekrana bas
  --list-ext -tr        Tüm uzantıları, gövdeleri ve sabit yolları listele
  -h, --help            İngilizce yardım
  -tr                   Bu Türkçe yardım

ÇIKTIYI OKUMA
  [HIGH]   magic byte doğrulandı, gerçek dosya -> buna bak
  [MEDIUM] content-type uygun ama imza tanınmadı -> elle kontrol et
  [LOW]    zayıf sinyal, --all olmadan yazılmaz

  Sadece HIGH olanları görmek için:
    grep high hits.jsonl

ÖRNEKLER
  # geniş tarama, en yüksek isabet, host başına ~27 istek
  python3 lucille -l live.txt --no-derive --no-common -r 20 -o stage1.jsonl

  # her şey, kısa ve elle seçilmiş listede, host başına ~4930 istek
  python3 lucille -l shortlist.txt --ext full -r 20 -o stage2.jsonl

  # proxy ile
  python3 lucille -l live.txt --ext full -r 50 \\
    --proxy 'http://customer-AD-sessid-{SESSION}:SIFRE@pr.oxylabs.io:7777' \\
    -o hits.jsonl

  # istek atmadan ne deneneceğini gör
  python3 lucille -l live.txt --ext full --dry-run | head -50
"""

# Set on Ctrl+C so worker threads wind down.
STOP = threading.Event()
# Set when the scan finishes, to stop the status-line thread.
DONE = threading.Event()

# ANSI colours, blanked out when the output is not a terminal.
C = {
    "reset": "\033[0m", "dim": "\033[2m", "bold": "\033[1m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    "grey": "\033[90m",
}
NO_COLOR = {k: "" for k in C}


ANSI_RE = re.compile('\x1b\\[[0-9;]*m')


def terminal_width(default=100):
    """Usable width of the terminal, with a sane fallback when unknown."""
    try:
        w = shutil.get_terminal_size((default, 24)).columns
    except Exception:
        w = default
    return max(20, w - 1)   # one spare column: some terminals wrap early


def _fit(line, width):
    """Truncate a line to `width` visible characters, keeping colour codes."""
    if len(ANSI_RE.sub("", line)) <= width:
        return line
    out, visible, i = [], 0, 0
    while i < len(line) and visible < width:
        m = ANSI_RE.match(line, i)
        if m:                   # escape sequence: kept, but costs no column
            out.append(m.group())
            i = m.end()
            continue
        out.append(line[i])
        visible += 1
        i += 1
    return "".join(out) + '\x1b[0m'


class Console:
    """Prints permanent lines above a single in-place status line."""

    def __init__(self, color=True):
        self.c = C if color else NO_COLOR
        self.lock = threading.Lock()
        self._status_lines = 0

    def _erase(self):
        # Erase the whole in-place status block (one or more lines) and leave
        # the cursor at the top-left of where it was.
        n = self._status_lines
        if n:
            sys.stderr.write("\r\033[K")            # clear the current line
            for _ in range(n - 1):
                sys.stderr.write("\033[A\r\033[K")  # up one, clear
            self._status_lines = 0

    def out(self, text):
        """A permanent line on stdout (findings)."""
        with self.lock:
            self._erase()
            sys.stdout.write(text + "\n")
            sys.stdout.flush()

    def info(self, text):
        """A permanent line on stderr (progress, notices)."""
        with self.lock:
            self._erase()
            sys.stderr.write(text + "\n")
            sys.stderr.flush()

    def status(self, lines):
        """Redraw the live status block in place. Accepts a str or a list."""
        if not sys.stderr.isatty():
            return
        if isinstance(lines, str):
            lines = [lines]
        width = terminal_width()
        # Cut each line to the terminal width so it never wraps onto a second
        # row (the erase below counts rows, not logical lines), and follow it
        # with an erase-to-end so a shorter redraw cannot leave the tail of
        # the previous one behind.
        lines = [_fit(l, width) + '\x1b[K' for l in lines]
        with self.lock:
            self._erase()
            sys.stderr.write("\n".join(lines))
            sys.stderr.flush()
            self._status_lines = len(lines)

    def clear(self):
        with self.lock:
            self._erase()


def _encodable(text, stream):
    """True if this stream can actually render these characters."""
    try:
        text.encode(stream.encoding or "ascii")
        return True
    except (UnicodeEncodeError, LookupError, AttributeError):
        return False


# Box-drawing characters, with an ASCII fallback for non-UTF-8 terminals.
if _encodable("┌─│", sys.stdout):
    BOX = {"tl": "┌", "tr": "┐", "bl": "└", "br": "┘",
           "h": "─", "v": "│"}
else:
    BOX = {"tl": "+", "tr": "+", "bl": "+", "br": "+", "h": "-", "v": "|"}


# ------------------------------------------------------------- banner
# Lucille: the name in the Bloody figlet font, and the bat itself lying
# under it, barbed wire round the barrel and blood running off the barbs.
# Everything is plain data so the tool keeps zero dependencies; colours
# are 24-bit where the terminal says it can (COLORTERM), 256 otherwise.

# key -> (r, g, b, 256-colour fallback)
_ART_PAL = {
    '1': (255, 31, 31, 196),
    '2': (224, 0, 0, 160),
    '3': (179, 0, 0, 124),
    '4': (133, 0, 0, 88),
    '5': (86, 0, 0, 52),
    'h': (185, 112, 63, 130),
    'w': (154, 80, 40, 130),
    'd': (122, 60, 27, 94),
    'H': (156, 90, 52, 130),
    'W': (114, 56, 25, 94),
    'D': (69, 32, 13, 52),
    'k': (138, 72, 36, 94),
    'K': (74, 36, 16, 52),
    'G': (180, 180, 180, 250),
    'g': (124, 124, 124, 244),
    's': (80, 80, 80, 239),
    'R': (212, 0, 0, 160),
    'r': (156, 0, 0, 124),
    'q': (100, 0, 0, 88),
    't': (138, 138, 138, 245),
}

_ART_TEXT = [
    '   ██▓     █    ██  ▄████▄   ██▓ ██▓     ██▓    ▓█████ ',
    '  ▓██▒     ██  ▓██▒▒██▀ ▀█  ▓██▒▓██▒    ▓██▒    ▓█   ▀ ',
    '  ▒██░    ▓██  ▒██░▒▓█    ▄ ▒██▒▒██░    ▒██░    ▒███   ',
    '  ▒██░    ▓▓█  ░██░▒▓▓▄ ▄██▒░██░▒██░    ▒██░    ▒▓█  ▄ ',
    '  ░██████▒▒▒█████▓ ▒ ▓███▀ ░░██░░██████▒░██████▒░▒████▒',
    '  ░ ▒░▓  ░░▒▓▒ ▒ ▒ ░ ░▒ ▒  ░░▓  ░ ▒░▓  ░░ ▒░▓  ░░░ ▒░ ░',
    '  ░ ░ ▒  ░░░▒░ ░ ░   ░  ▒    ▒ ░░ ░ ▒  ░░ ░ ▒  ░ ░ ░  ░',
    '    ░ ░    ░░░ ░ ░ ░         ▒ ░  ░ ░     ░ ░      ░   ',
    '      ░  ░   ░     ░ ░       ░      ░  ░    ░  ░   ░  ░',
    '                   ░                                   ',
]
# one shade per text row: bright blood on top, darker as it drips
_ART_TEXT_SHADE = '1122344555'

# the bat: glyph rows, plus a foreground and a background key per cell
_ART_BAT = [
    "                                  '   *    '   *     '  *",
    ' ▗▄▖                         ▄▄▄▄x▄▄▄▄x▄▄▄x▄▄▄▄x▄▄▄▄x▄▄▄x▖',
    ' ███▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄████████████╳█╱██╱█╳█╱█▓╱█╳▓╱█▓╱█╳▓╱▓',
    ' ███▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀███████╳█╱██╱█╳█▓██╱█▓█╱█▓╱█▓█▓█▓',
    ' ▝▀▘                            ▀▀x▀▀▀▀x▀▀▀▀x▀▀▀▀▀▀▀▀▀▀▀▀▘',
    '                                  ,    *   ,  ▌ ▌ ▌  ▌ ▌',
    '                                              ▘   ▌  ▘',
    '                                                  ▘',
]
_ART_BAT_FG = [
    '                                  g   g    g   g     g  g',
    ' kkk                         HHHHGHHHHGHHHGHHHHGHRHHGRHRGH',
    ' kkkhhhhhhhhhhhhhhhhhhhhhWWWWWWWWGWGWWGWGWGWRGWGRGWRGWGRGR',
    ' KKKdddddddddddddddddddddDDDDDDDgDgDDgDgDrDDgDrDgDrgDrDrDr',
    ' KKK                            DDgDDDDgDDDDgDRDRDRDDRDRDD',
    '                                  s    s   s  r r r  r r',
    '                                              q   r  q',
    '                                                  q',
]
_ART_BAT_BG = [
    '                                                         ',
    '                                                          ',
    '                                 W W  W W W WW WWW WW WWWW',
    '                                D D  D D D  D D D DD D D D',
    '                                                          ',
    '                                                        ',
    '                                                      ',
    '                                                   ',
]

# for terminals that cannot draw block characters
_ART_ASCII = str.maketrans({
    "█": "#", "▓": "#", "▒": "+", "░": ".", "▄": "_", "▀": "'",
    "▗": ".", "▖": ".", "▝": "'", "▘": "'", "▌": "|",
    "╳": "x", "╱": "/",
})


def _truecolor():
    """True when the terminal can show 24-bit colour.

    COLORTERM is the standard signal, but plenty of terminals that do support
    it never set the variable, so the known ones are recognised by their own
    environment markers. Anything else gets the 256-colour fallback.
    """
    env = os.environ
    if env.get("COLORTERM", "").lower() in ("truecolor", "24bit"):
        return True
    if any(env.get(v) for v in ("WT_SESSION", "VTE_VERSION", "KONSOLE_VERSION",
                                "KITTY_WINDOW_ID", "ALACRITTY_SOCKET")):
        return True
    return env.get("TERM_PROGRAM", "") in ("iTerm.app", "WezTerm", "vscode")


def _paint(key, ground, true):
    """Escape for palette key `key`; ground 38 = foreground, 48 = background."""
    r, g, b, idx = _ART_PAL[key]
    if true:
        return "\033[%d;2;%d;%d;%dm" % (ground, r, g, b)
    return "\033[%d;5;%dm" % (ground, idx)


def _art_row(glyphs, fg, bg, color, true):
    """One row of the art, coloured cell by cell."""
    if not color:
        return glyphs
    fg, bg = fg.ljust(len(glyphs)), bg.ljust(len(glyphs))
    out, cur = [], None
    for ch, f, b in zip(glyphs, fg, bg):
        if ch == " " and b == " ":
            if cur is not None:
                out.append("\033[0m")
                cur = None
            out.append(" ")
            continue
        if (f, b) != cur:
            out.append("\033[0m" + _paint(f, 38, true))
            if b != " ":
                out.append(_paint(b, 48, true))
            cur = (f, b)
        out.append(ch)
    if cur is not None:
        out.append("\033[0m")
    return "".join(out)


def banner(color=True, stream=None):
    """The startup banner: the name, the bat, and what came off it."""
    stream = stream or sys.stderr
    true = color and _truecolor()
    rows = [""]
    for i, line in enumerate(_ART_TEXT):
        shade = _ART_TEXT_SHADE[min(i, len(_ART_TEXT_SHADE) - 1)]
        rows.append(_art_row(line, shade * len(line), "", color, true))
    rows.append("")
    for glyphs, fg, bg in zip(_ART_BAT, _ART_BAT_FG, _ART_BAT_BG):
        rows.append(_art_row(glyphs, fg, bg, color, true))
    tag = "          backup & source leak hunter"
    rows.append(_art_row(tag, "t" * len(tag), "", color, true))
    rows.append("")
    text = "\n".join(rows)
    if not _encodable("█▓░▄╳", stream):
        text = text.translate(_ART_ASCII)
    return text


UNITS = ("B", "KB", "MB", "GB", "TB", "PB")


def human_size(n):
    """1234567 -> '1.2 MB'. Falls back to '?' for a missing Content-Length."""
    try:
        n = float(int(n))
    except (TypeError, ValueError):
        return "?"
    if n < 0:
        return "?"
    for i, unit in enumerate(UNITS):
        if n < 1024 or i == len(UNITS) - 1:
            return "%d %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0
    return "?"


def render_hit(console, rec, bell=True):
    """A loud green box for HIGH hits, a single line for the rest."""
    c = console.c
    size = human_size(rec.get("content_length"))
    if rec["confidence"] != "high":
        console.out("%s[%s]%s %s  %s(%s, %s)%s" % (
            c["yellow"], rec["confidence"].upper(), c["reset"], rec["url"],
            c["grey"], rec["type"], size, c["reset"]))
        return

    rows = [
        "FOUND  %s" % rec["type"].upper(),
        rec["url"],
        "%s   %s   HTTP %s" % (size, rec.get("content_type") or "?", rec["status"]),
    ]
    width = min(max(len(r) for r in rows) + 2, 100)
    g, b, r0 = c["green"], c["bold"], c["reset"]
    bar = BOX["h"] * width
    console.out("")
    console.out("%s%s%s%s%s%s" % (g, b, BOX["tl"], bar, BOX["tr"], r0))
    for i, row in enumerate(rows):
        style = b if i < 2 else c["grey"]
        console.out("%s%s%s%s %s%-*s%s %s%s%s%s" % (
            g, b, BOX["v"], r0, style, width - 2, row[:width - 2], r0,
            g, b, BOX["v"], r0))
    console.out("%s%s%s%s%s%s" % (g, b, BOX["bl"], bar, BOX["br"], r0))
    console.out("")
    if bell:
        sys.stderr.write("\a")
        sys.stderr.flush()


class Stats:
    """Shared counters the status line reads from."""

    def __init__(self, total_hosts, total_requests=0):
        self.lock = threading.Lock()
        self.total_hosts = total_hosts
        self.total_requests = total_requests
        self.requests = 0
        self.hosts_done = 0
        self.hits = 0
        self.active = {}

    def request(self, host, path):
        with self.lock:
            self.requests += 1
            self.active[threading.get_ident()] = (host, path)

    def finish_host(self):
        with self.lock:
            self.hosts_done += 1
            self.active.pop(threading.get_ident(), None)

    def snapshot(self):
        with self.lock:
            last = list(self.active.values())[-1] if self.active else ("", "")
            return self.requests, self.hosts_done, self.hits, len(self.active), last


def status_loop(console, stats, started):
    """Repaint the live status line a few times a second."""
    spin = "|/-\\"
    i = 0
    while not DONE.is_set() and not STOP.is_set():
        reqs, done, hits, workers, (host, path) = stats.snapshot()
        elapsed = time.monotonic() - started
        rate = reqs / elapsed if elapsed > 0 else 0

        total = stats.total_requests
        left = max(total - reqs, 0)
        pct = (reqs / total * 100) if total else 0
        filled = int(pct / 5)                      # 20-cell bar
        bar = "=" * filled + ">" + " " * (19 - filled) if filled < 20 else "=" * 20

        # Requests are the finer-grained signal, so base the ETA on them and
        # fall back to host count before the first host finishes.
        if rate > 0 and left:
            eta_m = (left / rate) / 60
        elif done:
            eta_m = ((elapsed / done) * (stats.total_hosts - done)) / 60
        else:
            eta_m = 0

        c = console.c
        # Line 1: overall progress.
        line1 = ("%s%s%s %s%d/%d hosts%s [%s%s%s] %s%3.0f%%%s | %s%s reqs left%s"
                 " @ %.0f/s | %s%d hits%s | ~%.0fm" % (
                     c["cyan"], spin[i % 4], c["reset"],
                     c["bold"], done, stats.total_hosts, c["reset"],
                     c["cyan"], bar, c["reset"],
                     c["bold"], pct, c["reset"],
                     c["blue"], "{:,}".format(left), c["reset"], rate,
                     c["green"], hits, c["reset"], eta_m))
        # Line 2: what is being tried right now, host and path spelled out.
        if host:
            line2 = "   %strying%s %s%s%s %s->%s %s%s%s" % (
                c["grey"], c["reset"], c["bold"], host, c["reset"],
                c["grey"], c["reset"], c["yellow"], path, c["reset"])
        else:
            line2 = "   %sstarting...%s" % (c["grey"], c["reset"])
        console.status([line1, line2])
        i += 1
        time.sleep(0.25)
    console.clear()


class RateLimiter:
    """Global request rate limiter shared by all worker threads."""

    def __init__(self, per_second):
        self.interval = 1.0 / per_second if per_second > 0 else 0.0
        self.lock = threading.Lock()
        self.next_slot = time.monotonic()

    def wait(self):
        if self.interval <= 0:
            return
        with self.lock:
            now = time.monotonic()
            if self.next_slot < now:
                self.next_slot = now
            delay = self.next_slot - now
            self.next_slot += self.interval
        if delay > 0:
            time.sleep(delay)


def strip_vowels(word, keep_first=False):
    """selam -> slm. With keep_first, an initial vowel is preserved."""
    if not word:
        return ""
    out = []
    for i, ch in enumerate(word):
        if i == 0 and keep_first:
            out.append(ch)
            continue
        if ch.lower() not in VOWELS:
            out.append(ch)
    return "".join(out)


def name_variants(host):
    """Derive candidate filename bases from a hostname."""
    labels = [l for l in host.split(".") if l]
    seeds = set()

    if labels:
        seeds.add(labels[0])                 # portal.nasa.gov -> portal
    if len(labels) >= 3:
        seeds.add(labels[-3])                # portal.nasa.gov -> nasa
    if len(labels) >= 2:
        seeds.add(".".join(labels[:-1]))     # portal.nasa
    seeds.add(host)                          # portal.nasa.gov
    seeds.discard("")

    out = set()
    for seed in seeds:
        if not seed:
            continue
        out.add(seed)
        out.add(seed.replace(".", ""))
        out.add(re.sub(r"[-_]", "", seed))

        # split on separators: my-site -> my, site
        for part in re.split(r"[-_.]", seed):
            if len(part) >= 3:
                out.add(part)

        # vowel stripping, with and without keeping the first letter
        for word in list(out):
            if len(word) > 3 and word.isalnum():
                for keep_first in (False, True):
                    v = strip_vowels(word, keep_first=keep_first)
                    if 2 <= len(v) < len(word):
                        out.add(v)

        # leading abbreviations: portal -> por, port
        for n in (3, 4):
            if len(seed) > n and seed[:n].isalnum():
                out.add(seed[:n])

    return sorted(x for x in out
                  if 3 <= len(x) <= 30 and x.lower() not in SKIP_BASES)


def build_paths(host, exts, use_derive, use_common, use_source, fixed=True,
                use_tr=True):
    """Build the full list of paths to try against one host."""
    paths = []
    seen = set()

    def add(p):
        if p not in seen:
            seen.add(p)
            paths.append(p)

    bases = []
    if use_derive:
        bases += name_variants(host)
    if use_common:
        bases += COMMON_BASES_EN
        if use_tr:
            bases += COMMON_BASES_TR

    for base in bases:
        for ext in exts:
            add("%s.%s" % (base, ext))

    if use_source:
        for name in SOURCE_FILES:
            for suffix in SOURCE_SUFFIXES:
                add(name + suffix)
                if suffix == ".swp":
                    add("." + name + ".swp")   # vim swap: .index.php.swp

    if fixed:
        for p in FIXED_PATHS:
            add(p)

    return paths


def _columns(items, width=74, indent="  "):
    """Wrap a list of short strings into padded columns."""
    lines = []
    cur = indent
    for it in items:
        if len(cur) + len(it) + 2 > width and cur.strip():
            lines.append(cur.rstrip())
            cur = indent
        cur += it + "  "
    if cur.strip():
        lines.append(cur.rstrip())
    return "\n".join(lines)


def print_listing(tr=False):
    """Dump every extension, base and path the generator can produce."""
    sample = "portal.nasa.gov"
    new_normal = [e for e in EXT_NORMAL if e not in EXT_QUICK]
    new_full = [e for e in EXT_FULL if e not in EXT_NORMAL]

    t = {
        "hdr_q": "TIER 1 - --ext quick (%d extensions)" % len(EXT_QUICK),
        "hdr_n": "TIER 2 - --ext normal (%d total, %d new)" % (len(EXT_NORMAL), len(new_normal)),
        "hdr_f": "TIER 3 - --ext full (%d total, %d new)" % (len(EXT_FULL), len(new_full)),
        "hdr_d": "HOSTNAME-DERIVED BASES (on by default, off with --no-derive)",
        "hdr_c": "GENERIC BASES (on by default, off with --no-common) - %d" % len(COMMON_BASES),
        "hdr_s": "--source FILES (%d) x SUFFIXES (%d)" % (len(SOURCE_FILES), len(SOURCE_SUFFIXES)),
        "hdr_x": "FIXED PATHS (always tried) - %d" % len(FIXED_PATHS),
        "hdr_t": "PATHS PER HOST",
        "ex": "example for %s:" % sample,
        "row": ["--no-derive --no-common", "--ext quick", "--ext normal",
                "--ext full"],
    }
    if tr:
        t.update({
            "hdr_q": "KATMAN 1 - --ext quick (%d uzantı)" % len(EXT_QUICK),
            "hdr_n": "KATMAN 2 - --ext normal (toplam %d, %d yeni)" % (len(EXT_NORMAL), len(new_normal)),
            "hdr_f": "KATMAN 3 - --ext full (toplam %d, %d yeni)" % (len(EXT_FULL), len(new_full)),
            "hdr_d": "HOSTNAME'DEN ÜRETİLEN GÖVDELER (varsayılan açık, --no-derive kapatır)",
            "hdr_c": "GENEL GÖVDELER (varsayılan açık, --no-common kapatır) - %d" % len(COMMON_BASES),
            "hdr_s": "--source DOSYALARI (%d) x SON EKLER (%d)" % (len(SOURCE_FILES), len(SOURCE_SUFFIXES)),
            "hdr_x": "SABİT YOLLAR (her zaman denenir) - %d" % len(FIXED_PATHS),
            "hdr_t": "HOST BAŞINA YOL SAYISI",
            "ex": "%s için örnek:" % sample,
        })

    def section(title, body):
        print("\n" + title)
        print("-" * len(title))
        print(body)

    section(t["hdr_q"], _columns(EXT_QUICK))
    section(t["hdr_n"], _columns(new_normal))
    section(t["hdr_f"], _columns(new_full))
    section(t["hdr_d"], "  " + t["ex"] + "\n" + _columns(name_variants(sample)))
    section(t["hdr_c"], _columns(COMMON_BASES))
    section(t["hdr_s"], _columns(SOURCE_FILES) + "\n\n" +
            _columns(SOURCE_SUFFIXES) + "\n" +
            "  + vim swap: .<name>.swp")
    section(t["hdr_x"], _columns(FIXED_PATHS))

    combos = [
        (t["row"][0], build_paths(sample, EXT_QUICK, False, False, False)),
        (t["row"][1], build_paths(sample, EXT_QUICK, True, True, False)),
        (t["row"][2], build_paths(sample, EXT_NORMAL, True, True, False)),
        (t["row"][3], build_paths(sample, EXT_FULL, True, True, True)),
    ]
    rows = "\n".join("  %-26s %5d" % (name, len(paths)) for name, paths in combos)
    section(t["hdr_t"], rows)
    print("")


def build_opener(timeout, proxy=None):
    """Build a URL opener, optionally routed through an HTTP/HTTPS proxy."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    # An explicit empty mapping also stops urllib picking up *_proxy env vars.
    handlers.append(urllib.request.ProxyHandler(
        {"http": proxy, "https": proxy} if proxy else {}))
    return urllib.request.build_opener(*handlers)


def fetch(opener, url, limiter, timeout, max_bytes=None):
    """Fetch the first bytes of a URL. Returns (status, headers, body).

    Only `max_bytes` are read, PROBE_BYTES by default. Crawling asks for
    more, since a page truncated at 2 KB hides most of its links.
    """
    want = max_bytes or PROBE_BYTES
    limiter.wait()
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Range": "bytes=0-%d" % (want - 1),
        "Accept": "*/*",
        "Connection": "close",
    })
    # Header names are case-insensitive on the wire; normalise so lookups
    # cannot silently miss (Python's own http.server sends "Content-type").
    try:
        with opener.open(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, headers, resp.read(want)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(want)
        except Exception:
            body = b""
        headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        return e.code, headers, body
    except Exception:
        return None


def fingerprint(status, body):
    return (status, hashlib.sha1(body).hexdigest()[:16], len(body))


# Per-request noise in error pages: Cloudflare Ray IDs, request ids, clocks.
_NOISE = re.compile(rb"[0-9a-f]{12,}|\d")


def body_size(headers, body):
    """True resource size, or None when the server did not tell us.

    Returning None matters: with chunked transfer encoding there is no
    Content-Length, and every truncated read is exactly PROBE_BYTES long, so
    unrelated pages would all look like the same size.
    """
    crange = headers.get("content-range", "")
    if "/" in crange:
        total = crange.rsplit("/", 1)[-1].strip()
        if total.isdigit():
            return int(total)
    clen = headers.get("content-length", "")
    if clen.isdigit():
        return int(clen)
    if len(body) < PROBE_BYTES:
        return len(body)        # short body read in full, so this is the size
    return None                 # truncated and unannounced: size unknown


def same_shape(a, b, tol=0.02):
    """Same status code and body length within `tol` (default 2%).

    Content hashing is not enough for vendor error pages: a Cloudflare 1xxx
    page can differ by a couple of bytes between requests (nonces, variable
    width fields) while being the same page. Status plus near-equal length
    survives that, and a real homepage vs a 404 differ far more than 2%.
    """
    if a[0] != b[0]:
        return False
    la, lb = a[1], b[1]
    if la is None or lb is None:
        return False            # unknown size proves nothing either way
    if la == 0 and lb == 0:
        return True
    return abs(la - lb) / float(max(la, lb, 1)) <= tol


def loose_fingerprint(status, body):
    """Fingerprint that ignores per-request noise, for dead-host detection.

    Cloudflare 1xxx pages, and many vendor error pages, embed a Ray ID and a
    timestamp, so two responses that are the same page never hash alike.
    Only used to decide a host is a dead end, never to discard a finding.
    """
    return (status, hashlib.sha1(_NOISE.sub(b"", body)).hexdigest()[:16])


# --- crawling -------------------------------------------------------------
# Guessing filenames only ever finds what somebody else also guessed. Reading
# the site first turns guesses into candidates derived from paths that are
# known to exist, which is both cheaper and far more likely to land.

CRAWL_BYTES = 262144        # read this much of a page, not just PROBE_BYTES
CRAWL_MAX_PAGES = 8         # HTML pages fetched per host, across all depths
CRAWL_MAX_JS = 3            # script bundles read for the routes hidden in them
CRAWL_MAX_FILES = 25        # observed files that get backup suffixes appended
CRAWL_MAX_DIRS = 10         # observed directories that get probed
# Rough per-host allowance for the crawl itself plus the candidates it
# derives. Only used to keep the progress estimate honest; the real number
# depends on how much the site links to.
CRAWL_BUDGET = 150

# Suffixes appended to a file that was seen on the site. Shorter than
# SOURCE_SUFFIXES on purpose: every entry here is multiplied by CRAWL_MAX_FILES.
CRAWL_SUFFIXES = [".bak", "~", ".old", ".save", ".orig"]

# Tried inside every directory the crawl found. The root already gets the full
# FIXED_PATHS list, so this is the short high-value subset plus the archive
# names a directory is most often dumped under.
CRAWL_DIR_PROBES = [
    ".env", ".git/HEAD", ".htpasswd", ".DS_Store",
    "backup.zip", "backup.sql", "db.sql",
]

LINK_RE = re.compile(
    rb"""(?:href|src|action)\s*=\s*["']([^"'>\s]{1,300})""", re.I)
# Absolute paths quoted inside JavaScript: "/api/v2/users", '/assets/app.js'.
JSPATH_RE = re.compile(rb"""["'](/[A-Za-z0-9._~/\-]{2,120})["']""")


def _same_origin(url, base):
    """True when url belongs to the host (and scheme) we are scanning."""
    a, b = urllib.parse.urlparse(url), urllib.parse.urlparse(base)
    return a.netloc == b.netloc


def extract_links(body, page_url, base):
    """Absolute, same-origin URLs referenced by one page or script."""
    out = set()
    for m in LINK_RE.finditer(body):
        raw = m.group(1).decode("utf-8", "replace").strip()
        if not raw or raw.startswith(("#", "mailto:", "tel:", "javascript:",
                                      "data:")):
            continue
        url = urllib.parse.urljoin(page_url, raw)
        if url.startswith(("http://", "https://")) and _same_origin(url, base):
            out.add(url.split("#")[0])
    return out


def extract_js_paths(body, base):
    """Absolute paths quoted inside a script bundle (SPA routes, API calls)."""
    out = set()
    for m in JSPATH_RE.finditer(body):
        raw = m.group(1).decode("utf-8", "replace")
        if raw.startswith("//"):            # protocol-relative URL, not a path
            continue
        out.add(base.rstrip("/") + raw)
    return out


# Words that name a page rather than the site, so they never become a backup
# guess. Compared lowercase and ASCII-folded.
_NAME_STOPWORDS = {
    "login", "signin", "signup", "register", "home", "anasayfa", "giris",
    "dashboard", "panel", "admin", "account", "hesabim", "welcome", "index",
    "untitled", "react", "app", "vite", "next", "page", "site", "web", "www",
    "online", "store", "shop", "magaza", "yedek", "parca", "com", "net", "org",
    "loading", "error", "document", "title", "html", "main", "garajim",
    "logo", "logotype", "image", "otomobil", "otomotiv", "automotive", "auto",
    "parts", "spare", "ecommerce", "ticaret", "sanayi", "limited", "sirketi",
}

# Accented and Turkish letters folded to ASCII so a brand token matches the
# plain filename a backup would use.
_FOLD = {
    "ç": "c", "ğ": "g", "ı": "i", "ö": "o", "ş": "s",
    "ü": "u", "â": "a", "î": "i", "û": "u", "é": "e",
    "è": "e", "á": "a", "ä": "a", "ñ": "n",
}


def _ascii_fold(s):
    out = []
    for ch in s:
        low = ch.lower()
        out.append(_FOLD.get(ch, _FOLD.get(low, ch)))
    return "".join(out)


# title/meta/logo extractors, kept as compiled patterns so extract_names stays
# readable. Each captures one group: the text to mine for a brand token.
_NAME_PATTERNS = [
    re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S),
    re.compile(r'<meta[^>]+(?:property|name)=["\']og:site_name["\'][^>]+'
               r'content=["\']([^"\']+)', re.I),
    re.compile(r'<meta[^>]+name=["\']application-name["\'][^>]+'
               r'content=["\']([^"\']+)', re.I),
    re.compile(r'alt=["\']([^"\']*logo[^"\']*)["\']', re.I),
]

# a title splits on these before tokenising: "KARAKAYA | Yedek Parca"
_NAME_SPLIT = re.compile(r"[|\-–—:·/\\,]")
_NAME_TOKEN = re.compile(r"[A-Za-zÀ-ɏ0-9]{3,}")


def extract_names(body):
    """Brand names a site calls itself, for an IP target with no usable
    hostname. Mined from the title, og:site_name / application-name, and logo
    alt text, then reduced to distinctive tokens. KARAKAYA YEDEK PARCA ->
    {"karakaya"}; generic words are dropped so the guesses stay specific."""
    text = body[:CRAWL_BYTES].decode("utf-8", "replace")
    names = set()
    for pat in _NAME_PATTERNS:
        for m in pat.finditer(text):
            for piece in _NAME_SPLIT.split(m.group(1)):
                for tok in _NAME_TOKEN.findall(piece):
                    fold = re.sub(r"[^a-z0-9]", "", _ascii_fold(tok).lower())
                    if 3 <= len(fold) <= 20 and fold not in _NAME_STOPWORDS:
                        names.add(fold)
    return names


def _split_observed(urls, base):
    """Sort observed URLs into (files, directories), both relative to base."""
    root = base.rstrip("/")
    files, dirs = set(), set()
    for u in urls:
        path = urllib.parse.urlparse(u).path
        if not path or path == "/":
            continue
        parts = [p for p in path.split("/") if p]
        last = parts[-1] if parts else ""
        # A trailing slash, or a last segment with no dot, reads as a directory.
        if path.endswith("/") or "." not in last:
            depth = len(parts)
        else:
            files.add("/".join(parts))
            depth = len(parts) - 1
        for d in range(1, depth + 1):
            dirs.add("/".join(parts[:d]))
    return files, dirs


def crawl(opener, base, limiter, timeout, depth=2):
    """Walk the site briefly and return (files, dirs, names) seen, relative to base.

    Cheap by design: a handful of pages, a few scripts, plus robots.txt and
    sitemap.xml, which hand over directory names for free and are the one
    place a site volunteers paths it would rather you did not guess.
    """
    seen_pages = set()
    found = set()
    names = set()

    for extra in ("robots.txt", "sitemap.xml"):
        res = fetch(opener, "%s/%s" % (base, extra), limiter, timeout,
                    max_bytes=CRAWL_BYTES)
        if res and res[0] == 200 and res[2]:
            body = res[2]
            for m in re.finditer(rb"(?:Disallow|Allow|Sitemap)\s*:\s*(\S+)",
                                 body, re.I):
                raw = m.group(1).decode("utf-8", "replace")
                url = urllib.parse.urljoin(base + "/", raw)
                if _same_origin(url, base):
                    found.add(url)
            for m in re.finditer(rb"<loc>\s*([^<\s]+)\s*</loc>", body, re.I):
                url = m.group(1).decode("utf-8", "replace")
                if _same_origin(url, base):
                    found.add(url)

    queue = [(base + "/", 0)]
    scripts = []
    while queue and len(seen_pages) < CRAWL_MAX_PAGES:
        if STOP.is_set():
            break
        url, d = queue.pop(0)
        if url in seen_pages:
            continue
        seen_pages.add(url)
        res = fetch(opener, url, limiter, timeout, max_bytes=CRAWL_BYTES)
        if res is None or res[0] >= 400 or not res[2]:
            continue
        names |= extract_names(res[2])
        links = extract_links(res[2], url, base)
        found |= links
        if d < depth:
            for l in links:
                path = urllib.parse.urlparse(l).path
                if path.endswith(".js") and len(scripts) < CRAWL_MAX_JS:
                    scripts.append(l)
                elif ("." not in path.rsplit("/", 1)[-1]
                        or path.endswith((".html", ".htm", ".php"))):
                    queue.append((l, d + 1))

    for s in scripts:
        if STOP.is_set():
            break
        res = fetch(opener, s, limiter, timeout, max_bytes=CRAWL_BYTES)
        if res and res[0] == 200 and res[2]:
            found |= extract_js_paths(res[2], base)

    files, dirs = _split_observed(found, base)
    return files, dirs, names


def crawl_paths(files, dirs, names=(), exts=None):
    """Turn what the crawl saw into backup-file candidates.

    Observed files get backup suffixes, observed directories get probed, and
    any brand name the site calls itself (KARAKAYA on an IP target) is run
    through the same name machinery as a hostname would be, so karakaya.zip,
    krky.sql and friends get tried even though the URL was only an IP:port."""
    paths, seen = [], set()

    def add(p):
        if p and p not in seen:
            seen.add(p)
            paths.append(p)

    # Shortest paths first: they sit closer to the web root, where a stray
    # backup is both more likely and more useful.
    for f in sorted(files, key=lambda x: (x.count("/"), len(x)))[:CRAWL_MAX_FILES]:
        for suf in CRAWL_SUFFIXES:
            add(f + suf)
        # A source map hands over the original, unminified source in one file.
        if f.endswith((".js", ".css", ".mjs")):
            add(f + ".map")

    for d in sorted(dirs, key=lambda x: (x.count("/"), len(x)))[:CRAWL_MAX_DIRS]:
        name = d.rsplit("/", 1)[-1]
        for probe in CRAWL_DIR_PROBES:
            add("%s/%s" % (d, probe))
        for ext in ("zip", "tar.gz", "sql"):
            add("%s/%s.%s" % (d, name, ext))     # /admin/admin.zip
            add("%s.%s" % (d, ext))              # /admin.zip

    # Brand names -> the same variants a hostname produces, each with every
    # extension. This is the whole point on an IP target: the URL gives no
    # name, but the page does.
    tier = exts if exts is not None else EXT_QUICK
    for nm in names:
        for base in name_variants(nm):
            for ext in tier:
                add("%s.%s" % (base, ext))

    return paths


def calibrate(opener, base, limiter, timeout, rounds=2):
    """Learn how this host responds to files that do not exist."""
    prints = set()
    loose = set()
    lengths = set()
    shapes = []
    soft_200 = False
    for _ in range(rounds):
        rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        res = fetch(opener, "%s/%s.zip" % (base, rnd), limiter, timeout)
        if res is None:
            continue
        status, headers, body = res
        prints.add(fingerprint(status, body))
        loose.add(loose_fingerprint(status, body))
        lengths.add(len(body))
        shapes.append((status, body_size(headers, body)))
        if status in (200, 206):
            soft_200 = True
    return prints, lengths, soft_200, loose, shapes


def has_magic(body):
    """True when the body opens with a known binary file signature."""
    for sig, offset, _ in SIGNATURES:
        if body[offset:offset + len(sig)] == sig:
            return True
    return False


def is_html(body):
    """True when the body is an HTML document rather than a file.

    Servers answer a missing path with the site's own page all the time, and
    such a page carries login forms and inline JS config that match the text
    signatures below. So HTML has to be ruled out before they are tried, or
    every path on the host is reported as a credential file.
    """
    head = body[:1024].lstrip().lower()
    if head[:3] == bytes([0xef, 0xbb, 0xbf]):   # UTF-8 BOM
        head = head[3:].lstrip()
    if head.startswith((b"<!doctype html", b"<html", b"<head")):
        return True
    # Some pages open with a comment or a conditional block before <html>.
    return head.startswith(b"<!--") and b"<html" in head


def identify(headers, body):
    """Identify the file type from its content. Returns (label, confidence)."""
    for sig, offset, label in SIGNATURES:
        if body[offset:offset + len(sig)] == sig:
            return label, "high"
    if is_html(body):
        return "html", "reject"
    for pattern, label in TEXT_SIGNATURES:
        if pattern.search(body[:PROBE_BYTES]):
            return label, "high"

    ctype = (headers.get("content-type") or "").lower()
    if "html" in ctype:
        return "html", "reject"
    if any(t in ctype for t in ("zip", "octet-stream", "gzip", "x-tar",
                                "x-rar", "sql", "x-7z", "x-bzip")):
        return ctype.split(";")[0], "medium"
    return ctype.split(";")[0] or "unknown", "low"


def parse_target(line):
    """Parse one input line into (key, base candidates, had_scheme).

    An explicit scheme is honoured as given. A bare hostname is tried over
    https first, then http.
    """
    parts = line.strip().split()
    if not parts:
        return None
    token = parts[0].rstrip("/")
    if not token or token.startswith("#"):
        return None

    if token.startswith("http://") or token.startswith("https://"):
        return token, [token], True

    # Drop any stray path or query fragment
    token = token.split("/")[0].split("?")[0]
    if not token:
        return None
    return token, ["https://" + token, "http://" + token], False


def resolve_base(candidates, opener, limiter, timeout):
    """Return the scheme that actually serves something, as (base, response).

    A bare hostname is tried over https first, then http. An https endpoint
    answering with a gateway or server error (broken TLS backend, Cloudflare
    5xx) technically replied but is useless to scan, so the other scheme is
    tried too and a working one wins. If both are 5xx, the first is kept so
    the host is still reported rather than silently dropped.
    """
    fallback = None
    for base in candidates:
        if STOP.is_set():
            return None, None
        res = fetch(opener, base, limiter, timeout)
        if res is None:
            continue
        if res[0] < 500:
            return base, res
        if fallback is None:
            fallback = (base, res)
    if fallback is not None:
        return fallback
    return None, None


def stats_of(opts):
    return opts.get("stats")


def scan_host(key, candidates, opts, limiter):
    """Scan one target. Returns (key, findings, skip_reason_or_None)."""
    # One proxy per host, not per request: soft-404 calibration only holds if
    # every request for this host leaves through the same exit node.
    proxies = opts.get("proxies")
    proxy = random.choice(proxies) if proxies else None
    if proxy and SESSION_TOKEN in proxy:
        # Rotating-proxy providers keep one exit IP per session id, so give
        # each host its own id and the whole host scan stays on one IP.
        sid = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        proxy = proxy.replace(SESSION_TOKEN, sid)
    opener = build_opener(opts["timeout"], proxy)
    results = []

    if STOP.is_set():
        return key, results, None

    base, alive = resolve_base(candidates, opener, limiter, opts["timeout"])
    if base is None:
        if stats_of(opts):
            stats_of(opts).finish_host()
        return key, results, None

    soft404, soft_lengths, soft_200, soft_loose, soft_shapes = calibrate(
        opener, base, limiter, opts["timeout"])

    # A host that answers "/" the same way it answers a random path serves one
    # constant page for every URL: parked domain, broken DNS, Cloudflare 1xxx.
    # Nothing can ever be found there, so do not spend thousands of requests.
    # Only ever skip on an error status. A host that answers every URL with
    # the same page but a 200 is a working app with catch-all routing (SPA
    # login screens do this): a real file still gets served by the web server
    # before the catch-all, so it must be scanned. A 4xx/5xx everywhere means
    # nothing is being served at all.
    dead_reason = None
    if (opts.get("skip_dead") and alive is not None and soft_shapes
            and alive[0] >= 400):
        root_shape = (alive[0], body_size(alive[1], alive[2]))
        if (loose_fingerprint(alive[0], alive[2]) in soft_loose
                or all(same_shape(root_shape, s) for s in soft_shapes)):
            size_txt = (human_size(root_shape[1]) if root_shape[1] is not None
                        else "size unknown")
            dead_reason = "constant response (HTTP %s, %s)" % (
                alive[0], size_txt)

    host = urllib.parse.urlparse(base).hostname or ""
    if opts["paths"] is not None:
        paths = opts["paths"]
    else:
        paths = build_paths(host, opts["exts"], opts["derive"],
                            opts["common"], opts["source"],
                            use_tr=opts.get("tr", True))
    if opts["max_per_host"]:
        paths = paths[:opts["max_per_host"]]

    # Candidates derived from paths the site actually serves. Put first:
    # they are the likeliest to land, so a run cut short by Ctrl+C or
    # --max-per-host has already tried the best ones.
    if opts.get("crawl"):
        try:
            files, dirs, names = crawl(opener, base, limiter,
                                       opts["timeout"],
                                       depth=opts.get("crawl_depth", 2))
            derived = [p for p in crawl_paths(files, dirs, names, opts["exts"])
                       if p not in set(paths)]
            paths = derived + paths
        except Exception:
            pass        # a crawl that fails must never cost the scan

    # A host answering every URL with one error page is usually empty, but an
    # API server with nothing at "/" looks exactly the same and may still be
    # serving .env or .git/HEAD. So rather than skip it outright, try only the
    # fixed high-value paths: 24 requests instead of thousands, and the
    # findings that actually matter live there anyway.
    if dead_reason is not None:
        paths = list(FIXED_PATHS)

    console = opts.get("console")
    stats = opts.get("stats")
    verbose = opts.get("verbose")
    logfh = opts.get("logfh")
    loglock = opts.get("loglock")

    def log(status, url):
        if logfh is None:
            return
        with loglock:
            logfh.write("%s %s\n" % (status, url))

    for path in paths:
        if STOP.is_set():
            break
        url = "%s/%s" % (base, path)
        if stats:
            stats.request(host, path)
        res = fetch(opener, url, limiter, opts["timeout"])
        if res is None:
            log("ERR", url)
            if verbose and console:
                console.info("%s  ... %s%s" % (console.c["grey"], url, console.c["reset"]))
            continue
        status, headers, body = res
        log(status, url)
        if verbose and console:
            col = console.c["yellow"] if status in (200, 206) else console.c["grey"]
            console.info("%s  %s %s%s" % (col, status, url, console.c["reset"]))
        if status not in (200, 206):
            continue
        if fingerprint(status, body) in soft404:
            continue
        # Same page as the calibration probe, just with a different Ray ID /
        # request id / timestamp baked in.
        if loose_fingerprint(status, body) in soft_loose:
            continue
        # Length filter, but ONLY when the body was read in full. A response
        # bigger than PROBE_BYTES is always read as exactly PROBE_BYTES, so a
        # truncated soft-404 page and a truncated real backup would both look
        # like PROBE_BYTES long and the real file would be dropped. When
        # truncated, skip this check and let identify()'s magic bytes decide.
        if (soft_200 and len(body) < PROBE_BYTES
                and len(body) in soft_lengths):
            continue
        # A truncated body defeats the length filter above, so fall back to the
        # response shape: the same status and the same size the server declares
        # as a calibration probe means the same page came back. Skipped when
        # the bytes carry a real file signature, so a genuine archive is never
        # dropped on size alone.
        if (soft_shapes and len(body) >= PROBE_BYTES and not has_magic(body)
                and any(same_shape((status, body_size(headers, body)), s)
                        for s in soft_shapes)):
            continue
        if not body:
            continue

        label, confidence = identify(headers, body)
        if confidence == "reject":
            continue

        # On a 206 the Content-Length is only the slice we asked for, so the
        # real file size lives in Content-Range: "bytes 0-2047/104857600".
        size = headers.get("content-length", "")
        crange = headers.get("content-range", "")
        if "/" in crange:
            total = crange.rsplit("/", 1)[-1].strip()
            if total.isdigit():
                size = total

        results.append({
            "url": url,
            "status": status,
            "type": label,
            "confidence": confidence,
            "content_type": headers.get("content-type", ""),
            "content_length": size,
            "content_range": crange,
            "preview": body[:64].hex(),
        })
    # No real host holds dozens of different backups that are all exactly the
    # same size. When most findings on a host share one size, the host is
    # answering everything with one page and the findings are noise.
    if len(results) >= CATCHALL_MIN:
        counts = {}
        for r in results:
            counts[r["content_length"]] = counts.get(r["content_length"], 0) + 1
        repeated = max(counts.values())
        if repeated >= len(results) * CATCHALL_RATIO:
            if stats:
                stats.finish_host()
            return key, [], "catch-all: %d identical responses" % repeated
    if stats:
        stats.finish_host()
    return key, results, dead_reason


def main():
    # Never let an unrepresentable character kill a running scan; substitute
    # instead. Matters for the Turkish help and the box drawing under LANG=C.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass

    # Intercepted before argparse: "-tr" would be read as "-t r".
    argv = sys.argv[1:]
    if any(f in argv for f in ("--version", "-V")):
        print("%s %s" % (NAME, VERSION))
        return 0
    want_tr = any(f in argv for f in ("-tr", "--tr", "--help-tr"))
    if "--list-ext" in argv:
        print_listing(tr=want_tr)
        return 0
    if want_tr:
        print(banner(color=sys.stdout.isatty(), stream=sys.stdout))
        print(HELP_TR)
        return 0

    ap = argparse.ArgumentParser(
        prog=NAME,
        description="Backup file and source leak hunter",
        # No prefix abbreviation: otherwise a stray "--max" would silently
        # resolve to "--max-per-host" and demand a value. Flags must be spelled
        # in full, and an unknown one gives a clean "unrecognized" error.
        allow_abbrev=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  # wide sweep, highest hit rate, ~27 requests per host
  lucille -l live.txt --no-derive --no-common -r 20 -o stage1.jsonl

  # everything, on a short hand-picked list, ~11000 requests per host
  lucille -l shortlist.txt --ext full -r 15 -o stage2.jsonl

  # see what would be requested without sending anything
  lucille -l live.txt --ext full --dry-run | head -50

Turkish help: lucille -tr
""")
    ap.add_argument("-l", "--list", required=True,
                    help="target list (httpx output or bare hostnames)")
    ap.add_argument("-p", "--paths",
                    help="custom path list file (disables all path generation)")
    ap.add_argument("-o", "--output", default="hits.jsonl", help="output file (JSONL)")
    ap.add_argument("-t", "--threads", type=int, default=10, help="concurrent hosts")
    ap.add_argument("-r", "--rate", type=float, default=20,
                    help="total requests per second across all threads")
    ap.add_argument("--timeout", type=float, default=8, help="request timeout in seconds")
    ap.add_argument("--ext", choices=["quick", "normal", "full"], default="quick",
                    help="extension tier (quick=12, normal=43, full=120)")
    ap.add_argument("--no-derive", dest="derive", action="store_false",
                    help="disable hostname-derived filename bases")
    ap.add_argument("--no-common", dest="common", action="store_false",
                    help="disable generic bases (backup, db, www, yedek, ...)")
    ap.add_argument("--no-tr", action="store_true",
                    help="drop the Turkish bases (yedek, arsiv, veritabani, ...)"
                         " from the generic set")
    ap.add_argument("--source", action="store_true",
                    help="also try source file backups (index.php~, config.php.bak,"
                         " ...); already included by --ext full")
    ap.add_argument("--max-per-host", type=int, default=0,
                    help="cap requests per host (0 = no cap)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the generated paths without sending requests")
    ap.add_argument("--list-ext", action="store_true",
                    help="print every extension, base and fixed path the"
                         " generator can produce, then exit (add -tr for Turkish)")
    ap.add_argument("--all", action="store_true", help="include low-confidence findings")
    ap.add_argument("--log", dest="logfile",
                    help="write every attempt (status + URL) to this file,"
                         " one per line, for reviewing after the scan")
    ap.add_argument("--state", help="state file path (default: <output>.state)")
    ap.add_argument("--restart", action="store_true",
                    help="ignore the state file and start over")
    ap.add_argument("--proxy",
                    help="route all requests through one proxy, e.g."
                         " http://user:pass@1.2.3.4:8080. For a rotating"
                         " provider, put {SESSION} in the username and each"
                         " host gets its own sticky session id")
    ap.add_argument("--proxy-file",
                    help="file with one proxy URL per line; a proxy is picked"
                         " per host and kept for that host's whole scan")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print every path as it is tried, with its status code"
                         " (replaces the live status line)")
    ap.add_argument("--no-color", action="store_true", help="disable colours")
    ap.add_argument("--no-bell", action="store_true",
                    help="do not ring the terminal bell on a HIGH hit")
    ap.add_argument("--no-crawl", action="store_true",
                    help="do not read the site first; skip building"
                         " candidates from the paths it actually serves")
    ap.add_argument("--crawl-depth", type=int, default=2,
                    help="how many link hops the crawl follows (default 2)")
    ap.add_argument("--no-skip-dead", action="store_true",
                    help="scan every host fully, even ones that answer every"
                         " URL with the same page (parked domains, broken DNS,"
                         " Cloudflare 1xxx errors)")
    ap.add_argument("-V", "--version", action="store_true",
                    help="print the version and exit")
    ap.add_argument("-s", "--silent", action="store_true", help="suppress the banner")
    args = ap.parse_args()

    # "full" means everything: 120 extensions plus source-file backups.
    # --source stays as a flag so it can be added to quick/normal too.
    if args.ext == "full":
        args.source = True

    if not args.silent and not args.dry_run:
        print(banner(color=not args.no_color
                     and sys.stderr.isatty()),
              file=sys.stderr)

    exts = {"quick": EXT_QUICK, "normal": EXT_NORMAL, "full": EXT_FULL}[args.ext]

    if args.ext == "full":
        print("[*] full tier: 120 extensions + source-file backups",
              file=sys.stderr)

    # --- proxies ---
    proxies = []
    if args.proxy:
        proxies.append(args.proxy)
    if args.proxy_file:
        with open(args.proxy_file) as pf:
            proxies += [l.strip() for l in pf
                        if l.strip() and not l.startswith("#")]
    if proxies:
        bad = [p for p in proxies if p.startswith("socks")]
        if bad:
            print("[!] SOCKS proxies are not supported (urllib limitation);"
                  " %d entry/entries ignored" % len(bad), file=sys.stderr)
            proxies = [p for p in proxies if not p.startswith("socks")]
    if proxies:
        sticky = sum(1 for p in proxies if SESSION_TOKEN in p)
        print("[*] proxies: %d loaded, one picked per host" % len(proxies),
              file=sys.stderr)
        if sticky:
            print("[*] %d use {SESSION}: a fresh sticky session id per host"
                  % sticky, file=sys.stderr)
        else:
            print("[!] no {SESSION} placeholder found. If this is a rotating"
                  " provider that changes IP every request, soft-404"
                  " calibration will misfire and findings get noisy.",
                  file=sys.stderr)

    targets = []
    seen = set()
    n_scheme = 0
    n_plain = 0
    with open(args.list) as f:
        for line in f:
            parsed = parse_target(line)
            if not parsed:
                continue
            key, candidates, had_scheme = parsed
            if had_scheme:
                n_scheme += 1
            else:
                n_plain += 1
            if key not in seen:
                seen.add(key)
                targets.append((key, candidates))

    if not targets:
        print("[!] target list is empty: %s" % args.list, file=sys.stderr)
        return 1

    # Report the detected input format before doing anything
    if n_plain and not n_scheme:
        print("[*] input format: bare hostnames (%d)" % n_plain, file=sys.stderr)
        print("[*] each host will be tried over https:// first, then http://",
              file=sys.stderr)
    elif n_scheme and not n_plain:
        print("[*] input format: URLs with scheme (%d)" % n_scheme, file=sys.stderr)
        print("[*] the given scheme will be used as-is, no fallback", file=sys.stderr)
    else:
        print("[*] input format: mixed (%d with scheme, %d bare hostnames)"
              % (n_scheme, n_plain), file=sys.stderr)
        print("[*] scheme URLs used as-is, bare hostnames try https then http",
              file=sys.stderr)

    custom_paths = None
    if args.paths:
        with open(args.paths) as f:
            custom_paths = [l.strip().lstrip("/") for l in f if l.strip()]

    if args.dry_run:
        host = targets[0][0].replace("https://", "").replace("http://", "").split("/")[0]
        paths = custom_paths if custom_paths is not None else build_paths(
            host, exts, args.derive, args.common, args.source,
            use_tr=not args.no_tr)
        if args.max_per_host:
            paths = paths[:args.max_per_host]
        print("# bases generated for %s:" % host, file=sys.stderr)
        print("# %s" % ", ".join(name_variants(host)), file=sys.stderr)
        print("# %d paths per host" % len(paths), file=sys.stderr)
        for p in paths:
            print(p)
        return 0

    opts = {
        "exts": exts, "derive": args.derive, "common": args.common,
        "source": args.source, "timeout": args.timeout,
        "max_per_host": args.max_per_host, "paths": custom_paths,
        "proxies": proxies, "skip_dead": not args.no_skip_dead,
        "tr": not args.no_tr, "crawl": not args.no_crawl,
        "crawl_depth": args.crawl_depth,
    }

    # --- resume support ---
    state_path = args.state or (args.output + ".state")
    done_keys = set()
    if args.restart:
        for path in (state_path, args.output):
            try:
                open(path, "w").close()
            except OSError:
                pass
    else:
        try:
            with open(state_path) as sf:
                done_keys = {l.strip() for l in sf if l.strip()}
        except FileNotFoundError:
            pass

    total_targets = len(targets)
    if done_keys:
        targets = [t for t in targets if t[0] not in done_keys]
        print("[*] previous run detected: %d hosts already done, skipping"
              % len(done_keys), file=sys.stderr)
        print("[*] use --restart to start over", file=sys.stderr)
        if not targets:
            print("[*] all targets already scanned, nothing to do", file=sys.stderr)
            return 0

    # Exact request total: count the paths every host will actually generate,
    # not one host's count times the number of hosts. Different hostnames yield
    # different numbers of derived bases, so the estimate drifted and the
    # "reqs left" counter never lined up with the real request count. This is
    # pure string work, no network, so it is cheap even for large lists.
    # (+3 per host covers the alive probe and two calibration probes.)
    crawling = not args.no_crawl and custom_paths is None
    OVERHEAD = 3
    if custom_paths is not None:
        n = args.max_per_host or len(custom_paths)
        total = len(targets) * (n + OVERHEAD + (CRAWL_BUDGET if crawling else 0))
    else:
        total = 0
        for key, _cands in targets:
            host = key.replace("https://", "").replace("http://", "").split("/")[0]
            n = len(build_paths(host, exts, args.derive, args.common,
                                args.source, use_tr=not args.no_tr))
            if args.max_per_host:
                n = min(n, args.max_per_host)
            total += n + OVERHEAD + (CRAWL_BUDGET if crawling else 0)
    per_host = total // len(targets) if targets else 0
    minutes = (total / args.rate) / 60 if args.rate > 0 else 0

    print("[*] targets: %d of %d | ~%d requests per host | %d requests overall"
          % (len(targets), total_targets, per_host, total), file=sys.stderr)
    print("[*] rate %.0f req/s -> estimated runtime: %.0f min (%.1f h)"
          % (args.rate, minutes, minutes / 60), file=sys.stderr)
    if crawling:
        print("[*] crawling each site first; candidates built from the"
              " paths it serves (--no-crawl to skip)", file=sys.stderr)
    if minutes > 180:
        print("[!] over 3 hours. consider --ext quick, --max-per-host, or a"
              " shorter target list.", file=sys.stderr)
    print("[*] Ctrl+C is safe to use; re-running the same command resumes.",
          file=sys.stderr)
    print("", file=sys.stderr)

    console = Console(color=not args.no_color and sys.stderr.isatty())
    stats = Stats(len(targets), total)
    opts["console"] = console
    opts["stats"] = stats
    opts["verbose"] = args.verbose

    # Optional full attempt log. Append so a resumed run keeps the earlier lines.
    logfh = None
    if args.logfile:
        logfh = open(args.logfile, "a")
        opts["logfh"] = logfh
        opts["loglock"] = threading.Lock()
        print("[*] logging every attempt to %s" % args.logfile, file=sys.stderr)

    limiter = RateLimiter(args.rate)
    counters = {"done": 0, "hits": 0, "skipped": 0}
    skipped_hosts = []
    lock = threading.Lock()
    started = time.monotonic()
    interrupted = False
    # With few hosts but many paths each, a host takes minutes; report every
    # one so the run never looks frozen. Only batch the reports on long lists.
    step = 1 if len(targets) <= 200 else 25

    out_mode = "a" if (done_keys and not args.restart) else "w"
    out = open(args.output, out_mode)
    state = open(state_path, "a")
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=args.threads)

    col = console.c
    conf_colour = {"high": col["green"], "medium": col["yellow"], "low": col["grey"]}

    status_thread = None
    if not args.verbose and sys.stderr.isatty():
        status_thread = threading.Thread(
            target=status_loop, args=(console, stats, started), daemon=True)
        status_thread.start()

    try:
        futures = [pool.submit(scan_host, key, cands, opts, limiter)
                   for key, cands in targets]
        for fut in concurrent.futures.as_completed(futures):
            try:
                key, found, skipped = fut.result()
            except Exception:
                continue

            with lock:
                counters["done"] += 1
                if skipped:
                    counters["skipped"] += 1
                    skipped_hosts.append(key)
                    console.info("%s[~]%s skipped %s %s(%s)%s" % (
                        col["grey"], col["reset"], key,
                        col["grey"], skipped, col["reset"]))
                for r in found:
                    if r["confidence"] == "low" and not args.all:
                        continue
                    counters["hits"] += 1
                    with stats.lock:
                        stats.hits += 1
                    out.write(json.dumps(r) + "\n")
                    out.flush()
                    render_hit(console, r, bell=not args.no_bell)
                if not STOP.is_set():
                    state.write(key + "\n")
                    state.flush()
                if counters["done"] % step == 0 or counters["done"] == len(targets):
                    elapsed = time.monotonic() - started
                    done = counters["done"]
                    eta = (elapsed / done) * (len(targets) - done) if done else 0
                    console.info("%s[*]%s %s%d/%d%s hosts | %s%d%s findings |"
                                 " %.0fm elapsed | ~%.0fm left" % (
                                     col["cyan"], col["reset"],
                                     col["bold"], done, len(targets), col["reset"],
                                     col["green"], counters["hits"], col["reset"],
                                     elapsed / 60, eta / 60))
    except KeyboardInterrupt:
        interrupted = True
        STOP.set()
        console.info("\n%s[!]%s stopping, letting in-flight requests finish..."
                     % (col["yellow"], col["reset"]))
    finally:
        DONE.set()
        if status_thread:
            status_thread.join(timeout=1)
        console.clear()
        pool.shutdown(wait=True, cancel_futures=True)
        out.close()
        state.close()
        if logfh:
            logfh.close()

    if interrupted:
        console.info("%s[!]%s %d/%d hosts completed. re-run the same command"
                     " to resume." % (col["yellow"], col["reset"],
                                      counters["done"], len(targets)))
        console.info("%s[!]%s state file: %s" % (col["yellow"], col["reset"],
                                                 state_path))
    else:
        console.info("%s[*]%s done. %s%d findings%s -> %s" % (
            col["cyan"], col["reset"], col["green"], counters["hits"],
            col["reset"], args.output))

    if skipped_hosts:
        skip_path = args.output + ".skipped"
        try:
            with open(skip_path, "w") as sf:
                sf.write("\n".join(skipped_hosts) + "\n")
        except OSError:
            skip_path = "(could not write)"
        console.info("%s[~]%s %d host(s) answered every URL identically;"
                     " only the %d fixed high-value paths were tried on them"
                     " -> %s" % (col["grey"], col["reset"],
                                 len(skipped_hosts), len(FIXED_PATHS),
                                 skip_path))
        console.info("%s[~]%s use --no-skip-dead to scan them in full"
                     % (col["grey"], col["reset"]))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except KeyboardInterrupt:
        print("\n[!] aborted.", file=sys.stderr)
        sys.exit(130)
