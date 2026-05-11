"""
WebTrail — DFIR Edition
Browsing history forensics tool for incident response.
Supports: Chrome, Edge, Firefox, Brave, Opera, Vivaldi, Safari (macOS), Yandex
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import sqlite3
import shutil
import os
import sys
import platform
import threading
import csv
import json
import re
import webbrowser
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse
import tempfile
import io
import base64
try:
    from PIL import Image, ImageTk
    _PIL_OK = True
except ImportError:
    try:
        import subprocess, sys
        subprocess.check_call([sys.executable, "-m", "pip", "install",
                               "pillow", "--quiet"],
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
        from PIL import Image, ImageTk
        _PIL_OK = True
    except Exception:
        _PIL_OK = False  # Icons will fall back to coloured dots — app still works



# ─── Chrome epoch → datetime ─────────────────────────────────────────────────
CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Reasonable year bounds — anything outside is treated as corrupted
_YEAR_MIN = 2000
_YEAR_MAX = 2035

def _is_valid_dt(dt):
    """Return True if dt is a plausible real-world browser timestamp."""
    if dt is None:
        return False
    try:
        return _YEAR_MIN <= dt.year <= _YEAR_MAX
    except Exception:
        return False

def chrome_time(microseconds):
    try:
        dt = CHROME_EPOCH + timedelta(microseconds=int(microseconds))
        return dt if _is_valid_dt(dt) else None
    except Exception:
        return None

def firefox_time(microseconds):
    try:
        dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(microseconds))
        return dt if _is_valid_dt(dt) else None
    except Exception:
        return None

def fmt_dt(dt):
    """Format a datetime as DD/MM/YYYY HH:MM:SS. Returns 'Not valid' for
    None, out-of-range, or otherwise corrupt timestamps."""
    if dt is None:
        return "Not valid"
    try:
        if not _is_valid_dt(dt):
            return "Not valid"
        local = dt.astimezone()
        return local.strftime("%d/%m/%Y %H:%M:%S")
    except Exception:
        return "Not valid"

def domain_of(url):
    try:
        return urlparse(url).netloc or url[:40]
    except Exception:
        return url[:40]


# ─── Browser path discovery ───────────────────────────────────────────────────
class BrowserPaths:
    @staticmethod
    def get_all():
        system = platform.system()
        browsers = {}

        if system == "Windows":
            # Robust fallback: derive from USERPROFILE if LOCALAPPDATA/APPDATA are unset
            userprofile = os.environ.get("USERPROFILE", str(Path.home()))
            local  = os.environ.get("LOCALAPPDATA",  "") or \
                     os.path.join(userprofile, "AppData", "Local")
            roaming = os.environ.get("APPDATA", "") or \
                      os.path.join(userprofile, "AppData", "Roaming")

            browsers = {
                "Chrome":  [
                    os.path.join(local, "Google", "Chrome", "User Data"),
                    os.path.join(local, "Google", "Chrome Beta", "User Data"),
                    os.path.join(local, "Google", "Chrome SxS", "User Data"),  # Canary
                ],
                "Edge":    [
                    os.path.join(local, "Microsoft", "Edge", "User Data"),
                    os.path.join(local, "Microsoft", "Edge Beta", "User Data"),
                    os.path.join(local, "Microsoft", "Edge Dev", "User Data"),
                ],
                "Brave":   [
                    os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data"),
                ],
                # Opera stores History directly inside "Opera Stable" (no User Data layer)
                # Mark with prefix "OPERA_FLAT:" so reader handles it differently
                "Opera":   [
                    "OPERA_FLAT:" + os.path.join(roaming, "Opera Software", "Opera Stable"),
                    "OPERA_FLAT:" + os.path.join(local,   "Opera Software", "Opera Stable"),
                ],
                "Vivaldi": [
                    os.path.join(local, "Vivaldi", "User Data"),
                ],
                "Firefox": [
                    os.path.join(roaming, "Mozilla", "Firefox", "Profiles"),
                ],
                "Yandex": [
                    os.path.join(local, "Yandex", "YandexBrowser", "User Data"),
                ],
            }

        elif system == "Darwin":
            home = Path.home()
            browsers = {
                "Chrome":  [str(home / "Library/Application Support/Google/Chrome")],
                "Edge":    [str(home / "Library/Application Support/Microsoft Edge")],
                "Brave":   [str(home / "Library/Application Support/BraveSoftware/Brave-Browser")],
                "Opera":   [str(home / "Library/Application Support/com.operasoftware.Opera")],
                "Vivaldi": [str(home / "Library/Application Support/Vivaldi")],
                "Firefox": [str(home / "Library/Application Support/Firefox/Profiles")],
                "Safari":  [str(home / "Library/Safari")],
                "Yandex":  [str(home / "Library/Application Support/Yandex/YandexBrowser")],
            }

        else:  # Linux
            home = Path.home()
            browsers = {
                "Chrome":  [
                    str(home / ".config/google-chrome"),
                    str(home / "snap/chromium/common/chromium"),
                ],
                "Chromium": [str(home / ".config/chromium")],
                "Edge":    [str(home / ".config/microsoft-edge")],
                "Brave":   [str(home / ".config/BraveSoftware/Brave-Browser")],
                "Opera":   [str(home / ".config/opera")],
                "Vivaldi": [str(home / ".config/vivaldi")],
                "Firefox": [str(home / ".mozilla/firefox")],
                "Yandex":  [str(home / ".config/yandex-browser")],
            }

        return browsers


# ─── History Reader ───────────────────────────────────────────────────────────
class HistoryReader:

    def __init__(self, progress_cb=None, status_cb=None):
        self.progress_cb = progress_cb or (lambda v, t: None)
        self.status_cb   = status_cb   or (lambda s: None)
        self._stop = False

    def stop(self):
        self._stop = True

    def _copy_db(self, src):
        """Copy locked DB to temp location for safe reading."""
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        shutil.copy2(src, tmp.name)
        return tmp.name

    def read_chromium_profile(self, profile_dir, browser_name):
        history_file = os.path.join(profile_dir, "History")
        if not os.path.exists(history_file):
            return []

        rows = []
        tmp = None
        try:
            tmp = self._copy_db(history_file)
            self.status_cb(f"Reading {browser_name} — {os.path.basename(profile_dir)}")
            conn = sqlite3.connect(tmp)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute("""
                SELECT
                    u.url,
                    u.title,
                    u.visit_count,
                    u.typed_count,
                    u.last_visit_time,
                    v.visit_time,
                    v.from_visit,
                    v.transition,
                    ? as browser,
                    ? as profile
                FROM urls u
                LEFT JOIN visits v ON v.url = u.id
                ORDER BY v.visit_time DESC
            """, (browser_name, os.path.basename(profile_dir)))

            TRANSITION_TYPES = {
                0: "Link", 1: "Typed", 2: "Auto Bookmark", 3: "Auto Subframe",
                4: "Manual Subframe", 5: "Generated", 6: "Start Page", 7: "Form Submit",
                8: "Reload", 9: "Keyword", 10: "Keyword Generated"
            }

            for r in cur.fetchall():
                if self._stop:
                    break
                visit_dt = chrome_time(r["visit_time"]) if r["visit_time"] else \
                           chrome_time(r["last_visit_time"])
                trans = r["transition"] & 0xFF if r["transition"] else 0
                rows.append({
                    "url":         r["url"] or "",
                    "title":       r["title"] or "",
                    "visit_time":  visit_dt,
                    "visit_count": r["visit_count"] or 0,
                    "typed_count": r["typed_count"] or 0,
                    "visit_type":  TRANSITION_TYPES.get(trans, str(trans)),
                    "browser":     browser_name,
                    "profile":     r["profile"],
                    "history_file": history_file,
                })
            conn.close()
        except Exception as e:
            self.status_cb(f"  ⚠ {browser_name}: {e}")
        finally:
            if tmp and os.path.exists(tmp):
                os.unlink(tmp)
        return rows

    def read_chromium_browser(self, user_data_dir, browser_name):
        """
        Scan every subdirectory of user_data_dir that contains a 'History' file.
        Catches Default, Profile 1, Profile 2, System Profile, Guest Profile, etc.
        Also handles Opera's flat layout (History directly inside the app folder)
        via the 'OPERA_FLAT:' prefix convention set in BrowserPaths.get_all().
        """
        # ── Opera flat layout ────────────────────────────────────────────────
        if user_data_dir.startswith("OPERA_FLAT:"):
            real_dir = user_data_dir[len("OPERA_FLAT:"):]
            if not os.path.exists(real_dir):
                return []
            if os.path.isfile(os.path.join(real_dir, "History")):
                return self.read_chromium_profile(real_dir, browser_name)
            return []

        # ── Standard Chromium layout ─────────────────────────────────────────
        if not os.path.exists(user_data_dir):
            return []

        rows = []
        try:
            entries = os.listdir(user_data_dir)
        except PermissionError:
            self.status_cb(f"  ⚠ {browser_name}: permission denied — {user_data_dir}")
            return []

        # Accept any subdirectory that actually contains a History SQLite file.
        # This covers: Default, Profile 1..N, System Profile, Guest Profile, etc.
        for entry in sorted(entries):
            if self._stop:
                break
            profile_path = os.path.join(user_data_dir, entry)
            if not os.path.isdir(profile_path):
                continue
            if os.path.isfile(os.path.join(profile_path, "History")):
                rows.extend(self.read_chromium_profile(profile_path, browser_name))

        return rows

    def read_firefox_profiles(self, profiles_dir):
        if not os.path.exists(profiles_dir):
            return []
        rows = []
        for entry in os.listdir(profiles_dir):
            if self._stop:
                break
            profile_path = os.path.join(profiles_dir, entry)
            if not os.path.isdir(profile_path):
                continue
            history_file = os.path.join(profile_path, "places.sqlite")
            if not os.path.exists(history_file):
                continue
            tmp = None
            try:
                tmp = self._copy_db(history_file)
                self.status_cb(f"Reading Firefox — {entry}")
                conn = sqlite3.connect(tmp)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("""
                    SELECT
                        p.url,
                        p.title,
                        p.visit_count,
                        h.visit_date,
                        h.visit_type,
                        ? as profile
                    FROM moz_places p
                    JOIN moz_historyvisits h ON h.place_id = p.id
                    ORDER BY h.visit_date DESC
                """, (entry,))

                VISIT_TYPES = {
                    1: "Link", 2: "Typed", 3: "Bookmark", 4: "Embed",
                    5: "Redirect Permanent", 6: "Redirect Temporary",
                    7: "Download", 8: "Framed Link", 9: "Reload"
                }

                for r in cur.fetchall():
                    if self._stop:
                        break
                    rows.append({
                        "url":         r["url"] or "",
                        "title":       r["title"] or "",
                        "visit_time":  firefox_time(r["visit_date"]),
                        "visit_count": r["visit_count"] or 0,
                        "typed_count": 0,
                        "visit_type":  VISIT_TYPES.get(r["visit_type"], str(r["visit_type"])),
                        "browser":     "Firefox",
                        "profile":     r["profile"],
                        "history_file": history_file,
                    })
                conn.close()
            except Exception as e:
                self.status_cb(f"  ⚠ Firefox/{entry}: {e}")
            finally:
                if tmp and os.path.exists(tmp):
                    os.unlink(tmp)
        return rows

    def read_safari(self, safari_dir):
        """Read Safari history (macOS)."""
        history_file = os.path.join(safari_dir, "History.db")
        if not os.path.exists(history_file):
            return []
        rows = []
        tmp = None
        try:
            tmp = self._copy_db(history_file)
            self.status_cb("Reading Safari")
            conn = sqlite3.connect(tmp)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            # Safari uses Core Data; table may vary by version
            cur.execute("""
                SELECT
                    i.url,
                    v.title,
                    v.load_successful,
                    v.visit_time
                FROM history_visits v
                JOIN history_items i ON i.id = v.history_item
                ORDER BY v.visit_time DESC
            """)
            SAFARI_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
            for r in cur.fetchall():
                if self._stop:
                    break
                try:
                    dt = SAFARI_EPOCH + timedelta(seconds=float(r["visit_time"]))
                except Exception:
                    dt = None
                rows.append({
                    "url":         r["url"] or "",
                    "title":       r["title"] or "",
                    "visit_time":  dt,
                    "visit_count": 1,
                    "typed_count": 0,
                    "visit_type":  "Link",
                    "browser":     "Safari",
                    "profile":     "Default",
                    "history_file": history_file,
                })
            conn.close()
        except Exception as e:
            self.status_cb(f"  ⚠ Safari: {e}")
        finally:
            if tmp and os.path.exists(tmp):
                os.unlink(tmp)
        return rows

    def read_all(self, selected_browsers=None, days=None, date_from=None, date_to=None, custom_paths=None):
        all_rows = []
        paths = BrowserPaths.get_all()

        if custom_paths:
            paths.update(custom_paths)

        CHROMIUM_BROWSERS = ["Chrome", "Edge", "Brave", "Opera", "Vivaldi", "Chromium", "Yandex"]

        browser_list = list(paths.keys())
        total = len(browser_list)

        for i, (browser, dirs) in enumerate(paths.items()):
            if self._stop:
                break
            if selected_browsers and browser not in selected_browsers:
                self.progress_cb(i + 1, total)
                continue

            self.progress_cb(i + 1, total)

            for d in dirs:
                if self._stop:
                    break
                try:
                    if browser == "Firefox":
                        all_rows.extend(self.read_firefox_profiles(d))
                    elif browser == "Safari":
                        all_rows.extend(self.read_safari(d))
                    elif browser in CHROMIUM_BROWSERS:
                        all_rows.extend(self.read_chromium_browser(d, browser))
                except Exception as e:
                    self.status_cb(f"  ✗ {browser}: {e}")

        # ─── Date filter ──────────────────────────────────────────────────
        if days is not None:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            all_rows = [r for r in all_rows if r["visit_time"] and r["visit_time"] >= cutoff]

        if date_from:
            all_rows = [r for r in all_rows if r["visit_time"] and r["visit_time"] >= date_from]
        if date_to:
            all_rows = [r for r in all_rows if r["visit_time"] and r["visit_time"] <= date_to]

        # ─── Sort by visit time desc ───────────────────────────────────────
        all_rows.sort(key=lambda r: r["visit_time"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)

        self.progress_cb(total, total)
        self.status_cb(f"Done — {len(all_rows):,} records loaded")
        return all_rows


# ─── BEC IOC Engine ───────────────────────────────────────────────────────────
# Each rule: (category, severity, label, list_of_patterns)
# Patterns are checked against the full URL (lowercase).
# severity: "critical" | "high" | "medium" | "info"

BEC_RULES = [

    # ── Microsoft Identity / Authentication ───────────────────────────────────
    ("Microsoft Auth", "critical",
     "OAuth Token / Consent Grant",
     ["login.microsoftonline.com/common/oauth2",
      "login.microsoftonline.com/organizations/oauth2",
      "login.live.com/oauth20",
      "accounts.microsoft.com/oauth"]),

    ("Microsoft Auth", "critical",
     "Microsoft Login Portal",
     ["login.microsoftonline.com",
      "login.live.com",
      "login.microsoft.com",
      "account.live.com/password",
      "msft.sts."]),

    ("Microsoft Auth", "high",
     "MFA / Conditional Access Challenge",
     ["login.microsoftonline.com/common/deviceauth",
      "mysignins.microsoft.com",
      "aka.ms/mfasetup",
      "account.microsoft.com/security",
      "login.microsoftonline.com/common/proofup"]),

    ("Microsoft Auth", "high",
     "Azure AD / Entra Admin",
     ["portal.azure.com",
      "entra.microsoft.com",
      "aad.portal.azure.com",
      "admin.microsoft.com"]),

    # ── Microsoft 365 Services ────────────────────────────────────────────────
    ("Microsoft 365", "high",
     "SharePoint / OneDrive Access",
     ["-my.sharepoint.com",
      "-sharepoint.com",
      "onedrive.live.com",
      "1drv.ms",
      "sharepoint.com/sites",
      "sharepoint.com/personal"]),

    ("Microsoft 365", "high",
     "Outlook / Exchange Web Access",
     ["outlook.office365.com",
      "outlook.office.com",
      "outlook.live.com",
      "mail.office365.com",
      "owa/",
      "substrate.office.com"]),

    ("Microsoft 365", "medium",
     "Teams / Collaboration",
     ["teams.microsoft.com",
      "teams.live.com",
      "meet.google.com"]),

    ("Microsoft 365", "medium",
     "Microsoft Forms / Power Apps",
     ["forms.office.com",
      "forms.microsoft.com",
      "make.powerapps.com",
      "flow.microsoft.com"]),

    # ── Document Signing & eSignature ─────────────────────────────────────────
    ("eSignature", "critical",
     "DocuSign",
     ["docusign.com",
      "docusign.net",
      "app.docusign.com",
      "account.docusign.com",
      "na3.docusign.net",
      "eu1.docusign.net"]),

    ("eSignature", "high",
     "Adobe Sign / Acrobat Sign",
     ["adobesign.com",
      "echosign.com",
      "sign.adobe.com",
      "acrobat.adobe.com/sign"]),

    ("eSignature", "high",
     "HelloSign / Dropbox Sign",
     ["hellosign.com",
      "dropboxsign.com",
      "sign.dropbox.com"]),

    ("eSignature", "medium",
     "Other eSignature Services",
     ["signnow.com",
      "pandadoc.com",
      "rightsignature.com",
      "signable.co.uk",
      "onespan.com",
      "esignlive.com"]),

    # ── File Sharing & Exfiltration ───────────────────────────────────────────
    ("File Sharing", "high",
     "WeTransfer",
     ["wetransfer.com",
      "we.tl/"]),

    ("File Sharing", "high",
     "Dropbox",
     ["dropbox.com/s/",
      "dropbox.com/sh/",
      "dl.dropboxusercontent.com",
      "dropbox.com/scl/"]),

    ("File Sharing", "high",
     "Google Drive / Docs",
     ["drive.google.com",
      "docs.google.com",
      "sheets.google.com",
      "slides.google.com"]),

    ("File Sharing", "medium",
     "Box",
     ["app.box.com",
      "box.com/s/",
      "boxcn.net"]),

    ("File Sharing", "medium",
     "Sendspace / Filebin / Temp Share",
     ["sendspace.com",
      "filebin.net",
      "filedropper.com",
      "transfer.sh",
      "gofile.io",
      "anonfiles.com",
      "buzzheavier.com"]),

    # ── Banking & Financial Redirect ──────────────────────────────────────────
    ("Financial", "critical",
     "Banking Portal Access",
     ["online.anz.com.au",
      "internetbanking.commbank.com.au",
      "nab.com.au/personal/online-banking",
      "westpac.com.au/online-banking",
      "banking.westpac.com.au",
      "ib.nab.com.au",
      "netbank.commbank.com.au",
      "secure.hsbc.com",
      "online.barclays.co.uk",
      "bankofamerica.com/online-banking",
      "chase.com/digital/login",
      "wellsfargo.com/auth",
      "citibank.com/login",
      "secure.paypal.com"]),

    ("Financial", "critical",
     "Wire Transfer / Payment Portals",
     ["anz.com.au/transfer",
      "commbank.com.au/transfer",
      "westpac.com.au/transfer",
      "paypal.com/myaccount/transfer",
      "wise.com/send",
      "transferwise.com/send",
      "remitly.com",
      "xe.com/send"]),

    # ── Credential Phishing Infrastructure ───────────────────────────────────
    ("Phishing Infrastructure", "critical",
     "URL Shortener (common in phishing)",
     ["bit.ly/",
      "tinyurl.com/",
      "t.co/",
      "ow.ly/",
      "buff.ly/",
      "shorturl.at/",
      "rb.gy/",
      "cutt.ly/",
      "tiny.cc/",
      "is.gd/",
      "v.gd/",
      "soo.gd/"]),

    ("Phishing Infrastructure", "critical",
     "Ngrok / Tunneling Services",
     ["ngrok.io",
      "ngrok-free.app",
      "trycloudflare.com",
      "pagekite.me",
      "localtunnel.me"]),

    ("Phishing Infrastructure", "high",
     "Suspicious Login Pages",
     ["microsoftonline-login.",
      "microsoft-login.",
      "office365-login.",
      "outlook-login.",
      "office-365-",
      "microsoft365-",
      "0ffice365.",
      "mlcrosoft.",
      "micros0ft."]),

    ("Phishing Infrastructure", "high",
     "EvilGinx / AiTM Proxy Indicators",
     ["evilginx",
      "/signin/v2/identifier",
      "login-live.",
      "live-login.",
      "microsoft-online.",
      "microsoftonlne.",
      "0utlook.",
      "0ffice."]),

    # ── Remote Access & VPN ───────────────────────────────────────────────────
    ("Remote Access", "high",
     "Anydesk / TeamViewer / Remote Tools",
     ["anydesk.com",
      "teamviewer.com",
      "screenconnect.com",
      "connectwise.com/remotecontrol",
      "logmein.com",
      "goto.com/remote"]),

    ("Remote Access", "medium",
     "VPN / Proxy Services",
     ["nordvpn.com",
      "expressvpn.com",
      "protonvpn.com",
      "mullvad.net",
      "hide.me",
      "surfshark.com",
      "cyberghostvpn.com"]),

    # ── Email Infrastructure Abuse ────────────────────────────────────────────
    ("Email Infrastructure", "high",
     "Email Client / Webmail (non-corporate)",
     ["mail.google.com",
      "gmail.com",
      "mail.yahoo.com",
      "mail.proton.me",
      "protonmail.com",
      "tutanota.com",
      "tutamail.com",
      "temp-mail.org",
      "guerrillamail.com",
      "10minutemail.com",
      "mailinator.com",
      "yopmail.com"]),

    ("Email Infrastructure", "high",
     "SMTP / Email Sending Services",
     ["sendgrid.com",
      "mailchimp.com",
      "constantcontact.com",
      "klaviyo.com",
      "mailgun.com",
      "smtp2go.com",
      "postmarkapp.com",
      "sparkpost.com"]),

    # ── Crypto / Money Laundering ─────────────────────────────────────────────
    ("Cryptocurrency", "high",
     "Crypto Exchange Access",
     ["coinbase.com",
      "binance.com",
      "kraken.com",
      "crypto.com",
      "bybit.com",
      "kucoin.com",
      "bitfinex.com",
      "blockchain.com/wallet",
      "localbitcoins.com"]),

    # ── Collaboration / Project Tools (data staging) ──────────────────────────
    ("Collaboration", "medium",
     "Notion / Confluence (data staging)",
     ["notion.so",
      "notion.site",
      "confluence.atlassian.net"]),

    ("Collaboration", "medium",
     "Pastebin / Code Sharing",
     ["pastebin.com",
      "paste.ee",
      "hastebin.com",
      "ghostbin.co",
      "privatebin.net",
      "gist.github.com",
      "rentry.co"]),

    # ── Misc Suspicious ───────────────────────────────────────────────────────
    ("Suspicious", "high",
     "IP Address Direct Access (no hostname)",
     []),   # handled specially in code

    ("Suspicious", "medium",
     "Newly Registered Domain Indicators",
     [".xyz/",
      ".top/",
      ".club/",
      ".work/",
      ".online/",
      ".site/",
      ".icu/"]),

    # ── OAuth Device Code Phishing ────────────────────────────────────────────
    # Legitimate device code flow should NEVER appear in a desktop browser
    # session — it's only used by TVs, printers etc. Presence = phishing signal.
    ("OAuth / Device Code Phishing", "critical",
     "Microsoft Device Code Auth (AiTM / PhaaS indicator)",
     ["microsoft.com/devicelogin",
      "login.microsoftonline.com/common/oauth2/deviceauth",
      "login.microsoftonline.com/organizations/oauth2/deviceauth",
      "microsoftonline.com/common/deviceauth"]),

    # ── Cloudflare Workers Abuse ──────────────────────────────────────────────
    # workers.dev is free Cloudflare hosting — legitimate enterprises almost
    # never surface it in browser history; very high signal for AiTM proxies.
    ("Phishing Infrastructure", "critical",
     "Cloudflare Workers Domain (AiTM Proxy Indicator)",
     [".workers.dev/"]),

    # ── railway.app Hosting ───────────────────────────────────────────────────
    # Niche developer hosting platform observed in Tycoon 2FA / EvilTokens
    # redirect chains. Legitimate enterprise use is negligible.
    ("Phishing Infrastructure", "high",
     "Railway.app Hosting (Phishing Redirect Infrastructure)",
     ["railway.app"]),

    # ── Milanote LOTS Lure ────────────────────────────────────────────────────
    # Darktrace confirmed Milanote used as lure delivery in AiTM campaigns.
    # Legitimate corporate use is rare enough to be noteworthy.
    ("Phishing Infrastructure", "high",
     "Milanote (Living-off-Trusted-Services Lure Platform)",
     ["milanote.com/m/",
      "milanote.com/plan/"]),

    # ── Adobe Acrobat Share Links ─────────────────────────────────────────────
    # Scoped to the specific Acrobat share/URN path used to host phishing HTML.
    # Does NOT flag acrobat.adobe.com broadly — only the share URL pattern.
    ("Phishing Infrastructure", "high",
     "Adobe Acrobat Share URL (LOTS Phishing Host)",
     ["acrobat.adobe.com/id/urn:",
      "acrobat.adobe.com/link/review",
      "acrobat.adobe.com/link/share"]),

    # ── Slack Phishing Delivery Patterns ─────────────────────────────────────
    # Flags attacker-constructed redirect paths observed in Okta research.
    # These path patterns do NOT appear on legitimate slack.com domains.
    ("Phishing Infrastructure", "high",
     "Slack-Themed Phishing Redirect (Non-Slack Domain)",
     ["/slack/connection/",
      "/integration/slack/",
      "/integration/payroll/"]),

    # ── Okta Phishing / Impersonation ─────────────────────────────────────────
    # Okta login pages on non-okta.com domains = clear phishing signal.
    # Legitimate Okta tenants use *.okta.com or *.okta-emea.com.
    ("Phishing Infrastructure", "critical",
     "Okta Login Page (Non-Okta Domain — Credential Harvesting)",
     ["okta-login.",
      "okta.login.",
      "login-okta.",
      "/okta/login",
      "/okta/signin"]),

    # ── Mamba 2FA / EvilProxy / EvilTokens ───────────────────────────────────
    # Kit-specific strings found in URLs — zero legitimate use.
    ("Phishing Infrastructure", "critical",
     "Known PhaaS Kit Indicators (Mamba 2FA / EvilProxy / EvilTokens)",
     ["mamba2fa",
      "evil-proxy",
      "evilproxy",
      "eviltokens",
      "eviltoken",
      "tycoon2fa",
      "tycoon-2fa"]),

    # ── Gift Card Cash-Out Pages ──────────────────────────────────────────────
    # Scoped to the specific purchase/redemption paths, not the homepage.
    # Gift cards account for 59% of BEC cash-outs (Fortra/APWG 2025).
    ("Financial", "high",
     "Gift Card Purchase / Redemption (BEC Cash-Out Vector)",
     ["apple.com/shop/buy-giftcard",
      "amazon.com/gift-cards/buy",
      "amazon.com/dp/B004LLIKVU",
      "store.steampowered.com/digitalgiftcards",
      "play.google.com/store/account/redeem",
      "account.microsoft.com/billing/redeem",
      "bestbuy.com/site/gift-cards"]),

    # ── Microsoft Forms Phishing Delivery ─────────────────────────────────────
    # Microsoft Forms is already in Microsoft 365 category but the specific
    # pattern of Forms used as a phishing lure delivery page is worth flagging
    # at higher severity based on 2025 Microsoft TI reporting.
    ("Microsoft Auth", "high",
     "Microsoft Forms Phishing Lure (Credential Harvest via Forms)",
     ["forms.office.com/pages/responsepage",
      "forms.microsoft.com/pages/responsepage",
      "forms.office.com/r/"]),

]


def run_bec_analysis(rows):
    """
    Run BEC IOC rules against a list of history rows.
    Returns a list of finding dicts:
      { category, severity, label, url, title, visit_time, browser, profile }
    """
    import re as _re
    IP_RE = _re.compile(
        r"https?://(\d{1,3}\.){3}\d{1,3}[:/]"
    )

    findings = []
    seen = set()   # deduplicate (rule_label, url) pairs

    for row in rows:
        url = row.get("url", "").lower()
        if not url:
            continue

        for category, severity, label, patterns in BEC_RULES:
            matched = False

            # Special case: direct IP access
            if label == "IP Address Direct Access (no hostname)":
                if IP_RE.match(url):
                    matched = True
            else:
                for pat in patterns:
                    if pat.lower() in url:
                        matched = True
                        break

            if matched:
                dedup_key = (label, row["url"])
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append({
                    "category":   category,
                    "severity":   severity,
                    "label":      label,
                    "url":        row["url"],
                    "title":      row.get("title", ""),
                    "visit_time": row.get("visit_time"),
                    "browser":    row.get("browser", ""),
                    "profile":    row.get("profile", ""),
                })

    # Sort: critical first, then high, medium, info
    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["category"]))
    return findings


SEV_COLORS = {
    "critical": "#E95555",   # crimson
    "high":     "#DCA032",   # amber
    "medium":   "#6374F8",   # iris
    "info":     "#2EAD7A",   # emerald
}

SEV_BG = {
    "critical": "#FFF0F0",
    "high":     "#FFF8EC",
    "medium":   "#ECEFFE",
    "info":     "#EDFAF4",
}


# ─── Design tokens (MIA-style: light canvas + navy sidebar + iris accent) ──────
C = {
    "bg":         "#F5F6FA",   # light canvas
    "sidebar":    "#181B25",   # dark nav rail
    "sidebar_b":  "#1A1D27",
    "accent":     "#6374F8",   # iris
    "accent_dk":  "#4A57D4",   # indigo hover
    "accent_lite":"#2A2E45",   # active nav bg
    "navy":       "#1A1D27",
    "text":       "#1A1D27",
    "muted":      "#8C90A4",
    "border":     "#E4E6EF",
    "row_alt":    "#FAFBFD",
    "row_sel":    "#E0E4FE",
    "green":      "#2EAD7A",
    "amber":      "#DCA032",
    "red":        "#E95555",
    "white":      "#FFFFFF",
    "card":       "#FFFFFF",
    "tbl_hdr":    "#F0F1F8",
}

FONTS = {
    "h1":    ("Segoe UI", 17, "bold"),
    "h2":    ("Segoe UI", 13, "bold"),
    "h3":    ("Segoe UI", 11, "bold"),
    "body":  ("Segoe UI", 10),
    "small": ("Segoe UI", 9),
    "mono":  ("Consolas", 9),
    "tag":   ("Segoe UI", 8, "bold"),
}

BROWSER_ICONS = {
    "Chrome": "🟡", "Chromium": "🔵", "Edge": "🌀",
    "Brave": "🦁", "Opera": "🔴", "Vivaldi": "🎭",
    "Firefox": "🦊", "Safari": "🧭", "Yandex": "🟥",
}

BROWSER_COLORS = {
    "Chrome":   "#F2A93B",
    "Chromium": "#F2A93B",
    "Edge":     "#4FC3F7",
    "Brave":    "#FF6B6B",
    "Opera":    "#FF4040",
    "Vivaldi":  "#EF5298",
    "Firefox":  "#FF9D55",
    "Safari":   "#81C784",
    "Yandex":   "#FF3333",
}


BROWSER_ICON_B64 = {
    "brave": "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAEmUlEQVR4nG2UW4zdVRXGf2vvfe4HptfRtkyxKhamLSTYBFJMT7lMalUoKDNe0lR8UIzGECLCAyRlQoIhUSBKSIEACV4epmCjhkibBiXWQkvSUGlVHLWtzkCnnc7ldM4587/stXyYGYLE7219a60vO3ut9QmA7cLJIMo8zvVf/umLCL/Ocv1IniCk5mImkqoqmHkYb8f8tjWH/vn6Qs+8hskC0ezv7Q24rtSX6gXLfx5EuttJNBcRbWXEDHLvycysICKqOpEG93WXpk1Rpnv+NHwMQACm+9f9sOTlPsSJttsQc2aTzCQiRIFSFzF3JFMTxJiTqVmpEER8wNdqODPaMT5+6Yrhe2R6YN0vLy76rzZzMZ0at2LflyVctw07PSw6fgb/iQ2EdRsx50nfPkpy/CiyaAnhsl6bPXKQ6Rd2m1+ylMUOdz6LvwqKnczNqU6NW3HTZ33lrkcQH+Cam/gwKit7qGzdvhBKbXMf1pqR5ks/i8my5VGw4eAkdJF2nP/kuli553FIOqQHXiQ7/CqWJBSu3Urp1p3gPO29v6C1/zeoOMqbtlC/eYCl9z9COnJK9PhRR7GylOmvXNm68PkeSw8fUDMzy1IzVYtjIza79zlrfmubWZaZmdm5b2y35vNPWDZy2ixGs3yOnz3+lp26epWd3Hx54szsjVKlSrL3GbPmBIQCaMR1r6J4/a0Urv4MiECMlDZeR+WmLxBWrQZT8AFtt5h86sdaKhYROOSwOOTLZbJjh2g9sAM9Owo+gBmth74N1Sp4D97juj/K+R98E4sRfCBOjDP23a/Rem0/oVLBVIdkor93tUdOhBDq2UzT3LIVUn3wefzqT5HuGyJ99be4+jJUCqRnRilu7qN++07yM+8y9r0dpCeHrdC1WPIsbRHcerdkz1/+DRwui0G1ptachCQBVYpbB6g9uBtTxSbGWfTwk9QH7pibccyIk+eRal0rKCa8uea1d065+cN52XkHSWJu+Ur8ZRvAzaV07F30vf8Qx0aJo6fnyp0j9KwhXHIplnSs6BzOeBkgAIiTV1pJ9iMplX0cPUnnifspbNlOdmg/eupfFPtuwUKZmWd/gnSvoHzDNjp/PED61z/jKjXfzHJz6l8BEJs/v6nbe9+qBb+hHc1ozzgpVal8/1EKm7b+z3InR9/g7L13Es+fhYu6tCK4jtqJj9349ysZxByNhhcwQX5X8CKmGqV2MYiQDD1FduQP74ulx96k+fRjWJrguxaDaaw4h5jtk0GURsOL7cIxiF344vq1vmBveyR0cs0dLuhMC1KlvPNurFRn+qcPk6cJWq2jqnnJu2CGxlyu6nn9byfYhcgH/XCyf/1tVcfuonfdzdmIqkTJzOtkk5gaeaVG7lyMMbpFwUsSdbxlfOfjB9/Zs6Dxvh8uEKdvWbtyebnwAMqdZcRNd6JaJhIzIYu51Zy4VlQDe+Zcog9ddeQfIwZOmDNo+eCHWz9e9hABpr60fmNRbdBH+VzaUWJmCJCo7Us07uo5OHwYYKgfPzDf839hINZohIX4ws1X7Jjp6x2Z3nLFe2ONtXcs8L9vNIJ96EEA/wV6G2jfgmsKBQAAAABJRU5ErkJggg==",
    "chrome": "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAEjUlEQVR4nG2UTWyUVRSG3/fc74dpC7UtLRSbgBYE4w9iCyYGJagBqkZBMg2JuNFo3KAulIWGYlEh/i0w4u/CyMLANBoVMaAGE0jUoCWaKKAY0QZFQAqdtjP95vvuOS6GiSx8N+du7nOf3Lw5xEWxPBwH4At5uMVDV90N4J6M6AakjSSc46lA+J1CPnh9/6GP+gG1fN5xYMDXGKwdCnm43gH4X7uv6Ikl2OSE3YEIMgOUBGkIRBCJg1ZvHpzw3HDpgcHPCvm8670AZdWs+sqxrrn9U5zrUxIlNRXSIBQhQQIgIYSC5OQwEEfBmGrf9C8Hn6kxWKMfWTBn07Qo3DCceQ8KROjogirIe5CESAiSIBUGqhNaaxy50xO+b8aBb6tQADg7a9bySmtuT0k1VTAQIcU5+LExGIm4qcnoDL5yDk5IiS6xC6LmhL4+DMJixd/a/vmhfYRtjZ9+dODbh/efvrroqAI6cYJsdAzNy5dZy71rkbTPhoRmoT8CPf4akpMf0YWTYaYA1McxXJLoD3HHxCJ27ViVT3NhYcsbR/38E2VXrougI0XMePwJHV27ji/uzXjwWAkEsKizHuuXO0wb3qjp0U0iUT2gGQymQWiSlXSlSKprPGHvLp2uWeDMj4yguafHxu5fJz1bTnHbrr/x89A4jgyN49VP/8LtL57GyaZ+Sutd5stlmMYwHxjozMStkRToyo2mHJxZH3xxdaPVJ4apD9yP53elOPJnio6pESZFglwk6GiJ8eOfCV7ek9HNfgQKAhQAIvCOMNctAKZ6VcSZcvvCRo7PbNOkeRa+OlrClDqHJDOoAWpAJTNMyQX4+lgZGecimNRqMAXEwbwAIq2iavRmiBKPP1oiFhY2W1xReKJamf+JmVUrTFczrE2Kqf0DAh5mDSnxXoeXs+603nxZDudKHnFQBZNAFBDFcoZFnXUI8CuyyjlCYgACOgfQnRE1PQRH82bq1DAaGp/95UM+c3uEOdNCDA2nSFJFkiqGhiuY1x7hyTsCy35/2xwvWIooImcUNxiA2KmqK6HGFB6XhPUoHN4n81vn6oH1a7h5d8JvjpcBAIs7c3hsRYzhk2/4KSd3uzBqhlkGmCPUCMNOznxnyaS6NPe9xO4KP5FZ9UOAkYlxrL5yqT543So0RR2EAWeSP/Dm4Af2oG1Hd7OT1AM074McJCvpT0FLUxcBYN5by+6UumiXL6WpeQsAkCTOl0dBiLXVNcLB8NP5ItdNP6svzUukUgEE3kjLXD3DrOhXhEtO7JV8Ie+OPvTZJ7448YLUh6HBvKqq9x6NcQMawkksJuM8VS7xmsmBbbic9F4AUCniXVMYZkV7LlxyYq8V4AiAKOQFvQN+zmu3PS+5cL2mHppkajDAQEfwTIX2Sud5va99jEmFiOsgCICsmG4Ob/rtKSvAsRf+v6Zt3Cjo79fObbeshJN+ENfCAHpFsWK4oSHFxwtGgACAKlT1e61oX3jjz7vMIGRt716cQt6hd8DP3roi1jBbbaqrqXr9WGqtO64at6VtyZnU45AA77vj/n32Hq7UzGqIfwHwRED0B3vxXAAAAABJRU5ErkJggg==",
    "edge": "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAEvklEQVR4nG2VW4hVZRiG3+/711r7MHs7o854ukgv8kBUGl5E2Mmg6LrY2zIoAlEwFSLDoGCxb4LuOgoG5UUlNruiIBOMAjtDhDYqOZ7z3OyZvWef91r//39fF0YH6Ll/n8vnJfyL0vi4qZbLfuWn3xWzC5c+BnWPiiarRZIxICGmpAGTTJJJD4W28eEv6544CQCxxlyhigAA3VApIQahQrL229pGDSimgFaIOojtQySBwgFswaGFCfsI9Y92Lmq9h1ojPrx+53RpvGSq5aonqFKpCq6Wya/9pvFmUBx+xvfb8ElHlAQgISVHAgchq9BEw6Ch+eyMKYw6mKR2npLOI1/c+tLRWGOm0riaapn82q9m3orG5m11zZYlVqMkLOogkkLEQslByAFIkAmnkYumNBvWXWHEhkY60zpwd36yonKeAOCOr2c25BfO22/rTZu0O6Ht9qDiwFmDoBiBcwG8SyCaApwgF04hn6khFzWQCZt2zpiGvtk+vO/d3AO08tPfisMLFh3rznRvqk2c1qSTMBQgBpiBMFTNLR7yhRXzgRAG0qN85h9hLmojF3b80AhM0rKPB3NvWrChdmp66ZUfJsUU5nBQGAOHEZgJJKkKlLrTPkh7DYzcnoXJDFTVkqoDVAAIFEpQVTKyLbg6cX5DbTJRM3eJmvwQYAzUEBSqVBwlHbSmOervS2pttI51Ns6/KxpV31dVR6IeXhTOM/c6DuLpjmD6THe1hvNIMxF7JbAoSEUpl4e9dPa61q/c09pdPgMAxR2H3iyuan4bjtoF3g/UiSPnBUwKTQQgzbOT4jwNIohXUq8QL9Ag4/21y2S/+Xx/a3f5DJ7am126d2+2/fpDp4No6gPKeHIy8N4lsC5Fap2mKpKk6WwgJqvkBcyAAGBiSLcNOnkUNGesj9K4wYUTbtky4HcAQVgXaATv27CcgiiFirVcpMgOBh+xqs4oGYioihcIBZDrFwk2BeeG16Fa9lh5jQ6vr7g1Pz6/nKPmFu1dFdVZWNf01jYVc9KoW2+c8ta+yKp6VDlUFYgKIF6AZt1AIQhydxdKe+7G229bbN4Thj4dMjx7jXmGw6FWwPm2cdyV/mzrQNK0D3655v0p4hePP41o6F1Ku0JMTEGIYPIHBN2uID9CEHshkOT+RnXLRQBYGt+XXfTw4tXikiUwAZwzZ4/cu38CABDHTNh6vEDDmKAou4zsQCmT4eDszwhbdSAqCLFheHdJxG7vfLz5M/wPN29/LVM/1x6tH3jpyo3avDBRoqH549RvWAqjwEydo8zlk0B+LuCtEBsmENQlPwF6gNSeMGy7CozA8W1w/klJW881v6x8RBhXgzJ57Pr1DSou3Ea9uiO1nJ38npkCwIQgbxWqSkHEBAa8BfkUAMDZYfjm5XdmD+7ahFLJMMoQlMYNXlm9XXv1NzRbDCQ7zOmSVaJJW+BTBRsCEasdeE06qdq+VQBgA9+59urswV2bEMeMalUYIEW1LIhjxsu37NBecyPSdNItXM7JinWsBELaA8QBxIaCTERhJgR0Era3cfbznc8ijhmVit4o9X8/wKBa9oiPF9gGj2km+yj3m2vCmYtjplsH27RG3h0h7z6JZqf31w5XOn9v/uJPdEHQ9BBSQL4AAAAASUVORK5CYII=",
    "firefox": "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAEaElEQVR4nI2UW4hVZRTHf9/37X1us89cncnLqIzWpCRiGppgaeh0ASPBjpRUmA/5mEIYhDKJFAThQ0J0eSgwCmaIQKOsCDPtQoyhUo5mSjoDM3PGc+bMnHPm7HP23t/qYSZHo4fWy4LF+v/5sWD94X+UCBpAck/Ml/KWPsk/ulwEJZIx/97Vtwm70dI9LRbUTO9GhrrqIPiUlFlF1R5UCoGsEqb2/otCzRh365n5egdArm/cL9HjIiOP+FLdLHJ1w16Avr5V7q3am2QAcnjOSjkybzeAfDO3RY6srj+x/oQjR19IRf0PDESDXZEMbAplqCuU0S6RC+s23/SYJlX/mDHU2cyK8Qskw5NcWnuIzvz7PP/jOqUoyGV3JdGSM8QRrKeQhMUzmmKUJYq/ghc7rdqPXhLp1kp6MGobUbS342O9wH8aW71uo9ktOhnXp3r3r8gWFm5raatkUrNHl3kLL6lFm75ViTkFCNKWOlczIVetq/v1XZUn4WR16vDPrVnOHflzJCuWdE1TX4OWMLhyfqt//st3064xEJSxIdR1nGXlM+/Q2DmI0inB6sCmlavFf0otOtHjAFgbbtVRDKqhJakVVRduhO7ipUfdeJ0f9p/Zo2tjd+p4ENK+9jecZh/GHTCiiGmtk0ZRlC1AjwbQVXMfRRerHMXdkaIzoVjYAI110v7QMWfN9tf0eMow4abpP74VwUE1TCJjBgpKUxJs5C4TQU0R+u5cXRF0Nq7kVwVLathWh77zz6qB0v3kR9YQOI149WXCkVYufrGJ1TvfBL8JW3aVnjsJvm7js43NDihsMaF0TCCK4IqBZMSRr3fw/cXtpOY3kPTiNHg1It9BxULGcvVQCLBFhTWgowrk6w1+zHEAqrmmkuOFEFghHsJwkj+HW6ilrqETHoHTQmhTiAYdJjDOCGQVYS6JszgnTCglY7Ecxet5DcLkaNNZip5QdUQqcVRW09X6A2PVGqXCOJOTWSb9LGPlccpRliVNp+FqIyaZw6iikK0TbqjLateZQAOURluPRcPNCt9oVXGRiXrW+7+zo+k4ki9RGCkzmivij43w2Ky3aQ//QEouTlSCrCMMeIq8Ojr1KYiC78xAQ++5+R0jS0kVLK4YiYWoeIVBO4eLQTtGW+6JX6MtNYB4cVS9gnosQTO1QnMuNmuokwMnx5WQMYre6Fr8pYcb0v5XyXmDYSxZMWirrGPR8Qq4NTAWlMHiorWFtJVAp0K3vMitJSo74x998oFkMmbqU+gxim3RX6nd3bMS9tWwdch6XkWMExq0xRoBY9HGgokAG1XGPUlOdjiTXuW9up8/3CWZjFG9vdFMZE2TDqb27HNMeDBRV8Gmi8QSVes6oShtESvUAteYiWaYaKLqhm81jR5+UcgY6LUK5LYcE7q14oDNei8/GNravkDXNiQdXKMFhUIigx/qKC7uTzYWvdFWOPT5zdgCme7/CtppUoCxhn33RmGwrkq4QKOJ4Qwbo041Trz+y60At+r/BkySJoAVpjOqAAAAAElFTkSuQmCC",
    "opera": "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAD8ElEQVR4nH2UTYjVVRjGn/c95//l3HsnR1FzGhGaTGgMxS8waNJdjRSC101tglZBEUiSGMhERrUoaueiVYtg7mBmIYiBY2AfQmEUlIvMFqmhTjOjc2fmf895nxZ37qgT9azP+Z3nfR7OK7hLRN0JGpH9/Rlmu/aCrBu4SSErIQqIXoPgAtQfw8CTo/LFcHMEcPuA2GHIHRicAJG9A08BegQiG9snBIgtXJ69hatlk6XFKSeaVtT9WvXJ6/1/XzlJUAWwBeCCs9UbDsG5N0HCGIOK81fmbl/+7vbVc3+VTXro9orqQ02Suah0OY9S8Ma+mZnD804NRN0BAFcP7GffJrJ3ILB3oGTfRk6tWv/RYWD5whT9/dnxavXVz2s1O16tlqOVSjhdrXK0UjkMACPtKQGufHQ7EnwLMgAE1HvEMCpXfq4DAoKuAaAOmAA80dPzclX1g2kyKIBcxDfJXbtv3jyjBASOb0OknaSog8WbMP8iASHoBIid4I8CydPj4x/GJBlbluc+TVMrsgx5mr5zBvCK+x/ZAZXHYcZ2CSogP5ZrF64Dg07ubZDrABKQzPv38jRFnqbevLdalm1N1q7dpVDdA4gaaAZR0BCEJwgIsIJYpCeAKACLJPnKvL9Ry3Mt0tRqeY4iTfdqoG0BiUhCCQ0Wp72GiwIQaNhioMw73HLp0mSeZRdr7XGZpCmKNN2owVDtAAkiElMIlYnFoHtUrysAFFl2vZLnKPIceZIgz7KKDySMhkDCzYOvoSX/C5xXkSRSeI8yRmSqkBjFt8wmAxQtEgZDJLtrceY+ANP/SWq0o8iybEXiHIoYUahCzKY0kOeDEaUZZiyaB5Y0Rda3S4EuZrH9GTkxNLS0SJKHNUmQpalkeY4lafq9zlp5bDwGK406Z2Y0omm2RwCOYfDfow8OOgLSTe7Mu7p6xLlYJInCOTjvR3XN+O/nmzGeTgiZs8gbMTAYn/ul6Fu9E2dD52t23AHtpiGyHyQUiEgSBXnOb9s2pgDQQnxtIobYitBbMUaQ3TFxR9uXG5GAsl53AlDOng0cGjoI73cgxABVBQmQB2R42HQEcAOTf1yYaIWXxMyV0fR6aJWI3P3jsgc/4QvPPiCASaMRf9u8uTsODQ1D9S2E0IKKIkk8QjggJ09+Pf/onV34Zdr7SiHyvgPQhIUC6rOlS66tW9/3TVdPFQA2w7k1aAUDoOVsaUI7mJ469S7rdSeNRlwIvbN5T/hVgzlxhILHBAJGQ5ElWLq8hqJaQJ1OkpbNtcIP09Ozh7b+eXFspF53+xqNOJ/vHd21zuVTt+IZM9YJbGjRuiMMhE0q8FOJ8tjzmPkMQOg46zD+Aeqt98G+6J1aAAAAAElFTkSuQmCC",
    "safari": "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAEv0lEQVR4nGXUS2yc1RXA8f+53523PeNJ7DzGiaFEUBKBXUUQJY0oCAFZBBYgBJQCKpUqgmCFBBIEIRYtVVUkFiy6qVQWBCljRahAkIII4h1CKIKoaWwCiWNjJ+DY87Bnvpm5372HRTECelZnc3678xd+NKoaiYj/fq8Au6ZqYfti228EWJWXmYvL9ihwSERmf34DID/HVHWw1Qt7X59IfjdZs0O1nhAnHmMgnTKsyii/LCfzN1+W2ZezS8+IFOd/jMpPsfbOj6fTL718KhqZvdCiq71g06pxUDFGyVjRnlPJRGmzYXWR2y5lets6d7dI+oMVw1ar1RVsx+HJ1Bv/OBbymdSSawW19aCmvhQIUQADIjCQElaFWKdaNnn2PT/ywFjqDdXeDSJypFqtRqKqBprlo1+mjj/3nlQK2U4y3cEuBk/HBEw6gFU0Uowq3itx32pu+uoTBs+cSiauv9c+Ntqd23axH4VizYhIaDTkyVdP5iopbbjpprPzHUeXgM0opBUyAZtK6BYMcTnPQ59WuevA3zg2do0tRLF79etCpdGQJ0UkWFVd9/KRC/efOrusLvJ2sSMkKTAiBIAIjPUs9OUYac7zpzf3s/VfL/LbPzzPzKphSvGSneqKvj0Vfq+6/FcL9d2nF2wpjuuhFVkTOyWyQvAgQVCFxVyOW778mKffPUD/4UPs3fVHTm67jv5zi9SzWSl5F063CgN0GrvtuW+SHXMXvFqcLrUDGEE94CEkkGiKP7/1Ivf95x0WTkxS3TjK63c+SH+zRogiml1lTV50vmV0tqY7TKPlh1vtWJxz4lwC3qEuwXhPfbnHg5dkue/GUc5MTDFZb/PPPU+hXpAERA3eQwgqnZ5Ks6PDFvVICKj3SAIawKaExpLym19k2XNZgQ9nhunsvp794RKmhjZRqi0RyEICJgjBCyigHtuf1dl8GsU5NV6RAN0YBvKGp68Z4swXJ5g8cYbXrr6Xz3yZ/m8X8aSR4CERIjFkMNpn0f50MmuGV8uRDWUjnXZPilGC9hKWmz0ev3aI7OIX7P/3HH+vXcqn36bJ1VuEGGh7JPaE2FM2nlbLydpsV9b3dY9Ysvbg5vXt+mGbLolx6tpB7to+yFhujr0H5/mocxEmZShYRxCLiEcEXALFlNCHaKQp2ZRbqEcDvYNGZO35qzaZF349WpH2cpL8ajjLWLnOnn0LvHt+DZmeJ9VJCO2AxB5ij1sOZJPAYOQJcUjGKmnZWum+IHLF+e9f72T5+H8zx/9yoF3JR/Xk64azM600GMUbg1gDxoCJEInoy1jWFCwFa5Jcps8+cl08N7alNwqba2Z8fFxEtixs3hBuf/TW/nbsSzY46zaVVNfnoWQCheAphMCABEZygQ2ZRKOuc7koZR++1rW3rOvdLrJlYXx8XP6Xr2o1kjvu8M1vJnaeW8699MoxGXn/8/M0Wp2QzYoGVQmAtZG6xEipL2d2XDHELaNueqTYuTu/9vIPVoz/C2xz9pNBk1vzxGen3T0Tszp0dt6zFCeoKsWCZeNQxOaKmR+7KNqHW3ymWNn6k8DaH9It4qvValQcvuoC8Ijq2Wd3XhntWqj77c1WshGgmLMzqwfkKFkOiYzMAqz0dMX5DglHlBI925igAAAAAElFTkSuQmCC",
    "vivaldi": "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAESUlEQVR4nE2VS2hVVxSGv7XOueeem4fEa4wmBgcSSxGjdSBcwYpgBop00JkTBYtWjOJrJgjBmYgo6kQsrRXEkYp04GsitSAolGp8TKJgWq+ixmgeN+eee87Zq4OTRDcsWOy9+dn8/7/+LTYwoHL0qKuuWfPtXNWfM7O1mdligzmIBKgqIOTLcM6JWQOzCRX5ryDy16c0/aXr4cPnNjCgAjBSqfzY6nm/eSJtDTMywIng6nUsjsG5HE4VKRbRMETN8IBAhNRsPDL7ae79+1dlbO3ab8iyx0XVsJZlqXqeWhwLcSy6ZAl+by/a1QVmuGqVdHAQNzwMYWgSBGZZ5kqe5zecixvwne/SdM8c3w8/J0mqhYJvk5NoZyfh7t0EfX1IqcTXy2o1GrdvUz93TtzIiEhzs04lSdpWKBTHs2yPjFYq/4SetzIGs1pN/eXLaTpxAm/BghzBOTDLexFQBSB7/ZraoUNkL14gTU2uCBJn2aAKLMpALI5FOztpPn36C9g0b3heXtNgAF53Ny1nziDlMpYkkoKYSLcCrU4E4lhK+/ej5TJvLlzg+a5dNN6/z183U0Dj7Vte7t3Lh4sX0YULCfv7oVYTJ4JAi6JacFGE19ND0NeHiyJenz/PyNWr/Hv8OIhgZti00p/v3OHj5cu8O38eq9cJNm/GFi+GOMZEAkXVszjGX7UKPA8NQ+Zv2kRx3jxGb91i4uFDRBWyDJyjdfVqgnKZ8saNuYWKRbLeXrJ6HVGVnBQzdNGiWX66+/spdnQgSUL15MlcjyDIOTQjKJfp2L37i/KdndTTFBXhC8szh0lCob2drp07UTPqT5/y5tgx0g8fiF+94s2RI3Ts2IHf3o4lSa6bCJFzODP8GTu4ajVvPQ+cY/6WLXy6do345Us+XrrE+I0b2NgYQVcX87ZvB+fyu0BWrYIqdedQnMukWCR99AiSBFQxMyQI6DpwAEkSCq2tSBRBHLPw8GGkUMhFUsVFEY3BQfwwpJFlpuZcoqUS2dAQjbt3QQSZVrV1/XraNmyA8XEsipjT10fzunWYc3laiDB18ybZ8DB+Pt8NBSbUDIpFmzp1imx0FHwf0hTM6Dh4EK9Uwg9D5h84kPsxTcH3Sd++ZezsWbzmZtPcpxMyumbN3yXVVRGY1GqaLFtG28mTFL6alsbQEADB0qWze2m1ysi+fSQzo2cmdecGFbgXiIilqZOWFrxnz6hu3crY9eu4qalZoBkwNznJ5JUrvN+2jeTFC7S5GZemLlAVFflTPlcqPSLyuKjaVMuy1PM8jep1GavVpLRkCeGKFRQ6O5FpNeMnT0hfvUJKpdn4asrjK/JFVgrAaKXyQ5Pn/V4QKc8E7LhzxFGENBrIjAiqaBjmEzLtuYIImXOjEWzvfvDgD5n5At5VKj0tnrfTOfe9g8Wpc3NqEIiIh0z/AHlIZDjXUJFxFfm3IHLvs9mvPQ8eDNnAgP4PooMkvWf+DxwAAAAASUVORK5CYII=",
    "yandex": "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAACgElEQVR4nJWVzUuVQRSHnzPv3PeamvZFriyyiMiF2iYKaxGIhIsi+sKFK6l15L7+gGgXbbsVgZtuHxSBlNA/YC4MIgghI1HU1Lre+973ndNi7kXvh2azmQMz55nf/M4ZRlbP7W9rdOl7QKdTQBH+ZwhqfMZUzhRGbEOSvm9SwSCxw5jyplKgbhNI1boC1vQ0FNPGotpF7FyMOhwGVYjW/MYwDVIlWIEo54PyuuBs7AyqXRaRCMHgQFQNYRraO/zpP7+DS2CjC0bg0FEIApidgajgXTIYRCJT4ZkIxEXMnQcEj8eRvkuwugKB9YDfK8jpPoIn45i7DyGOq9WXzSiNwMLyEprNQGCRazegaSckMahCKoVcGYbAoq+ewvIC2FQFohLoEmhuQceyMDuDdBxDevsh9wfyOaT7FNJ1Epbm0bHn0NRSsmQzoCqkQliYw73IeBeuDkMYQhQhF4dABH076v0L0z5nU2BZZWOzT1pZ8qqO98DBI0j/ZUgS3Otn0NAIrrataoGqkG6AmWn0zahXeWEIOdELP6bR7CP49sUD6/SpFM+2T9hAumOnTsoHiIHCGhw4TJD5AIHF3RxAP0/U7U0FZ42YONFPtQrBn7yjCb5Ooe9fgrXIwHUo5Guq+u8rb4SmUrhsBlSRM+dhXxvEUe3r2R5QvZrFOd+Hu/dC657aZt42sAwNrK+mAsaU2mRzhXZLYHmEaT9vcdV1oKB1V1TBWvi1gLs96GGL894GrZ+CoBbVEBWH4Gr2iYH8GvrxHaC+8sb4uBLkUEA1tIhMYk2njZ2p66gJoHWXj6ve7fptMFgDRZ20NoxuuWLogE7nqP8FJFtUtvwFxMlUPiiM/AVwngODLYW8RgAAAABJRU5ErkJggg==",
}


# ─── Icon loader — returns a tk.PhotoImage (20×20) or None ────────────────────
_icon_cache = {}

def get_browser_icon(browser_name: str):
    """Return a cached 20×20 PhotoImage for the browser, or None.

    Icons are pre-rendered 20x20 RGBA PNGs (native cairosvg + PIL LANCZOS).
    """
    if not _PIL_OK:
        return None
    key = browser_name.lower()
    if key in _icon_cache:
        return _icon_cache[key]
    MAP = {
        "chrome": "chrome", "chromium": "chrome",
        "edge": "edge",
        "firefox": "firefox",
        "brave": "brave",
        "opera": "opera",
        "vivaldi": "vivaldi",
        "safari": "safari",
        "yandex": "yandex",
        "custom": "chrome",
    }
    icon_key = MAP.get(key)
    if not icon_key or icon_key not in BROWSER_ICON_B64:
        return None
    try:
        data = base64.b64decode(BROWSER_ICON_B64[icon_key])
        img = Image.open(io.BytesIO(data)).convert("RGBA")
        if img.size != (20, 20):
            img = img.resize((20, 20), Image.LANCZOS)
        photo = ImageTk.PhotoImage(img)
        _icon_cache[key] = photo
        return photo
    except Exception:
        return None



# ─── Main Application ─────────────────────────────────────────────────────────
class BrowsingHistoryApp(tk.Tk):

    COLUMNS = [
        ("visit_time",  "Visit Time",   155),
        ("url",         "URL",          330),
        ("title",       "Title",        215),
        ("browser",     "Browser",       88),
        ("profile",     "Profile",       88),
        ("visit_type",  "Type",          85),
        ("visit_count", "Visits",        52),
        ("typed_count", "Typed",         52),
    ]

    def __init__(self):
        super().__init__()
        self.title("WebTrail — DFIR Edition")
        self.geometry("1380x860")
        self.minsize(1100, 700)
        self.configure(bg=C["bg"])

        self._all_rows   = []
        self._shown_rows = []
        self._reader     = None
        # Multi-column sort: list of (col, desc) in priority order
        self._sort_keys  = [("visit_time", True)]
        # Date filter
        self._date_mode  = tk.StringVar(value="all")  # all|last|before|after|between
        self._date_from  = tk.StringVar(value="")
        self._date_to    = tk.StringVar(value="")
        self._date_days  = tk.StringVar(value="30")
        self._filter_var = tk.StringVar()
        self._bec_findings = []

        self._build_ui()

    # ── UI Construction ───────────────────────────────────────────────────────
    def _build_ui(self):
        self._build_header()
        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill="both", expand=True)
        self._build_sidebar(body)
        content = tk.Frame(body, bg=C["bg"])
        content.pack(side="left", fill="both", expand=True)

        # ── Page container — History and Analysis pages sit here ──────────────
        self._page_container = tk.Frame(content, bg=C["bg"])
        self._page_container.pack(fill="both", expand=True)

        # ── Page A: History ───────────────────────────────────────────────────
        self._page_history = tk.Frame(self._page_container, bg=C["bg"])
        self._build_toolbar(self._page_history)
        self._build_table(self._page_history)
        self._build_detail_panel(self._page_history)
        self._build_status_bar(self._page_history)

        # ── Page B: BEC Analysis ──────────────────────────────────────────────
        self._page_analysis = tk.Frame(self._page_container, bg=C["bg"])
        self._build_analysis_page(self._page_analysis)

        # Start on History page
        self._show_page("history")
        self._build_footer()

    # ── Header ────────────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self, bg=C["navy"], height=58)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        inner = tk.Frame(hdr, bg=C["navy"])
        inner.pack(fill="both", expand=True, padx=20)

        # Logo + title
        tk.Label(inner, text="🔍", font=("Segoe UI", 20),
                 bg=C["navy"], fg=C["accent"]).pack(side="left", pady=12)
        tk.Label(inner, text="WebTrail",
                 font=("Segoe UI", 16, "bold"),
                 bg=C["navy"], fg="#FFFFFF").pack(side="left", padx=(10, 6), pady=14)
        tk.Label(inner, text="DFIR Edition",
                 font=FONTS["small"], bg=C["navy"], fg=C["muted"]).pack(side="left", pady=18)

        # Right-side: Export + Open file
        tk.Button(inner, text="📋  Export",
                  command=self._export_menu,
                  bg=C["accent_lite"], fg=C["white"],
                  font=FONTS["small"], relief="flat", cursor="hand2",
                  padx=12, pady=6, bd=0,
                  activebackground=C["accent_dk"],
                  activeforeground=C["white"]).pack(side="right", padx=(4, 0), pady=12)

        self._btn_open = tk.Button(inner,
                  text="📂  Open History File…",
                  command=self._open_custom_file,
                  bg=C["accent"], fg=C["white"],
                  font=("Segoe UI", 10, "bold"), relief="flat", cursor="hand2",
                  padx=14, pady=6, bd=0,
                  activebackground=C["accent_dk"],
                  activeforeground=C["white"])
        self._btn_open.pack(side="right", padx=4, pady=12)

        # Centre: page tab buttons
        tab_frame = tk.Frame(inner, bg=C["navy"])
        tab_frame.pack(side="left", padx=(30, 0))

        def _tab_btn(text, page, enabled=True):
            b = tk.Button(tab_frame, text=text,
                          command=lambda: self._show_page(page) if enabled else None,
                          bg=C["accent_lite"], fg=C["white"] if enabled else "#4A4F6A",
                          font=("Segoe UI", 10, "bold"),
                          relief="flat",
                          cursor="hand2" if enabled else "arrow",
                          padx=16, pady=6, bd=0,
                          state="normal",
                          activebackground=C["accent_dk"] if enabled else C["accent_lite"],
                          activeforeground=C["white"] if enabled else "#4A4F6A")
            b.pack(side="left", padx=3, pady=12)
            return b

        self._tab_history  = _tab_btn("📋  History",  "history",  True)
        self._tab_analysis = _tab_btn("🔍  Analysis", "analysis", False)
        # Start with History active styling
        self._tab_history.configure(bg=C["accent"])

    # ── Sidebar ───────────────────────────────────────────────────────────────
    def _build_sidebar(self, parent):
        sb = tk.Frame(parent, bg=C["sidebar"], width=230,
                      highlightbackground=C["sidebar_b"], highlightthickness=1)
        sb.pack(side="left", fill="y")
        sb.pack_propagate(False)

        def section(text):
            tk.Label(sb, text=text, font=FONTS["tag"],
                     bg=C["sidebar"], fg=C["muted"]).pack(
                         anchor="w", padx=18, pady=(18, 4))

        # ── Date Filter ───────────────────────────────────────────────────────
        section("DATE FILTER")

        ENTRY_STYLE = dict(bg="#252836", fg="#FFFFFF",
                           insertbackground="#FFFFFF",
                           font=FONTS["small"], relief="flat",
                           bd=4, highlightthickness=0)

        def _date_entry(parent, var, width=11):
            e = tk.Entry(parent, textvariable=var, width=width, **ENTRY_STYLE)
            e.bind("<FocusOut>", lambda ev: self._apply_filter())
            e.bind("<Return>",   lambda ev: self._apply_filter())
            return e

        # ── Mode radio buttons ────────────────────────────────────────────────
        modes = [
            ("all",     "All time"),
            ("last",    "Last N days"),
            ("after",   "After"),
            ("before",  "Before"),
            ("between", "Between"),
        ]
        self._mode_radios = {}
        for val, lbl_text in modes:
            rb = tk.Radiobutton(sb, text=lbl_text,
                                variable=self._date_mode, value=val,
                                command=self._on_date_mode_change,
                                font=FONTS["small"], bg=C["sidebar"],
                                fg="#C0C4D8", selectcolor="#2A2E45",
                                activebackground=C["sidebar"],
                                activeforeground="#C0C4D8",
                                bd=0, relief="flat", cursor="hand2")
            rb.pack(anchor="w", padx=14, pady=1)
            self._mode_radios[val] = rb

        # ── Dynamic input area — each sub-frame packs itself inside here ───────
        # All three frames are children of the sidebar (sb), not a container.
        # _on_date_mode_change pack/pack_forgets them in order, so they always
        # appear directly above the Apply/Clear buttons.

        # Last N days
        self._df_last = tk.Frame(sb, bg=C["sidebar"])
        r = tk.Frame(self._df_last, bg=C["sidebar"])
        r.pack(fill="x")
        tk.Label(r, text="Days:", font=FONTS["small"],
                 bg=C["sidebar"], fg=C["muted"]).pack(side="left", padx=(14, 0))
        _date_entry(r, self._date_days, width=5).pack(side="left", padx=(6, 0))

        # Single date (After / Before)
        self._df_single = tk.Frame(sb, bg=C["sidebar"])
        r2 = tk.Frame(self._df_single, bg=C["sidebar"])
        r2.pack(fill="x")
        tk.Label(r2, text="Date:", font=FONTS["small"],
                 bg=C["sidebar"], fg=C["muted"]).pack(side="left", padx=(14, 0))
        _date_entry(r2, self._date_from, width=11).pack(side="left", padx=(6, 0))
        tk.Label(self._df_single, text="DD/MM/YYYY",
                 font=("Segoe UI", 7), bg=C["sidebar"],
                 fg=C["muted"]).pack(anchor="w", padx=14, pady=(1, 0))

        # Between
        self._df_between = tk.Frame(sb, bg=C["sidebar"])
        rb1 = tk.Frame(self._df_between, bg=C["sidebar"])
        rb1.pack(fill="x")
        tk.Label(rb1, text="From:", font=FONTS["small"],
                 bg=C["sidebar"], fg=C["muted"]).pack(side="left", padx=(14, 0))
        _date_entry(rb1, self._date_from, width=11).pack(side="left", padx=(6, 0))
        rb2 = tk.Frame(self._df_between, bg=C["sidebar"])
        rb2.pack(fill="x", pady=(4, 0))
        tk.Label(rb2, text="To:   ", font=FONTS["small"],
                 bg=C["sidebar"], fg=C["muted"]).pack(side="left", padx=(14, 0))
        _date_entry(rb2, self._date_to, width=11).pack(side="left", padx=(6, 0))
        tk.Label(self._df_between, text="DD/MM/YYYY",
                 font=("Segoe UI", 7), bg=C["sidebar"],
                 fg=C["muted"]).pack(anchor="w", padx=14, pady=(1, 0))

        # Apply / Clear — always visible, always below the input frames
        self._df_btn_row = tk.Frame(sb, bg=C["sidebar"])
        btn_row = self._df_btn_row
        self._df_btn_row.pack(fill="x", padx=14, pady=(8, 4))
        tk.Button(btn_row, text="Apply",
                  command=self._apply_filter,
                  bg=C["accent"], fg=C["white"],
                  font=FONTS["small"], relief="flat", cursor="hand2",
                  padx=10, pady=4, bd=0,
                  activebackground=C["accent_dk"],
                  activeforeground=C["white"]).pack(side="left")
        tk.Button(btn_row, text="Clear",
                  command=self._clear_date_filter,
                  bg=C["accent_lite"], fg=C["white"],
                  font=FONTS["small"], relief="flat", cursor="hand2",
                  padx=10, pady=4, bd=0,
                  activebackground=C["accent_dk"],
                  activeforeground=C["white"]).pack(side="left", padx=(6, 0))

        # Initialise — hide all input frames (tree not built yet)
        self._df_last.pack_forget()
        self._df_single.pack_forget()
        self._df_between.pack_forget()

        # ── Browser list (informational — icon + name) ────────────────────────
        sep = tk.Frame(sb, bg="#2D3150", height=1)
        sep.pack(fill="x", padx=14, pady=6)
        section("BROWSERS")

        scroll_frame = tk.Frame(sb, bg=C["sidebar"])
        scroll_frame.pack(fill="x", padx=8)

        # Keep a reference so PhotoImages don't get GC'd
        self._sidebar_icons = {}
        paths = BrowserPaths.get_all()
        for browser in paths.keys():
            color = BROWSER_COLORS.get(browser, C["muted"])
            row = tk.Frame(scroll_frame, bg=C["sidebar"])
            row.pack(fill="x", pady=1)

            img = get_browser_icon(browser)
            if img:
                self._sidebar_icons[browser] = img
                tk.Label(row, image=img, bg=C["sidebar"],
                         borderwidth=0).pack(side="left", padx=(10, 6), pady=2)
            else:
                tk.Label(row, text="●", font=("Segoe UI", 8),
                         bg=C["sidebar"], fg=color).pack(
                             side="left", padx=(10, 6))

            tk.Label(row, text=browser, font=FONTS["small"],
                     bg=C["sidebar"], fg="#C0C4D8").pack(side="left", pady=2)

        # ── Stats card ────────────────────────────────────────────────────────
        sep2 = tk.Frame(sb, bg="#2D3150", height=1)
        sep2.pack(fill="x", padx=14, pady=(14, 6))
        section("STATS")

        stats_card = tk.Frame(sb, bg="#1E2234",
                               highlightbackground="#2D3150",
                               highlightthickness=1)
        stats_card.pack(fill="x", padx=10, pady=(4, 8))

        def stat_row(label, init="0"):
            f = tk.Frame(stats_card, bg="#1E2234")
            f.pack(fill="x", padx=10, pady=2)
            tk.Label(f, text=label, font=FONTS["small"],
                     bg="#1E2234", fg=C["muted"]).pack(side="left")
            lbl = tk.Label(f, text=init, font=("Segoe UI", 9, "bold"),
                            bg="#1E2234", fg=C["accent"])
            lbl.pack(side="right")
            return lbl

        self._stat_total  = stat_row("Records")
        self._stat_shown  = stat_row("Shown")
        self._stat_unique = stat_row("Unique URLs")

        sep3 = tk.Frame(stats_card, bg="#2D3150", height=1)
        sep3.pack(fill="x", padx=8, pady=4)

        # Dynamic per-browser stat rows — one for each detected browser
        self._stat_browser_frame = stats_card
        self._stat_browser_labels = {}   # browser_name → label widget
        self._stat_browser_stat_fn = stat_row  # keep ref for dynamic creation

        # Status text at bottom
        self._status_var = tk.StringVar(value="Ready")
        tk.Label(sb, textvariable=self._status_var,
                 font=FONTS["small"], bg=C["sidebar"], fg=C["muted"],
                 wraplength=200, justify="left").pack(
                     side="bottom", fill="x", padx=14, pady=10)

    # ── Toolbar (filter bar) ──────────────────────────────────────────────────
    def _build_toolbar(self, parent):
        bar = tk.Frame(parent, bg=C["white"],
                       highlightbackground=C["border"],
                       highlightthickness=1, height=50)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        tk.Label(bar, text="🔎", font=("Segoe UI", 13),
                 bg=C["white"], fg=C["muted"]).pack(side="left", padx=(14, 4), pady=12)

        self._filter_var.trace_add("write", lambda *a: self._debounce_filter())
        fe = tk.Entry(bar, textvariable=self._filter_var,
                      font=FONTS["body"], bg="#F0F1F8", fg=C["text"],
                      insertbackground=C["text"],
                      relief="flat", bd=6, width=44,
                      highlightthickness=1,
                      highlightbackground=C["border"],
                      highlightcolor=C["accent"])
        fe.pack(side="left", padx=6, pady=10, ipady=3)

        # Placeholder hint
        def _on_focus_in(e):
            if fe.get() == "":
                pass  # placeholder managed by textvariable
        fe.insert(0, "")
        fe.bind("<FocusIn>",  _on_focus_in)

        tk.Button(bar, text="✕ Clear", command=lambda: self._filter_var.set(""),
                  font=FONTS["small"], bg=C["white"], fg=C["muted"],
                  relief="flat", cursor="hand2", padx=8, pady=4, bd=0,
                  activebackground=C["border"]).pack(side="left", padx=4)

        # Hint label
        self._count_lbl = tk.Label(bar, text="", font=FONTS["small"],
                                    bg=C["white"], fg=C["muted"])
        self._count_lbl.pack(side="right", padx=16)

    # ── Table ─────────────────────────────────────────────────────────────────
    def _build_table(self, parent):
        tbl_frame = tk.Frame(parent, bg=C["bg"],
                              highlightbackground=C["border"],
                              highlightthickness=1)
        tbl_frame.pack(fill="both", expand=True)

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("BHV.Treeview",
                         background=C["white"],
                         foreground=C["text"],
                         fieldbackground=C["white"],
                         rowheight=26,
                         font=FONTS["body"],
                         borderwidth=0, relief="flat")
        style.configure("BHV.Treeview.Heading",
                         background=C["tbl_hdr"],
                         foreground=C["navy"],
                         font=("Segoe UI", 9, "bold"),
                         relief="flat", borderwidth=0)
        style.map("BHV.Treeview",
                  background=[("selected", C["row_sel"])],
                  foreground=[("selected", C["navy"])])
        style.map("BHV.Treeview.Heading",
                  background=[("active", C["border"])])

        cols = [c[0] for c in self.COLUMNS]
        self.tree = ttk.Treeview(tbl_frame, columns=cols, show="headings",
                                  style="BHV.Treeview", selectmode="extended")

        vsb = ttk.Scrollbar(tbl_frame, orient="vertical",   command=self.tree.yview)
        hsb = ttk.Scrollbar(tbl_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self.tree.pack(fill="both", expand=True)

        for col_id, col_label, col_width in self.COLUMNS:
            self.tree.heading(col_id, text=col_label,
                               command=lambda c=col_id: self._sort_by(c))
            anchor = "center" if col_id in ("visit_count", "typed_count") else "w"
            self.tree.column(col_id, width=col_width, minwidth=40, anchor=anchor)

        self.tree.tag_configure("odd",  background=C["white"])
        self.tree.tag_configure("even", background=C["row_alt"])
        for browser, color in BROWSER_COLORS.items():
            self.tree.tag_configure(browser.lower(), foreground=color)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>",         self._on_double_click)
        self.tree.bind("<Button-3>",         self._on_right_click)
        self.tree.bind("<Button-1>",         self._on_header_click)
        self.tree.bind("<Shift-Button-1>",   self._on_header_shift_click)

        # ── Empty-state overlay ───────────────────────────────────────────────
        self._empty_overlay = tk.Frame(tbl_frame, bg=C["white"])
        self._empty_overlay.place(relx=0, rely=0, relwidth=1, relheight=1)

        es_inner = tk.Frame(self._empty_overlay, bg=C["white"])
        es_inner.place(relx=0.5, rely=0.45, anchor="center")

        tk.Label(es_inner, text="📂", font=("Segoe UI", 48),
                 bg=C["white"], fg=C["border"]).pack()
        tk.Label(es_inner,
                 text="No history loaded",
                 font=("Segoe UI", 16, "bold"),
                 bg=C["white"], fg=C["text"]).pack(pady=(8, 4))
        tk.Label(es_inner,
                 text="Open a browser History or places.sqlite file to get started.",
                 font=FONTS["body"], bg=C["white"], fg=C["muted"]).pack()

        open_btn = tk.Button(es_inner,
                             text="📂  Open History File…",
                             command=self._open_custom_file,
                             bg=C["accent"], fg=C["white"],
                             font=("Segoe UI", 11, "bold"),
                             relief="flat", cursor="hand2",
                             padx=20, pady=10, bd=0,
                             activebackground=C["accent_dk"],
                             activeforeground=C["white"])
        open_btn.pack(pady=(20, 0))

        tk.Label(es_inner,
                 text="Supports Chrome · Edge · Firefox · Brave · Opera · Vivaldi · Safari · Yandex",
                 font=FONTS["small"], bg=C["white"], fg=C["muted"]).pack(pady=(10, 0))

        # Context menu
        self._ctx = tk.Menu(self, tearoff=0,
                             bg=C["card"], fg=C["text"],
                             activebackground=C["row_sel"],
                             activeforeground=C["navy"],
                             font=FONTS["body"])
        self._ctx.add_command(label="🌐  Open in Browser",   command=self._open_url)
        self._ctx.add_command(label="📋  Copy URL",          command=self._copy_url)
        self._ctx.add_command(label="📋  Copy Row (TSV)",    command=self._copy_row)
        self._ctx.add_separator()
        self._ctx.add_command(label="🔍  Filter by Domain",  command=self._filter_domain)
        self._ctx.add_command(label="🔍  Filter by Browser", command=self._filter_browser_ctx)

    # ── Detail panel (shown on selection) ─────────────────────────────────────
    def _build_detail_panel(self, parent):
        self._detail_visible = False
        self._detail_panel = tk.Frame(parent, bg=C["card"],
                                       highlightbackground=C["border"],
                                       highlightthickness=1, height=100)
        # Not packed until a row is selected
        inner = tk.Frame(self._detail_panel, bg=C["card"])
        inner.pack(fill="both", expand=True, padx=16, pady=10)

        def det_row(label_text):
            f = tk.Frame(inner, bg=C["card"])
            f.pack(fill="x", pady=1)
            tk.Label(f, text=f"{label_text}:", width=8,
                     font=FONTS["h3"], bg=C["card"], fg=C["accent"],
                     anchor="w").pack(side="left")
            lbl = tk.Label(f, text="", font=FONTS["body"],
                            bg=C["card"], fg=C["text"], anchor="w",
                            wraplength=1000)
            lbl.pack(side="left", fill="x", expand=True)
            return lbl

        self._det_url   = det_row("URL")
        self._det_title = det_row("Title")
        self._det_meta  = det_row("Meta")

    # ── Status bar ────────────────────────────────────────────────────────────
    def _build_status_bar(self, parent):
        bar = tk.Frame(parent, bg=C["white"],
                        highlightbackground=C["border"],
                        highlightthickness=1, height=28)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self._status_bar_lbl = tk.Label(bar, text="Ready",
                                         font=FONTS["small"],
                                         bg=C["white"], fg=C["muted"], anchor="w")
        self._status_bar_lbl.pack(side="left", padx=14, pady=5)

        self._progress_var = tk.DoubleVar(value=0)
        self._progress_bar = ttk.Progressbar(bar, variable=self._progress_var,
                                               maximum=1.0, length=200,
                                               mode="determinate")
        self._progress_bar.pack(side="right", padx=14, pady=7)

    # ── Footer (MIA-style dark navy bar) ─────────────────────────────────────
    def _build_footer(self):
        footer = tk.Frame(self, bg=C["navy"],
                          highlightbackground=C["sidebar_b"],
                          highlightthickness=1, height=32)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)
        inner = tk.Frame(footer, bg=C["navy"])
        inner.pack(fill="both", expand=True, padx=16)

        # Left: version + author
        tk.Label(inner, text="v1  •  Created by Yuvi Kapoor",
                 font=FONTS["small"], bg=C["navy"], fg=C["muted"]).pack(
                     side="left", pady=8)

        # LinkedIn link
        link = tk.Label(inner, text="linkedin.com/in/yuvi-kapoor-5a38521a5",
                        font=FONTS["small"], bg=C["navy"],
                        fg=C["accent"], cursor="hand2")
        link.pack(side="left", padx=(8, 0), pady=8)
        link.bind("<Button-1>", lambda e: webbrowser.open(
            "https://www.linkedin.com/in/yuvi-kapoor-5a38521a5/"))
        link.bind("<Enter>", lambda e: link.configure(fg=C["accent_dk"]))
        link.bind("<Leave>", lambda e: link.configure(fg=C["accent"]))

        # Right: tool description
        tk.Label(inner,
                 text="DFIR  •  WebTrail",
                 font=FONTS["small"], bg=C["navy"], fg=C["muted"]).pack(
                     side="right", pady=8)


    def _show_page(self, page):
        """Switch between 'history' and 'analysis' pages."""
        self._page_history.pack_forget()
        self._page_analysis.pack_forget()

        if page == "history":
            self._page_history.pack(fill="both", expand=True)
            self._tab_history.configure(bg=C["accent"])
            self._tab_analysis.configure(
                bg=C["accent_lite"],
                fg=C["white"] if self._all_rows else "#4A4F6A")
        else:
            # Refresh analysis data when switching to that page
            self._bec_findings = run_bec_analysis(self._shown_rows)
            self._refresh_bec_summary()
            self._refresh_bec_list()
            self._page_analysis.pack(fill="both", expand=True)
            self._tab_history.configure(bg=C["accent_lite"])
            self._tab_analysis.configure(bg=C["red"], fg=C["white"])


    def _scan_done(self, rows):
        # Pre-cache formatted timestamps — done once, used on every render
        for r in rows:
            r["_fmt_time"] = fmt_dt(r["visit_time"])
        self._all_rows = rows
        # Hide empty-state overlay once data is loaded
        if rows and hasattr(self, "_empty_overlay"):
            self._empty_overlay.place_forget()
        elif not rows and hasattr(self, "_empty_overlay"):
            self._empty_overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
        self._apply_filter()
        self._update_stats()
        # Unlock Analysis tab once data is loaded
        if rows and hasattr(self, "_tab_analysis"):
            self._tab_analysis.configure(
                fg=C["white"],
                cursor="hand2",
                command=lambda: self._show_page("analysis"),
                activebackground=C["accent_dk"])

    def _on_progress(self, done, total):
        # Only push a UI update every 3 ticks to avoid flooding the event queue
        if done % 3 == 0 or done == total:
            val = done / max(total, 1)
            self.after(0, lambda v=val: self._progress_var.set(v))

    def _on_status(self, msg):
        # Cancel any pending status update and schedule a fresh one
        if hasattr(self, "_status_after_id"):
            try:
                self.after_cancel(self._status_after_id)
            except Exception:
                pass
        self._status_after_id = self.after(80, lambda m=msg: self._set_status(m))

    def _set_status(self, msg):
        self._status_var.set(f"  {msg}")
        self._status_bar_lbl.configure(text=f"  {msg}")

    # ── Filter & Display ──────────────────────────────────────────────────────

    # ── Date filter helpers ───────────────────────────────────────────────────
    def _on_date_mode_change(self):
        """Show/hide the appropriate date input widgets for the selected mode."""
        mode = self._date_mode.get()
        for w in (self._df_last, self._df_single, self._df_between):
            w.pack_forget()
        if mode == "last":
            self._df_last.pack(fill="x", before=self._df_btn_row)
        elif mode in ("after", "before"):
            self._df_single.pack(fill="x", before=self._df_btn_row)
        elif mode == "between":
            self._df_between.pack(fill="x", before=self._df_btn_row)
        # Only filter if the tree is already built
        if hasattr(self, 'tree'):
            self._apply_filter()

    def _clear_date_filter(self):
        self._date_mode.set("all")
        self._date_from.set("")
        self._date_to.set("")
        self._date_days.set("30")
        self._on_date_mode_change()

    def _parse_date_entry(self, val):
        """Parse DD/MM/YYYY input → timezone-aware datetime at start of day.
        Returns None if blank or invalid."""
        val = val.strip()
        if not val:
            return None
        for fmt in ("%d/%m/%Y", "%d-%m-%Y", "%Y-%m-%d", "%m/%d/%Y"):
            try:
                dt = datetime.strptime(val, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    def _date_filter_rows(self, rows):
        """Apply the active date filter to a list of rows. Returns filtered list."""
        mode = self._date_mode.get()
        if mode == "all":
            return rows

        now = datetime.now(timezone.utc)

        if mode == "last":
            try:
                days = int(self._date_days.get() or 30)
            except ValueError:
                days = 30
            cutoff = now - timedelta(days=days)
            return [r for r in rows
                    if r["visit_time"] and r["visit_time"] >= cutoff]

        elif mode == "after":
            dt = self._parse_date_entry(self._date_from.get())
            if dt is None:
                return rows
            return [r for r in rows
                    if r["visit_time"] and r["visit_time"] >= dt]

        elif mode == "before":
            dt = self._parse_date_entry(self._date_from.get())
            if dt is None:
                return rows
            # Include the whole day selected — set to end of that day
            dt_end = dt.replace(hour=23, minute=59, second=59)
            return [r for r in rows
                    if r["visit_time"] and r["visit_time"] <= dt_end]

        elif mode == "between":
            dt_from = self._parse_date_entry(self._date_from.get())
            dt_to   = self._parse_date_entry(self._date_to.get())
            if dt_from is None and dt_to is None:
                return rows
            filtered = rows
            if dt_from:
                filtered = [r for r in filtered
                            if r["visit_time"] and r["visit_time"] >= dt_from]
            if dt_to:
                dt_to_end = dt_to.replace(hour=23, minute=59, second=59)
                filtered = [r for r in filtered
                            if r["visit_time"] and r["visit_time"] <= dt_to_end]
            return filtered

        return rows

    def _debounce_filter(self):
        """Delay _apply_filter by 150 ms after last keystroke — avoids
        running a full sort+repopulate on every single character typed."""
        if hasattr(self, "_filter_after_id"):
            self.after_cancel(self._filter_after_id)
        self._filter_after_id = self.after(150, self._apply_filter)

    def _apply_filter(self):
        # 1. Text filter
        q = self._filter_var.get().lower().strip()
        if q:
            rows = [r for r in self._all_rows
                    if q in r["url"].lower()
                    or q in (r["title"] or "").lower()
                    or q in r["browser"].lower()
                    or q in (r["profile"] or "").lower()
                    or q in r["visit_type"].lower()]
        else:
            rows = self._all_rows[:]

        # 2. Date filter
        self._shown_rows = self._date_filter_rows(rows)

        self._apply_sort()
        n, total = len(self._shown_rows), len(self._all_rows)
        self._count_lbl.configure(text=f"{n:,} / {total:,} records")
        self._update_stats()
        # If analysis page is currently visible, refresh it too
        if hasattr(self, '_page_analysis') and self._page_analysis.winfo_ismapped():
            self._bec_findings = run_bec_analysis(self._shown_rows)
            self._refresh_bec_summary()
            self._refresh_bec_list()

    def _populate_tree(self, rows):
        tree = self.tree
        # Detach tree from screen updates while bulk-inserting
        tree.configure(displaycolumns=tree["columns"])

        # Clear existing rows efficiently
        children = tree.get_children()
        if children:
            tree.delete(*children)

        if not rows:
            return

        # Pre-build all insert args — avoid repeated attribute lookups in loop
        insert = tree.insert
        CHUNK  = 500   # render first chunk immediately, rest in background
        _end   = "end"
        _empty = ""

        def _insert_chunk(start):
            chunk = rows[start:start + CHUNK]
            for i, r in enumerate(chunk, start=start):
                tags = ("odd" if i % 2 == 0 else "even", r["browser"].lower())
                insert(_empty, _end, values=(
                    r.get("_fmt_time") or fmt_dt(r["visit_time"]),
                    r["url"],
                    r["title"] or _empty,
                    r["browser"],
                    r["profile"],
                    r["visit_type"],
                    r["visit_count"],
                    r["typed_count"],
                ), tags=tags)
            next_start = start + CHUNK
            if next_start < len(rows):
                # Schedule next chunk — yields to event loop between chunks
                self.after(0, lambda: _insert_chunk(next_start))

        _insert_chunk(0)

    # ── Sort helpers ──────────────────────────────────────────────────────────
    _SORT_KEYS_MAP = {
        "visit_time":  lambda r: r["visit_time"] or datetime.min.replace(tzinfo=timezone.utc),
        "url":         lambda r: r["url"].lower(),
        "title":       lambda r: (r["title"] or "").lower(),
        "browser":     lambda r: r["browser"].lower(),
        "profile":     lambda r: (r["profile"] or "").lower(),
        "visit_type":  lambda r: r["visit_type"].lower(),
        "visit_count": lambda r: r["visit_count"],
        "typed_count": lambda r: r["typed_count"],
    }

    def _on_header_click(self, event):
        if self.tree.identify_region(event.x, event.y) == "heading":
            col = self.tree.identify_column(event.x)
            try:
                col_id = self.COLUMNS[int(col.lstrip("#")) - 1][0]
                self._sort_by(col_id, shift=False)
            except (ValueError, IndexError):
                pass

    def _on_header_shift_click(self, event):
        if self.tree.identify_region(event.x, event.y) == "heading":
            col = self.tree.identify_column(event.x)
            try:
                col_id = self.COLUMNS[int(col.lstrip("#")) - 1][0]
                self._sort_by(col_id, shift=True)
            except (ValueError, IndexError):
                pass

    def _sort_by(self, col, shift=False):
        existing_idx = next(
            (i for i, (c, _) in enumerate(self._sort_keys) if c == col), None)

        if shift:
            if existing_idx is None:
                self._sort_keys.append((col, False))       # add ascending
            elif not self._sort_keys[existing_idx][1]:
                self._sort_keys[existing_idx] = (col, True)  # asc -> desc
            else:
                self._sort_keys.pop(existing_idx)           # desc -> remove
        else:
            if existing_idx is None:
                self._sort_keys = [(col, False)]            # new primary asc
            elif existing_idx == 0 and not self._sort_keys[0][1]:
                self._sort_keys = [(col, True)]             # asc -> desc
            elif existing_idx == 0 and self._sort_keys[0][1]:
                self._sort_keys = []                        # desc -> unsorted
            else:
                self._sort_keys = [(col, False)]            # promote to primary

        self._apply_sort()

    def _apply_sort(self):
        import functools as _ft

        # _shown_rows is already filtered by _apply_filter before this is called.
        # When sort keys are cleared, just restore original load order for the
        # current filtered set by re-filtering from _all_rows.
        if not self._sort_keys:
            q = self._filter_var.get().lower().strip()
            if q:
                self._shown_rows = [r for r in self._all_rows
                                    if q in r["url"].lower()
                                    or q in (r["title"] or "").lower()
                                    or q in r["browser"].lower()
                                    or q in (r["profile"] or "").lower()
                                    or q in r["visit_type"].lower()]
            else:
                self._shown_rows = self._all_rows[:]
            # Re-apply date filter on unsorted restore
            self._shown_rows = self._date_filter_rows(self._shown_rows)
        else:
            def _cmp(a, b):
                for col, desc in self._sort_keys:
                    fn = self._SORT_KEYS_MAP.get(col, lambda r: "")
                    va, vb = fn(a), fn(b)
                    if va == vb:
                        continue
                    try:
                        result = (va > vb) - (va < vb)
                    except TypeError:
                        result = (str(va) > str(vb)) - (str(va) < str(vb))
                    return -result if desc else result
                return 0
            self._shown_rows.sort(key=_ft.cmp_to_key(_cmp))

        self._update_headings()
        self._populate_tree(self._shown_rows)

    def _update_headings(self):
        sort_map = {col: (i + 1, desc)
                    for i, (col, desc) in enumerate(self._sort_keys)}
        for col_id, col_label, _ in self.COLUMNS:
            if col_id in sort_map:
                pri, desc = sort_map[col_id]
                arrow = " \u25bc" if desc else " \u25b2"
                num = f" {pri}" if len(self._sort_keys) > 1 else ""
                self.tree.heading(col_id, text=col_label + arrow + num)
            else:
                self.tree.heading(col_id, text=col_label)


    def _update_stats(self):
        rows = self._shown_rows
        b_counts = {}
        for r in rows:
            b = r["browser"]
            b_counts[b] = b_counts.get(b, 0) + 1

        self._stat_total.configure(text=f"{len(self._all_rows):,}")
        self._stat_shown.configure(text=f"{len(rows):,}")
        self._stat_unique.configure(text=f"{len(set(r['url'] for r in rows)):,}")

        # Add a stat row for any new browser we haven't seen before
        for browser, count in sorted(b_counts.items()):
            if browser not in self._stat_browser_labels:
                # Create label dynamically using the same stat_row style
                f = tk.Frame(self._stat_browser_frame, bg="#1E2234")
                f.pack(fill="x", padx=10, pady=2)
                tk.Label(f, text=browser, font=FONTS["small"],
                         bg="#1E2234", fg=C["muted"]).pack(side="left")
                lbl = tk.Label(f, text="0",
                               font=("Segoe UI", 9, "bold"),
                               bg="#1E2234", fg=C["accent"])
                lbl.pack(side="right")
                self._stat_browser_labels[browser] = lbl

        # Update all known browser labels
        for browser, lbl in self._stat_browser_labels.items():
            lbl.configure(text=f"{b_counts.get(browser, 0):,}")

    # ── Selection & Detail ────────────────────────────────────────────────────
    def _get_selected_row(self):
        sel = self.tree.selection()
        if not sel:
            return None
        idx = self.tree.index(sel[0])
        if idx < len(self._shown_rows):
            return self._shown_rows[idx]
        return None

    def _on_select(self, event=None):
        row = self._get_selected_row()
        if not row:
            return
        if not self._detail_visible:
            self._detail_panel.pack(fill="x", side="bottom",
                                     before=self._status_bar_lbl.master)
            self._detail_visible = True

        self._det_url.configure(text=row["url"])
        self._det_title.configure(text=row["title"] or "(no title)")
        meta = (f"Browser: {row['browser']}  ·  Profile: {row['profile']}  ·  "
                f"Type: {row['visit_type']}  ·  Visits: {row['visit_count']}  ·  "
                f"Typed: {row['typed_count']}  ·  Time: {fmt_dt(row['visit_time'])}")
        self._det_meta.configure(text=meta)

    def _on_double_click(self, event=None):
        row = self._get_selected_row()
        if row:
            try:
                webbrowser.open(row["url"])
            except Exception:
                pass

    def _on_right_click(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self._ctx.post(event.x_root, event.y_root)

    # ── Actions ───────────────────────────────────────────────────────────────
    def _open_url(self):
        row = self._get_selected_row()
        if row:
            webbrowser.open(row["url"])

    def _copy_url(self):
        row = self._get_selected_row()
        if row:
            self.clipboard_clear(); self.clipboard_append(row["url"])

    def _copy_row(self):
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        if idx < len(self._shown_rows):
            r = self._shown_rows[idx]
            text = "\t".join([
                fmt_dt(r["visit_time"]), r["url"], r["title"] or "",
                r["browser"], r["profile"], r["visit_type"],
                str(r["visit_count"]), str(r["typed_count"])
            ])
            self.clipboard_clear(); self.clipboard_append(text)

    def _filter_domain(self):
        row = self._get_selected_row()
        if row:
            self._filter_var.set(domain_of(row["url"]))

    def _filter_browser_ctx(self):
        row = self._get_selected_row()
        if row:
            self._filter_var.set(row["browser"])

    # ── Export ────────────────────────────────────────────────────────────────
    def _export_menu(self):
        m = tk.Menu(self, tearoff=0,
                    bg=C["card"], fg=C["text"],
                    activebackground=C["row_sel"],
                    font=FONTS["body"])
        m.add_command(label="Export as CSV",  command=lambda: self._export("csv"))
        m.add_command(label="Export as TSV",  command=lambda: self._export("tsv"))
        m.add_command(label="Export as JSON", command=lambda: self._export("json"))
        m.add_command(label="Export as HTML", command=lambda: self._export("html"))
        m.post(self.winfo_pointerx(), self.winfo_pointery())

    def _export(self, fmt):
        rows = self._shown_rows
        if not rows:
            messagebox.showinfo("Export", "No data to export.")
            return
        ext = {"csv": ".csv", "tsv": ".tsv", "json": ".json", "html": ".html"}[fmt]
        path = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[(fmt.upper(), f"*{ext}"), ("All files", "*.*")],
            initialfile=f"browsing_history{ext}")
        if not path:
            return
        try:
            headers = ["visit_time", "url", "title", "browser", "profile",
                       "visit_type", "visit_count", "typed_count"]
            if fmt in ("csv", "tsv"):
                d = "," if fmt == "csv" else "\t"
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f, delimiter=d)
                    w.writerow(headers)
                    for r in rows:
                        w.writerow([fmt_dt(r["visit_time"]), r["url"],
                                    r["title"] or "", r["browser"],
                                    r["profile"], r["visit_type"],
                                    r["visit_count"], r["typed_count"]])
            elif fmt == "json":
                data = [{h: (fmt_dt(r["visit_time"]) if h == "visit_time" else r[h])
                         for h in headers} for r in rows]
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            elif fmt == "html":
                with open(path, "w", encoding="utf-8") as f:
                    f.write(f"""<!DOCTYPE html><html><head>
<meta charset="utf-8"><title>WebTrail Export</title>
<style>
body{{background:#F5F6FA;color:#1A1D27;font-family:'Segoe UI',sans-serif;font-size:12px;margin:0;padding:24px}}
h2{{color:#6374F8;font-size:18px;margin-bottom:16px}}
table{{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 4px rgba(0,0,0,0.08)}}
th{{background:#F0F1F8;color:#1A1D27;font-weight:600;padding:8px 12px;text-align:left;position:sticky;top:0;border-bottom:2px solid #E4E6EF}}
td{{padding:6px 12px;border-bottom:1px solid #F0F1F8;max-width:380px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
tr:hover td{{background:#E0E4FE}}
a{{color:#6374F8;text-decoration:none}}a:hover{{text-decoration:underline}}
</style></head><body>
<h2>🔍 WebTrail — {len(rows):,} records</h2>
<table><thead><tr>{''.join(f'<th>{h}</th>' for h in headers)}</tr></thead><tbody>
""")
                    for r in rows:
                        url = r["url"]
                        url_cell = f'<a href="{url}" target="_blank">{url[:80]}</a>'
                        f.write("<tr>")
                        f.write(f"<td>{fmt_dt(r['visit_time'])}</td>")
                        f.write(f"<td>{url_cell}</td>")
                        f.write(f"<td>{r['title'] or ''}</td>")
                        f.write(f"<td>{r['browser']}</td>")
                        f.write(f"<td>{r['profile']}</td>")
                        f.write(f"<td>{r['visit_type']}</td>")
                        f.write(f"<td style='text-align:center'>{r['visit_count']}</td>")
                        f.write(f"<td style='text-align:center'>{r['typed_count']}</td>")
                        f.write("</tr>\n")
                    f.write("</tbody></table></body></html>")
            messagebox.showinfo("Export", f"Saved {len(rows):,} records to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    # ── Open custom DB file ───────────────────────────────────────────────────
    def _open_custom_file(self):
        path = filedialog.askopenfilename(
            title="Open Browser History File",
            filetypes=[
                ("All supported", "*.db *.sqlite *.sqlite3"),
                ("History (Chromium)", "History"),
                ("places.sqlite (Firefox)", "places.sqlite"),
                ("All files", "*.*"),
            ])
        if not path:
            return

        fname  = os.path.basename(path).lower()
        fpath  = path.lower()

        # ── Guess browser from path / filename ────────────────────────────────
        def guess_browser(p):
            p = p.lower().replace("\\", "/")
            if "yandex"   in p: return "Yandex"
            if "brave"    in p: return "Brave"
            if "vivaldi"  in p: return "Vivaldi"
            if "opera"    in p: return "Opera"
            if "edge"     in p: return "Edge"
            if "firefox"  in p or "mozilla" in p or "places" in fname: return "Firefox"
            if "safari"   in p: return "Safari"
            if "chrome"   in p or "chromium" in p: return "Chrome"
            return "Chrome"   # safe default for unknown Chromium forks

        browser_name = guess_browser(fpath)

        # ── Detect format: Firefox (places.sqlite) vs Chromium (History) ──────
        is_firefox = (fname == "places.sqlite"
                      or "places" in fname
                      or browser_name == "Firefox")

        # Double-check by peeking at the SQLite schema
        if not is_firefox:
            try:
                import sqlite3 as _sq
                tmp_peek = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
                tmp_peek.close()
                shutil.copy2(path, tmp_peek.name)
                conn = _sq.connect(tmp_peek.name)
                tables = {r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
                conn.close()
                os.unlink(tmp_peek.name)
                if "moz_places" in tables:
                    is_firefox = True
                    if browser_name not in ("Firefox",):
                        browser_name = "Firefox"
            except Exception:
                pass

        self.tree.delete(*self.tree.get_children())
        self._all_rows.clear()
        reader = HistoryReader(status_cb=self._on_status,
                               progress_cb=self._on_progress)

        def run():
            tmp_dir = tempfile.mkdtemp()
            try:
                if is_firefox:
                    fake_profile = os.path.join(tmp_dir, "custom")
                    os.makedirs(fake_profile)
                    shutil.copy2(path, os.path.join(fake_profile, "places.sqlite"))
                    rows = reader.read_firefox_profiles(tmp_dir)
                    # Re-label with guessed browser name
                    for r in rows:
                        r["browser"] = browser_name
                else:
                    fake_profile = os.path.join(tmp_dir, "Default")
                    os.makedirs(fake_profile)
                    shutil.copy2(path, os.path.join(fake_profile, "History"))
                    rows = reader.read_chromium_browser(tmp_dir, browser_name)
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            self.after(0, lambda: self._scan_done(rows))

        threading.Thread(target=run, daemon=True).start()
        self._set_status(f"Reading {browser_name} — {os.path.basename(path)}…")


    # ── BEC Analysis full page ────────────────────────────────────────────────
    def _build_analysis_page(self, parent):
        """Full-page BEC IOC analysis view."""

        # ── Subheader bar ────────────────────────────────────────────────────
        subhdr = tk.Frame(parent, bg=C["white"],
                          highlightbackground=C["border"],
                          highlightthickness=1, height=50)
        subhdr.pack(fill="x")
        subhdr.pack_propagate(False)
        sh_inner = tk.Frame(subhdr, bg=C["white"])
        sh_inner.pack(fill="both", expand=True, padx=16)

        tk.Label(sh_inner, text="BEC IOC Analysis",
                 font=("Segoe UI", 13, "bold"),
                 bg=C["white"], fg=C["text"]).pack(side="left", pady=14)
        tk.Label(sh_inner,
                 text="Scanning for Business Email Compromise indicators in loaded history",
                 font=FONTS["small"], bg=C["white"], fg=C["muted"]).pack(
                     side="left", padx=(10, 0), pady=17)

        tk.Button(sh_inner, text="📋  Export Findings (CSV)",
                  command=self._export_bec,
                  bg=C["accent"], fg=C["white"],
                  font=FONTS["small"], relief="flat", cursor="hand2",
                  padx=12, pady=6, bd=0,
                  activebackground=C["accent_dk"],
                  activeforeground=C["white"]).pack(side="right", pady=11)

        self._bec_count_lbl = tk.Label(sh_inner, text="",
                                        font=FONTS["small"],
                                        bg=C["white"], fg=C["muted"])
        self._bec_count_lbl.pack(side="right", padx=12, pady=14)

        # ── Summary pills row ────────────────────────────────────────────────
        self._bec_summary_frame = tk.Frame(parent, bg=C["bg"])
        self._bec_summary_frame.pack(fill="x", padx=20, pady=(14, 8))

        # ── Filter bar ───────────────────────────────────────────────────────
        filter_row = tk.Frame(parent, bg=C["white"],
                               highlightbackground=C["border"],
                               highlightthickness=1, height=44)
        filter_row.pack(fill="x")
        filter_row.pack_propagate(False)
        fr_inner = tk.Frame(filter_row, bg=C["white"])
        fr_inner.pack(fill="both", expand=True, padx=14)

        tk.Label(fr_inner, text="🔎", font=("Segoe UI", 13),
                 bg=C["white"], fg=C["muted"]).pack(side="left", pady=10)

        self._bec_filter_var = tk.StringVar()
        self._bec_filter_var.trace_add("write", lambda *a: self._debounce_bec_filter())
        bec_fe = tk.Entry(fr_inner, textvariable=self._bec_filter_var,
                          font=FONTS["body"], bg="#F0F1F8", fg=C["text"],
                          relief="flat", bd=6, width=40,
                          insertbackground=C["text"],
                          highlightthickness=1,
                          highlightbackground=C["border"],
                          highlightcolor=C["accent"])
        bec_fe.pack(side="left", padx=8, pady=8, ipady=3)

        # Severity pills
        self._bec_sev_filter = tk.StringVar(value="all")
        sev_frame = tk.Frame(fr_inner, bg=C["white"])
        sev_frame.pack(side="left", padx=8)

        self._sev_btns = {}
        for sev_key, sev_label in [("all", "All"),
                                    ("critical", "● Critical"),
                                    ("high",     "● High"),
                                    ("medium",   "● Medium")]:
            color = SEV_COLORS.get(sev_key, C["accent"])
            b = tk.Button(sev_frame, text=sev_label,
                          command=lambda s=sev_key: self._set_bec_sev_filter(s),
                          bg=C["accent"] if sev_key == "all" else "#F0F1F8",
                          fg=C["white"] if sev_key == "all" else color,
                          font=FONTS["small"], relief="flat", cursor="hand2",
                          padx=10, pady=4, bd=0,
                          activebackground=color,
                          activeforeground=C["white"])
            b.pack(side="left", padx=3)
            self._sev_btns[sev_key] = b

        # ── Two-column findings area ──────────────────────────────────────────
        findings_outer = tk.Frame(parent, bg=C["bg"])
        findings_outer.pack(fill="both", expand=True)

        canvas = tk.Canvas(findings_outer, bg=C["bg"],
                            highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(findings_outer, orient="vertical",
                             command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        self._bec_list_inner = tk.Frame(canvas, bg=C["bg"])
        self._bec_list_win = canvas.create_window(
            (0, 0), window=self._bec_list_inner, anchor="nw")

        def _on_bec_resize(e):
            canvas.itemconfig(self._bec_list_win, width=e.width)
        canvas.bind("<Configure>", _on_bec_resize)
        self._bec_list_inner.bind("<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")))
        def _bec_scroll(e):
            # Windows/macOS: e.delta; Linux: Button-4/5
            if e.num == 4:
                canvas.yview_scroll(-2, "units")
            elif e.num == 5:
                canvas.yview_scroll(2, "units")
            else:
                canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")

        canvas.bind("<MouseWheel>", _bec_scroll)
        canvas.bind("<Button-4>",   _bec_scroll)
        canvas.bind("<Button-5>",   _bec_scroll)
        # Propagate scroll from child frames to canvas
        self._bec_scroll_fn = _bec_scroll
        self._bec_canvas = canvas

    def _debounce_bec_filter(self):
        if hasattr(self, "_bec_filter_after_id"):
            self.after_cancel(self._bec_filter_after_id)
        self._bec_filter_after_id = self.after(150, self._refresh_bec_list)

    def _set_bec_sev_filter(self, sev):
        self._bec_sev_filter.set(sev)
        # Update pill button active state
        for key, btn in self._sev_btns.items():
            color = SEV_COLORS.get(key, C["accent"])
            active = key == sev
            btn.configure(
                bg=color if active else "#F0F1F8",
                fg=C["white"] if active else (color if key != "all" else C["muted"]))
        self._refresh_bec_list()

    def _refresh_bec_summary(self):
        for w in self._bec_summary_frame.winfo_children():
            w.destroy()

        counts = {"critical": 0, "high": 0, "medium": 0}
        for f in self._bec_findings:
            s = f["severity"]
            if s in counts:
                counts[s] += 1

        pills_data = [
            (str(counts["critical"]), "Critical", C["red"]),
            (str(counts["high"]),     "High",     C["amber"]),
            (str(counts["medium"]),   "Medium",   C["accent"]),
            (str(len(self._bec_findings)), "Total", C["navy"]),
        ]
        for val, lbl_text, color in pills_data:
            pill = tk.Frame(self._bec_summary_frame, bg=C["white"],
                             highlightbackground=color,
                             highlightthickness=1)
            pill.pack(side="left", padx=(0, 6), ipadx=6, ipady=4)
            tk.Label(pill, text=val,
                     font=("Segoe UI", 14, "bold"),
                     bg=C["white"], fg=color).pack()
            tk.Label(pill, text=lbl_text,
                     font=FONTS["small"],
                     bg=C["white"], fg=C["muted"]).pack()

    def _refresh_bec_list(self):
        for w in self._bec_list_inner.winfo_children():
            w.destroy()

        q          = self._bec_filter_var.get().lower().strip()
        sev_filter = self._bec_sev_filter.get()

        filtered = self._bec_findings
        if sev_filter != "all":
            filtered = [f for f in filtered if f["severity"] == sev_filter]
        if q:
            filtered = [f for f in filtered
                        if q in f["url"].lower()
                        or q in f["label"].lower()
                        or q in f["category"].lower()
                        or q in (f["title"] or "").lower()]

        self._bec_count_lbl.configure(
            text=f"{len(filtered)} finding{'s' if len(filtered) != 1 else ''}")

        if not filtered:
            tk.Label(self._bec_list_inner,
                     text="No findings match the current filter.",
                     font=FONTS["body"], bg=C["bg"], fg=C["muted"]).pack(
                         pady=30)
            return

        last_cat = None
        for finding in filtered:
            cat = finding["category"]

            # Category header
            if cat != last_cat:
                last_cat = cat
                ch = tk.Frame(self._bec_list_inner, bg=C["bg"])
                ch.pack(fill="x", padx=10, pady=(10, 2))
                tk.Label(ch, text=cat.upper(),
                         font=FONTS["tag"],
                         bg=C["bg"], fg=C["muted"]).pack(side="left")
                tk.Frame(ch, bg=C["border"], height=1).pack(
                    side="left", fill="x", expand=True, padx=(8, 0), pady=6)

            # Finding card
            sev   = finding["severity"]
            color = SEV_COLORS.get(sev, C["muted"])
            bg    = SEV_BG.get(sev, C["white"])

            card_frame = tk.Frame(self._bec_list_inner, bg=bg,
                                   highlightbackground=color,
                                   highlightthickness=1,
                                   cursor="hand2")
            card_frame.pack(fill="x", padx=10, pady=3)

            # Left severity stripe
            tk.Frame(card_frame, bg=color, width=4).pack(side="left", fill="y")

            body_frame = tk.Frame(card_frame, bg=bg)
            body_frame.pack(side="left", fill="both", expand=True,
                             padx=(8, 8), pady=6)

            # Top row: severity badge + label
            top = tk.Frame(body_frame, bg=bg)
            top.pack(fill="x")
            tk.Label(top, text=sev.upper(),
                     font=FONTS["tag"],
                     bg=color, fg=C["white"],
                     padx=5, pady=1).pack(side="left")
            tk.Label(top, text=f"  {finding['label']}",
                     font=("Segoe UI", 9, "bold"),
                     bg=bg, fg=C["text"]).pack(side="left")

            # URL (truncated)
            url_short = finding["url"]
            if len(url_short) > 70:
                url_short = url_short[:67] + "…"
            url_lbl = tk.Label(body_frame, text=url_short,
                                font=FONTS["mono"],
                                bg=bg, fg=color,
                                anchor="w", cursor="hand2")
            url_lbl.pack(fill="x", pady=(2, 0))
            url_lbl.bind("<Button-1>",
                lambda e, u=finding["url"]: webbrowser.open(u))

            # Title + metadata row
            meta_parts = []
            if finding["title"]:
                meta_parts.append(finding["title"][:50])
            if finding["visit_time"]:
                meta_parts.append(fmt_dt(finding["visit_time"]))
            if finding["browser"]:
                meta_parts.append(finding["browser"])

            if meta_parts:
                tk.Label(body_frame, text="  ·  ".join(meta_parts),
                          font=FONTS["small"],
                          bg=bg, fg=C["muted"],
                          anchor="w").pack(fill="x")

            # Click card → jump to row in main table
            for w in (card_frame, body_frame, top):
                w.bind("<Button-1>",
                    lambda e, u=finding["url"]: self._jump_to_url(u))
            # Propagate mousewheel scroll from cards up to canvas
            for w in (card_frame, body_frame, top):
                w.bind("<MouseWheel>", self._bec_scroll_fn)
                w.bind("<Button-4>",   self._bec_scroll_fn)
                w.bind("<Button-5>",   self._bec_scroll_fn)

    def _jump_to_url(self, url):
        """Switch to History page, then select and scroll to the matching row."""
        # Always switch to history page first
        self._show_page("history")

        for i, row in enumerate(self._shown_rows):
            if row["url"] == url:
                children = self.tree.get_children()
                if i < len(children):
                    iid = children[i]
                    self.tree.selection_set(iid)
                    self.tree.see(iid)
                    self._on_select()
                return

        # URL is currently filtered out — clear filter and try again
        self._filter_var.set("")
        self.after(50, lambda: self._jump_to_url(url))

    def _export_bec(self):
        if not self._bec_findings:
            messagebox.showinfo("Export", "No BEC findings to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")],
            initialfile="webtrail_bec_findings.csv")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Severity", "Category", "Label",
                             "URL", "Title", "Visit Time",
                             "Browser", "Profile"])
                for finding in self._bec_findings:
                    w.writerow([
                        finding["severity"],
                        finding["category"],
                        finding["label"],
                        finding["url"],
                        finding["title"] or "",
                        fmt_dt(finding["visit_time"]),
                        finding["browser"],
                        finding["profile"],
                    ])
            messagebox.showinfo("Export",
                f"Saved {len(self._bec_findings):,} findings to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))


# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = BrowsingHistoryApp()
    app.mainloop()
