<div align="center">

# WebTrail

**Browser history forensics tool for Business Email Compromise investigations**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?style=flat-square)]()
[![DFIR](https://img.shields.io/badge/Use%20Case-DFIR%20%7C%20BEC-E95555?style=flat-square)]()
[![Author](https://img.shields.io/badge/Author-Yuvi%20Kapoor-2EAD7A?style=flat-square)](https://linkedin.com/in/yuvi-kapoor-5a38521a5)

</div>

---

## Overview

**WebTrail** is a desktop DFIR tool for extracting and analysing browser history from compromised endpoints during Business Email Compromise and ransomware engagements. Drop in a raw browser `History` or `places.sqlite` file from any supported browser and receive a clean, searchable, investigator-ready view in seconds — with an integrated BEC IOC analysis engine that automatically flags credential phishing infrastructure, OAuth abuse, file exfiltration, financial portals, and eSignature activity across 20+ rule categories.

WebTrail reads directly from SQLite history databases without touching the live browser process, handles locked files via safe copy-before-read, and auto-detects the browser type from the file path and schema.

Built by [Yuvi Kapoor](https://linkedin.com/in/yuvi-kapoor-5a38521a5)

---

## Features

- **Multi-browser support** — reads Chrome, Edge, Firefox, Brave, Opera, Vivaldi, Safari (macOS), and Yandex history files natively
- **Safe file reading** — copies the database to a temp location before reading; works on locked files from live systems
- **Auto-detection** — identifies Firefox vs Chromium format from the SQLite schema (`moz_places` check) and guesses browser name from the file path
- **Multi-profile scanning** — discovers every profile directory (`Default`, `Profile 1`, `Profile 2`, etc.) within a browser's `User Data` folder automatically
- **BEC IOC analysis engine** — 20 rule categories, 130+ patterns; flags Microsoft Auth abuse, OAuth device code phishing, AiTM/PhaaS infrastructure, eSignature platforms, file sharing, banking portals, URL shorteners, Cloudflare Workers, Ngrok, PhaaS kit strings, and more
- **Severity classification** — four-tier system (Critical / High / Medium / Info) with per-finding colour coding
- **Excel-style multi-column sort** — click to cycle asc/desc/unsorted; Shift+click to add secondary and tertiary sort keys with priority numbers displayed in headers
- **Date filter** — five modes: All time, Last N days, After, Before, Between — all in DD/MM/YYYY format
- **Live quick-filter** — text search across URL, title, browser, profile, and visit type with 150ms debounce
- **Chunked rendering** — table populates in batches of 500 rows; first results appear immediately regardless of dataset size
- **Pre-cached timestamps** — `fmt_dt` runs once per row at load time, not on every render
- **Export** — CSV, TSV, JSON, and self-contained styled HTML; BEC findings exportable separately as CSV
- **"Not valid" date handling** — corrupted, out-of-range (pre-2000 / post-2035), or zero-epoch timestamps display as `Not valid` rather than garbage values

---

## BEC IOC Rule Coverage

| Category | Severity | Examples |
|---|---|---|
| **Microsoft Auth — OAuth / Consent Grant** | Critical | `login.microsoftonline.com/common/oauth2`, `login.live.com/oauth20` |
| **OAuth Device Code Phishing** | Critical | `microsoft.com/devicelogin`, `oauth2/deviceauth` |
| **Microsoft Login Portal** | Critical | `login.microsoftonline.com`, `login.live.com` |
| **Known PhaaS Kit Indicators** | Critical | `mamba2fa`, `tycoon2fa`, `evilproxy`, `eviltokens` |
| **Okta Login — Non-Okta Domain** | Critical | `okta-login.`, `login-okta.`, `/okta/signin` |
| **Cloudflare Workers (AiTM Proxy)** | Critical | `*.workers.dev/` |
| **Phishing Infrastructure — Typosquat** | High | `microsoftonline-login.`, `0ffice365.`, `mlcrosoft.` |
| **EvilGinx / AiTM Indicators** | High | `microsoft-online.`, `microsoftonlne.`, `0utlook.` |
| **Ngrok / Tunnelling Services** | High | `ngrok.io`, `ngrok-free.app`, `trycloudflare.com` |
| **Railway.app Hosting** | High | `railway.app` |
| **Milanote LOTS Lure** | High | `milanote.com/m/`, `milanote.com/plan/` |
| **Adobe Acrobat Share Links** | High | `acrobat.adobe.com/id/urn:`, `/link/share` |
| **URL Shorteners** | Critical | `bit.ly/`, `tinyurl.com/`, `rb.gy/`, `cutt.ly/` |
| **DocuSign** | Critical | `docusign.com`, `docusign.net`, `na3.docusign.net` |
| **Adobe Sign / HelloSign** | High | `adobesign.com`, `hellosign.com`, `dropboxsign.com` |
| **SharePoint / OneDrive** | High | `-my.sharepoint.com`, `onedrive.live.com`, `1drv.ms` |
| **Outlook / OWA** | High | `outlook.office365.com`, `mail.office365.com`, `owa/` |
| **Azure AD / Entra Admin** | High | `portal.azure.com`, `entra.microsoft.com` |
| **File Sharing** | High | `wetransfer.com`, `dropbox.com/s/`, `drive.google.com` |
| **Banking Portals** | Critical | CommBank, NAB, Westpac, ANZ, HSBC, Chase, PayPal |
| **Wire Transfer / Payment** | Critical | `wise.com/send`, `remitly.com`, bank transfer URLs |
| **Gift Card Cash-Out** | High | `apple.com/shop/buy-giftcard`, `amazon.com/gift-cards/buy` |
| **Non-Corporate Webmail** | High | Gmail, ProtonMail, Tutanota, `temp-mail.org`, Mailinator |
| **Remote Access Tools** | High | AnyDesk, TeamViewer, ScreenConnect, LogMeIn |
| **Cryptocurrency Exchanges** | High | Coinbase, Binance, Kraken, Crypto.com, Bybit |
| **Microsoft Forms Phishing Lure** | High | `forms.office.com/pages/responsepage`, `forms.office.com/r/` |
| **Slack Phishing Redirect** | High | `/slack/connection/`, `/integration/payroll/` |
| **Direct IP Access** | High | `http(s)://x.x.x.x` — regex match, no hostname |
| **Suspicious TLDs** | Medium | `.xyz/`, `.top/`, `.icu/`, `.work/`, `.online/` |
| **Collaboration / Data Staging** | Medium | `notion.so`, `pastebin.com`, `gist.github.com` |

---

## Supported Browsers

| Browser | Format | Profiles |
|---|---|---|
| **Google Chrome** | Chromium SQLite | All profiles auto-discovered |
| **Microsoft Edge** | Chromium SQLite | All profiles auto-discovered |
| **Brave** | Chromium SQLite | All profiles auto-discovered |
| **Opera** | Chromium SQLite (flat layout) | Single profile |
| **Vivaldi** | Chromium SQLite | All profiles auto-discovered |
| **Yandex Browser** | Chromium SQLite | All profiles auto-discovered |
| **Firefox** | Mozilla `places.sqlite` | All profiles auto-discovered |
| **Safari** | WebKit SQLite | macOS only |

---

## Installation

### 1. Install dependencies

```bash
pip install pillow
```

> `tkinter` is included with standard Python on Windows. No other dependencies required.

### 2. Run

```bash
python WebTrail.py
```

Or double-click `WebTrail.py` if Python is associated with `.py` files.

**One-click launcher — create `run.bat` in the same folder:**

```bat
@echo off
python WebTrail.py
pause
```

---

## Usage

### Loading a History File

1. Click **📂 Open History File…** in the header
2. Navigate to the browser's history database:

| Browser | Path |
|---|---|
| Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\History` |
| Edge | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History` |
| Brave | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\History` |
| Firefox | `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\places.sqlite` |
| Opera | `%APPDATA%\Opera Software\Opera Stable\History` |
| Vivaldi | `%LOCALAPPDATA%\Vivaldi\User Data\Default\History` |
| Yandex | `%LOCALAPPDATA%\Yandex\YandexBrowser\User Data\Default\History` |

> Files can be opened directly from a forensic copy or mounted image — the browser does not need to be installed on the analyst machine.

### History Table

- **Click** a column header to sort ascending; click again for descending; click a third time to clear
- **Shift+click** a second or third column to add secondary sort keys — priority numbers appear in headers
- **Type** in the filter bar to search across URL, title, browser, profile, and visit type
- **Right-click** any row for: Open in Browser, Copy URL, Copy Row, Filter by Domain, Filter by Browser
- **Click** any row to expand the detail panel showing the full URL, title, and metadata

### Date Filter

Select a mode from the sidebar:

| Mode | Description |
|---|---|
| All time | No date restriction |
| Last N days | Rolling window from now — enter number of days |
| After | All records on or after a given date (DD/MM/YYYY) |
| Before | All records up to and including a given date |
| Between | Inclusive range between two dates |

Date filters and text filters stack — both apply simultaneously.

### BEC Analysis Page

1. Load a history file — the **🔍 Analysis** tab in the header activates once data is loaded
2. Click **🔍 Analysis** to switch to the analysis view
3. Summary pills show Critical / High / Medium / Total finding counts at a glance
4. Use severity filter buttons or the text search to narrow findings
5. Click any finding card to jump back to that exact row in the History table
6. Click **📋 Export Findings (CSV)** to save all findings with severity, category, label, URL, timestamp, browser, and profile

> The analysis page always reflects the current filter state — date and text filters apply before IOC rules run.

---

## Output Columns

| Column | Description |
|---|---|
| `Visit Time` | Timestamp in `DD/MM/YYYY HH:MM:SS` local time; `Not valid` for corrupt/out-of-range values |
| `URL` | Full URL as stored in the history database |
| `Title` | Page title at time of visit |
| `Browser` | Detected browser name |
| `Profile` | Profile directory name (`Default`, `Profile 1`, etc.) |
| `Type` | Visit transition type: `Typed`, `Link`, `Reload`, `Bookmark`, `Form Submit`, etc. |
| `Visits` | Total visit count for this URL |
| `Typed` | Number of times the URL was typed directly into the address bar |

---

## Date Handling

WebTrail validates every timestamp on load:

- **Chrome/Edge/Brave/Opera/Vivaldi/Yandex** — microseconds since 1601-01-01 UTC (Chromium epoch)
- **Firefox** — microseconds since 1970-01-01 UTC (Unix epoch)
- **Safari** — seconds since 2001-01-01 UTC (Core Data epoch)

Any timestamp that falls outside the range **01/01/2000 — 31/12/2035** is treated as corrupt and displays as `Not valid`. This catches zero-epoch artefacts, uninitialized database fields, integer overflow values, and partial database corruption.

---

## Export Formats

| Format | Contents |
|---|---|
| **CSV** | All visible (filtered) rows, UTF-8, comma-delimited |
| **TSV** | All visible rows, tab-delimited for Excel paste |
| **JSON** | All visible rows as a JSON array |
| **HTML** | Self-contained styled report with sortable table, opens in any browser |
| **BEC Findings CSV** | Severity, category, label, URL, title, timestamp, browser, profile for all IOC hits |

All exports respect the active filters — only the currently visible rows are exported.

---

## Data & Privacy

### What leaves your workstation

| Component | External contact | Data sent |
|---|---|---|
| History parsing | None — fully local | Nothing |
| BEC IOC analysis | None — fully local | Nothing |
| All exports | None | Nothing unless you send the file |

### Privacy considerations

Browser history databases contain a detailed record of every website visited by the subject — including authentication portals, personal communications, financial transactions, and medical information.

| Jurisdiction | Instrument | Key consideration |
|---|---|---|
| Australia | Privacy Act 1988 / APPs | Collect only what is necessary for the engagement; destroy when no longer required |
| European Union | GDPR | Data minimisation and purpose limitation apply |
| United Kingdom | UK GDPR / DPA 2018 | Same as EU GDPR in practice |

> This is general guidance, not legal advice. Consult your firm's legal team for jurisdiction-specific obligations.

---

## File Structure

```
WebTrail/
└── WebTrail.py      # Single-file application — parsing engine + BEC IOC rules + GUI
└── README.md
```

---

## Dependencies

| Package | Purpose |
|---|---|
| `tkinter` | GUI framework — included with standard Python |
| `Pillow` | Browser icon rendering *(optional — falls back to coloured dots if absent)* |

---

## Author

**Yuvi Kapoor**

Specialising in ransomware and BEC incident response engagements.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Yuvi%20Kapoor-0A66C2?style=flat-square&logo=linkedin)](https://linkedin.com/in/yuvi-kapoor-5a38521a5)

---

## Licence

Apache 2.0 — see [LICENSE](LICENSE)

---

<div align="center">

Built for the DFIR community

</div>
