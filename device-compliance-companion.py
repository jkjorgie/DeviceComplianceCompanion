#!/usr/bin/env python3
"""
Device Compliance Companion
===========================

Checks a Mac against the company device-compliance baseline, then collects the
evidence the security admin asks for, all in one run:

  1. Runs the compliance checks and prints the report.
  2. Saves the report (text + JSON) into a dated evidence folder.
  3. Screenshots the terminal window showing the report.
  4. Opens the macOS Passwords app and screenshots its window.
  5. Opens an email draft (Outlook, or Apple Mail) with everything attached.
     Nothing is sent automatically. You review and click Send.

Usage
-----
  python3 device-compliance-companion.py                 full run (checks + evidence + email draft)
  python3 device-compliance-companion.py --check-only    print the report and exit, nothing saved
  python3 device-compliance-companion.py --all-checks    also run the optional Drata-baseline checks
  python3 device-compliance-companion.py --to admin@x.y  address the draft (or set SECURITY_ADMIN_EMAIL below)
  python3 device-compliance-companion.py --mail-app mail use Apple Mail instead of Outlook for the draft
  python3 device-compliance-companion.py --install-schedule
        Reminds you at the start of every quarter by opening Terminal and running
        the full pipeline. Runs daily at SCHEDULE_HOUR until the quarter's
        evidence exists, then stays quiet until the next quarter.
  python3 device-compliance-companion.py --uninstall-schedule

Requirements: macOS only. Nothing to install. The built-in python3 needs the
Xcode Command Line Tools; macOS offers to install them the first time python3 runs.

Permissions macOS will ask for once:
  - Screen Recording for your terminal app (needed for the screenshots).
  - Automation, so the script can create the email draft in Outlook or Mail.
"""

import argparse
import datetime
import getpass
import hashlib
import json
import os
import platform
import plistlib
import re
import shlex
import shutil
import subprocess
import sys
import time
from typing import List, Optional, Tuple

# ============================ Configuration ============================

SCRIPT_VERSION = "2.0.0"

# Address the email draft to this person. Can be overridden with --to.
SECURITY_ADMIN_EMAIL = ""

# Screen lock policy: idle time until lock plus password grace period must be
# at or under this many minutes.
SCREEN_LOCK_MAX_MINUTES = 15

# Where evidence is stored: <EVIDENCE_ROOT>/<YYYY>-Q<n>/
EVIDENCE_ROOT = os.path.expanduser("~/Documents/Device Compliance Evidence")

# Support files (compiled helper, launchd wrapper, logs).
APP_SUPPORT = os.path.expanduser("~/Library/Application Support/DeviceComplianceCompanion")

# Quarterly reminder schedule (checked daily at this local hour).
LAUNCH_AGENT_LABEL = "com.gideontaylor.device-compliance-companion"
SCHEDULE_HOUR = 9
SCHEDULE_MINUTE = 0

# ============================ Console helpers ============================

USE_COLOR = True


def C(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def GREEN(s): return C(s, "32")
def RED(s): return C(s, "31")
def YELLOW(s): return C(s, "33")
def BOLD(s): return C(s, "1")
def DIM(s): return C(s, "2")


def run(cmd, timeout: int = 60) -> Tuple[int, str, str]:
    """Run a command (string or list). Returns (returncode, stdout, stderr), stripped."""
    argv = shlex.split(cmd) if isinstance(cmd, str) else cmd
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except subprocess.TimeoutExpired:
        return 1, "", f"timed out after {timeout}s"
    except Exception as e:  # noqa: BLE001
        return 1, "", f"ERROR: {e}"


def read_defaults(domain: str, key: str, current_host: bool = False):
    argv = ["defaults"] + (["-currentHost"] if current_host else []) + ["read", domain, key]
    rc, out, _ = run(argv)
    if rc != 0:
        return None
    try:
        return int(out)
    except ValueError:
        return out


def is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


# ============================ Checks ============================

class Check:
    def __init__(self, name: str, ok: Optional[bool], status: str, detail: str = "", required: bool = True):
        self.name = name
        self.ok = ok            # True / False / None (could not determine)
        self.status = status    # short human summary shown in the table
        self.detail = detail    # raw values, kept in the JSON for the admin
        self.required = required

    def to_dict(self) -> dict:
        return {"name": self.name, "ok": self.ok, "status": self.status,
                "detail": self.detail, "required": self.required}


def check_gatekeeper() -> Check:
    rc, out, err = run("spctl --status")
    raw = out or err
    enabled = "assessments enabled" in raw.lower()
    return Check("Gatekeeper (not Anywhere)", enabled,
                 "ENABLED" if enabled else "DISABLED (Anywhere)", raw)


def _display_sleep_minutes() -> Optional[int]:
    rc, out, _ = run("pmset -g")
    m = re.search(r"^\s*displaysleep\s+(\d+)", out, re.MULTILINE)
    return int(m.group(1)) if m else None


def _screen_lock_status() -> Tuple[Optional[bool], Optional[int], str]:
    """Native replacement for osquery's screenlock table.
    Returns (enabled, grace_seconds, raw)."""
    rc, out, err = run("sysadminctl -screenLock status")
    raw = (out + "\n" + err).strip()
    low = raw.lower()
    if "screenlock is off" in low:
        return False, None, raw
    if "immediate" in low:
        return True, 0, raw
    m = re.search(r"delay is (\d+) second", low)
    if m:
        return True, int(m.group(1)), raw
    return None, None, raw


def check_screen_lock() -> Check:
    """Compliant when a password is required on wake and the time from last
    activity to a locked screen (idle-to-lock + password grace) is at or under
    SCREEN_LOCK_MAX_MINUTES. The lock fires on screensaver start or display
    sleep, whichever comes first."""
    limit_secs = SCREEN_LOCK_MAX_MINUTES * 60

    idle = read_defaults("com.apple.screensaver", "idleTime", current_host=True)
    idle_secs = idle if isinstance(idle, int) and idle > 0 else None      # None = never

    ds_min = _display_sleep_minutes()
    ds_secs = ds_min * 60 if ds_min else None                              # 0/None = never

    candidates = [s for s in (idle_secs, ds_secs) if s is not None]
    effective_idle = min(candidates) if candidates else None

    enabled, grace, raw = _screen_lock_status()

    detail = (f"idleTime={idle}, displaysleep_min={ds_min}, "
              f"screenLock.enabled={enabled}, screenLock.grace_seconds={grace}")

    if enabled is None:
        return Check("Screen lock", None, "Could not read screen lock status", detail + " | " + raw)
    if not enabled:
        return Check("Screen lock", False, "Password on wake: OFF", detail)
    if effective_idle is None:
        return Check("Screen lock", False,
                     "Screen never locks automatically (screensaver and display sleep both Never)", detail)

    total = effective_idle + (grace or 0)
    ok = total <= limit_secs
    src = "screensaver" if effective_idle == idle_secs else "display sleep"
    status = (f"Locks {total / 60:g} min after last activity "
              f"({effective_idle // 60} min {src} + {(grace or 0) // 60} min grace); "
              f"limit {SCREEN_LOCK_MAX_MINUTES} min; password on wake: ON")
    return Check("Screen lock", ok, status, detail)


def check_security_responses() -> Check:
    crit = read_defaults("/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall")
    cfg = read_defaults("/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall")
    ok = (crit == 1 and cfg == 1)
    return Check("Security Responses + System Files", ok,
                 "ON" if ok else "OFF (enable in System Settings > General > Software Update > Automatic Updates)",
                 f"CriticalUpdateInstall={crit}, ConfigDataInstall={cfg}")


def check_filevault() -> Check:
    rc, out, err = run("fdesetup status")
    raw = out or err
    low = raw.lower()
    if "filevault is on" in low:
        return Check("FileVault", True, "ON", raw)
    if "filevault is off" in low:
        return Check("FileVault", False, "OFF", raw)
    return Check("FileVault", None, "UNKNOWN", raw)


def check_firewall() -> Check:
    rc, out, err = run("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate")
    raw = out or err
    m = re.search(r"State = (\d)", raw)
    if not m:
        return Check("Firewall", None, "UNKNOWN", raw, required=False)
    state = int(m.group(1))
    ok = state >= 1
    return Check("Firewall", ok, "ON" if ok else "OFF (System Settings > Network > Firewall)",
                 raw, required=False)


def check_pending_updates() -> Check:
    # --no-scan reads the last Software Update scan instead of hitting the network.
    rc, out, err = run("softwareupdate --list --no-scan", timeout=30)
    raw = (out + "\n" + err).strip()
    if "no new software available" in raw.lower():
        return Check("Pending macOS updates", True, "None pending", raw, required=False)
    titles = re.findall(r"^\s*\*\s*Label:\s*(.+)$", raw, re.MULTILINE)
    if titles:
        return Check("Pending macOS updates", False,
                     "Pending: " + "; ".join(t.strip() for t in titles), raw, required=False)
    return Check("Pending macOS updates", None, "Could not determine", raw, required=False)


def run_all_checks(include_additional: bool = False) -> List[Check]:
    checks = [
        # Required by the security team
        check_gatekeeper(),
        check_screen_lock(),
        check_security_responses(),
        check_filevault(),
    ]
    if include_additional:
        # Additional Drata-baseline items, reported but not currently required
        checks += [check_firewall(), check_pending_updates()]
    return checks


# ============================ Machine info ============================

def get_computer_name() -> str:
    rc, out, _ = run("scutil --get ComputerName")
    return out if rc == 0 and out else platform.node()


def get_current_user() -> str:
    for key in ("SUDO_USER", "USER", "LOGNAME"):
        if os.environ.get(key):
            return os.environ[key]
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return "unknown"


def get_serial() -> str:
    rc, out, _ = run("ioreg -c IOPlatformExpertDevice -d 2")
    m = re.search(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"', out)
    return m.group(1) if m else "unknown"


def get_os_version() -> str:
    rc, out, _ = run("sw_vers -productVersion")
    rc2, build, _ = run("sw_vers -buildVersion")
    return f"macOS {out} ({build})" if rc == 0 else platform.mac_ver()[0]


def get_script_hash() -> str:
    """SHA-256 of this file. Identifies which version of the script produced the
    report. It is NOT tamper evidence: a modified script could print any hash."""
    try:
        with open(os.path.abspath(__file__), "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:  # noqa: BLE001
        return f"ERROR: {e}"


def quarter_label(d: Optional[datetime.date] = None) -> str:
    d = d or datetime.date.today()
    return f"{d.year}-Q{(d.month - 1) // 3 + 1}"


# ============================ Report ============================

class Report:
    def __init__(self, checks: List[Check]):
        self.when = datetime.datetime.now().astimezone()
        self.quarter = quarter_label(self.when.date())
        self.computer = get_computer_name()
        self.user = get_current_user()
        self.serial = get_serial()
        self.os = get_os_version()
        self.script_hash = get_script_hash()
        self.checks = checks

    @property
    def required_failures(self) -> List[Check]:
        return [c for c in self.checks if c.required and c.ok is not True]

    @property
    def additional_failures(self) -> List[Check]:
        return [c for c in self.checks if not c.required and c.ok is not True]

    @property
    def compliant(self) -> bool:
        return not self.required_failures

    def to_dict(self) -> dict:
        return {
            "script_version": SCRIPT_VERSION,
            "script_sha256": self.script_hash,
            "generated_at": self.when.isoformat(),
            "quarter": self.quarter,
            "computer_name": self.computer,
            "user": self.user,
            "serial_number": self.serial,
            "os": self.os,
            "policy": {"screen_lock_max_minutes": SCREEN_LOCK_MAX_MINUTES},
            "checks": [c.to_dict() for c in self.checks],
            "required_checks_pass": self.compliant,
            "additional_checks_included": self.has_additional,
            "additional_checks_pass": (not self.additional_failures) if self.has_additional else None,
        }

    @property
    def has_additional(self) -> bool:
        return any(not c.required for c in self.checks)

    def render(self, color: bool) -> str:
        global USE_COLOR
        saved, USE_COLOR = USE_COLOR, color
        try:
            return self._render()
        finally:
            USE_COLOR = saved

    def _render(self) -> str:
        bar = "=" * 78
        lines = [bar,
                 f" {BOLD('Device Compliance Report')}   {self.quarter}   {self.when.strftime('%Y-%m-%d %H:%M:%S %Z')}",
                 bar,
                 f" Computer: {self.computer}    User: {self.user}    Serial: {self.serial}",
                 f" OS:       {self.os}",
                 f" Script:   v{SCRIPT_VERSION}   sha256 {self.script_hash}",
                 bar]

        def mark(c: Check) -> str:
            if c.ok is True:
                return GREEN("OK")
            if c.ok is False:
                return RED("NOT OK")
            return YELLOW("UNKNOWN")

        width = max(len(c.name) for c in self.checks) + 2

        def rows(items):
            for c in items:
                pad = " " * (10 - len("OK" if c.ok is True else "NOT OK" if c.ok is False else "UNKNOWN"))
                yield f" {c.name.ljust(width)} {mark(c)}{pad} {c.status}"

        lines.append(BOLD(" Required checks"))
        lines.extend(rows(c for c in self.checks if c.required))
        if self.has_additional:
            lines.append("")
            lines.append(BOLD(" Additional checks") + DIM(" (Drata baseline, reported for information)"))
            lines.extend(rows(c for c in self.checks if not c.required))
        lines.append("-" * 78)
        if self.compliant:
            lines.append(GREEN(" All required checks OK."))
        else:
            names = ", ".join(c.name for c in self.required_failures)
            lines.append(RED(f" Required checks NOT OK: {names}"))
        if self.additional_failures:
            names = ", ".join(c.name for c in self.additional_failures)
            lines.append(YELLOW(f" Additional checks needing attention: {names}"))
        lines.append(bar)
        return "\n".join(lines)


# ============================ Screenshots ============================

WINID_SWIFT_SOURCE = r'''
import CoreGraphics
import Foundation
let target = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ""
let opts: CGWindowListOption = [.optionOnScreenOnly, .excludeDesktopElements]
guard let list = CGWindowListCopyWindowInfo(opts, kCGNullWindowID) as? [[String: Any]] else { exit(1) }
for w in list {
    guard let owner = w["kCGWindowOwnerName"] as? String, owner == target,
          let layer = w["kCGWindowLayer"] as? Int, layer == 0,
          let id = w["kCGWindowNumber"] as? Int else { continue }
    if let b = w["kCGWindowBounds"] as? [String: Any],
       let wd = b["Width"] as? Double, let ht = b["Height"] as? Double, wd < 50 || ht < 50 { continue }
    print(id); exit(0)
}
exit(2)
'''


def _winid_via_pyobjc(owner: str) -> Optional[int]:
    try:
        import Quartz  # type: ignore  # present only with pyobjc installed
    except ImportError:
        return None
    try:
        opts = Quartz.kCGWindowListOptionOnScreenOnly | Quartz.kCGWindowListExcludeDesktopElements
        for w in Quartz.CGWindowListCopyWindowInfo(opts, Quartz.kCGNullWindowID):
            if w.get("kCGWindowOwnerName") != owner or w.get("kCGWindowLayer") != 0:
                continue
            b = w.get("kCGWindowBounds") or {}
            if b.get("Width", 0) < 50 or b.get("Height", 0) < 50:
                continue
            return int(w.get("kCGWindowNumber"))
    except Exception:  # noqa: BLE001
        return None
    return None


def _winid_helper_path() -> Optional[str]:
    """Compile a tiny Swift helper once (about 10 s) and cache it."""
    binary = os.path.join(APP_SUPPORT, "winid")
    if os.path.isfile(binary) and os.access(binary, os.X_OK):
        return binary
    if not shutil.which("swiftc"):
        return None
    os.makedirs(APP_SUPPORT, exist_ok=True)
    src = os.path.join(APP_SUPPORT, "winid.swift")
    with open(src, "w") as f:
        f.write(WINID_SWIFT_SOURCE)
    print(DIM("  One-time setup: building the window-capture helper (about 10 seconds)..."))
    rc, _, err = run(["swiftc", "-O", "-o", binary, src], timeout=300)
    if rc != 0:
        print(YELLOW(f"  Could not build helper: {err.splitlines()[-1] if err else rc}"))
        return None
    return binary


def find_window_id(owner: str) -> Optional[int]:
    wid = _winid_via_pyobjc(owner)
    if wid:
        return wid
    helper = _winid_helper_path()
    if helper:
        rc, out, _ = run([helper, owner], timeout=15)
        if rc == 0 and out.isdigit():
            return int(out)
    return None


def terminal_app_name() -> Optional[str]:
    """Window-owner name of the terminal we are running in."""
    tp = os.environ.get("TERM_PROGRAM", "")
    return {
        "Apple_Terminal": "Terminal",
        "iTerm.app": "iTerm2",
        "vscode": "Code",
        "WarpTerminal": "Warp",
        "ghostty": "Ghostty",
        "Alacritty": "Alacritty",
        "kitty": "kitty",
    }.get(tp)


def capture_window(owner: Optional[str], dest: str, label: str) -> bool:
    """Screenshot one window. Tries by window id, then falls back to letting the
    user click the window."""
    wid = find_window_id(owner) if owner else None
    if wid:
        rc, _, err = run(["screencapture", "-x", "-l", str(wid), dest], timeout=30)
    elif is_interactive():
        print(YELLOW(f"  Click on the {label} window to capture it (press Esc to skip)."))
        rc, _, err = run(["screencapture", "-x", "-i", "-w", dest], timeout=120)
    else:
        print(YELLOW(f"  Could not locate the {label} window and no terminal to ask. Skipping."))
        return False
    ok = rc == 0 and os.path.isfile(dest) and os.path.getsize(dest) > 0
    if not ok:
        print(YELLOW(f"  Screenshot of {label} failed: {err or 'no file produced'}"))
    return ok


SCREEN_RECORDING_NOTE = (
    "  If a screenshot shows only the desktop, grant your terminal app Screen Recording\n"
    "  permission: System Settings > Privacy & Security > Screen & System Audio Recording,\n"
    "  then run this again."
)


def wait_for_window(owner: str, seconds: float = 15.0) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        if find_window_id(owner):
            return True
        time.sleep(0.5)
    return False


# ============================ Email draft ============================

def _as_str(s: str) -> str:
    """Quote a Python string as an AppleScript string literal."""
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    return '"' + s.replace("\n", '" & linefeed & "') + '"'


def _osascript(script: str, timeout: int = 60) -> Tuple[int, str, str]:
    return run(["osascript", "-e", script], timeout=timeout)


def _html_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _status_word(c: Check) -> str:
    return "OK" if c.ok is True else "NOT OK" if c.ok is False else "UNKNOWN"


def build_email_bodies(report: Report, attachments: List[str]) -> Tuple[str, str]:
    """Returns (plain_text, html) versions of the email body."""
    when = report.when.strftime("%Y-%m-%d %H:%M %Z")
    required = [c for c in report.checks if c.required]
    additional = [c for c in report.checks if not c.required]
    verdict = "All required checks passed." if report.compliant else \
        "Required checks NOT OK: " + ", ".join(c.name for c in report.required_failures)

    # ---------- plain text ----------
    def block(title: str, items: List[Check]) -> str:
        width = max(len(c.name) for c in items)
        lines = [title, "-" * len(title)]
        for c in items:
            lines.append(f"  {_status_word(c):8} {c.name.ljust(width)}  {c.status}")
        return "\n".join(lines)

    sections = [
        f"Quarterly device compliance evidence for {report.quarter}.",
        "\n".join([
            "Device",
            "------",
            f"  Computer:   {report.computer}",
            f"  User:       {report.user}",
            f"  Serial:     {report.serial}",
            f"  OS:         {report.os}",
            f"  Generated:  {when}",
        ]),
        f"Result: {verdict}",
        block("Required checks", required),
    ]
    if additional:
        sections.append(block("Additional checks (Drata baseline, for information)", additional))
    sections += [
        "\n".join(["Attachments", "-----------"] + [f"  - {os.path.basename(a)}" for a in attachments]),
        f"Script v{SCRIPT_VERSION}, sha256 {report.script_hash}",
    ]
    plain = "\n\n".join(sections) + "\n"

    # ---------- html ----------
    colors = {"OK": "#1a7f37", "NOT OK": "#c0392b", "UNKNOWN": "#b7791f"}

    def rows(items: List[Check]) -> str:
        out = []
        for c in items:
            w = _status_word(c)
            out.append(
                f'<tr><td style="padding:4px 10px;white-space:nowrap;font-weight:bold;color:{colors[w]}">{w}</td>'
                f'<td style="padding:4px 10px;white-space:nowrap">{_html_escape(c.name)}</td>'
                f'<td style="padding:4px 10px">{_html_escape(c.status)}</td></tr>')
        return "\n".join(out)

    def table(title: str, items: List[Check], note: str = "") -> str:
        note_html = f' <span style="font-weight:normal;color:#666">{note}</span>' if note else ""
        return (f'<h3 style="margin:18px 0 6px">{title}{note_html}</h3>'
                f'<table style="border-collapse:collapse;border:1px solid #ddd">{rows(items)}</table>')

    verdict_color = colors["OK"] if report.compliant else colors["NOT OK"]
    device_rows = "".join(
        f'<tr><td style="padding:2px 10px 2px 0;color:#666">{k}</td><td style="padding:2px 0">{_html_escape(v)}</td></tr>'
        for k, v in [("Computer", report.computer), ("User", report.user), ("Serial", report.serial),
                     ("OS", report.os), ("Generated", when)])
    attach_items = "".join(f"<li>{_html_escape(os.path.basename(a))}</li>" for a in attachments)

    html = (
        '<div style="font-family:-apple-system,Helvetica,Arial,sans-serif;font-size:14px;line-height:1.4">'
        f'<h2 style="margin:0 0 10px">Device Compliance Report, {report.quarter}</h2>'
        f'<table style="border-collapse:collapse">{device_rows}</table>'
        f'<p style="margin:14px 0;font-weight:bold;color:{verdict_color}">{_html_escape(verdict)}</p>'
        + table("Required checks", required)
        + (table("Additional checks", additional, "(Drata baseline, for information)") if additional else "")
        + f'<h3 style="margin:18px 0 6px">Attachments</h3><ul style="margin:0">{attach_items}</ul>'
        f'<p style="margin-top:18px;color:#888;font-size:12px">Script v{SCRIPT_VERSION}, sha256 {report.script_hash}</p>'
        '</div>')
    return plain, html


def draft_outlook(to: str, subject: str, body: str, files: List[str], html: str = "") -> Tuple[bool, str]:
    content = f'content:{_as_str(html)}' if html else f'plain text content:{_as_str(body)}'
    parts = ['tell application "Microsoft Outlook"',
             f'  set m to make new outgoing message with properties {{subject:{_as_str(subject)}, {content}}}']
    if to:
        parts.append(f'  make new to recipient at m with properties {{email address:{{address:{_as_str(to)}}}}}')
    for f in files:
        parts.append(f'  make new attachment at m with properties {{file:POSIX file {_as_str(f)}}}')
    parts += ['  open m', '  activate', 'end tell']
    rc, out, err = _osascript("\n".join(parts))
    if rc != 0 and html:
        # Fall back to a plain-text body if this Outlook build rejects HTML content.
        return draft_outlook(to, subject, body, files, html="")
    return rc == 0, err


def draft_apple_mail(to: str, subject: str, body: str, files: List[str], html: str = "") -> Tuple[bool, str]:
    parts = ['tell application "Mail"',
             f'  set m to make new outgoing message with properties {{subject:{_as_str(subject)}, content:{_as_str(body + chr(10) + chr(10))}, visible:true}}',
             '  tell m']
    if to:
        parts.append(f'    make new to recipient at end of to recipients with properties {{address:{_as_str(to)}}}')
    for f in files:
        parts.append(f'    make new attachment with properties {{file name:POSIX file {_as_str(f)}}} at after the last paragraph')
    parts += ['  end tell', '  activate', 'end tell']
    rc, out, err = _osascript("\n".join(parts))
    if rc != 0 and ("outgoing message" in err or "-2710" in err or "-1708" in err):
        err += " (Apple Mail usually reports this when no email account is set up in Mail)"
    return rc == 0, err


MAIL_CLIENTS = {"outlook": ("Outlook", draft_outlook), "mail": ("Mail", draft_apple_mail)}


def create_email_draft(to: str, subject: str, body: str, files: List[str], html: str = "",
                       mail_app: Optional[str] = None) -> Tuple[bool, str]:
    """Returns (ok, which client). Outlook gets the HTML body; Mail gets plain text.
    mail_app: "outlook" or "mail" to force one client; None picks Outlook when
    installed and falls back to Mail otherwise."""
    if mail_app:
        order = [MAIL_CLIENTS[mail_app]]
    elif os.path.isdir("/Applications/Microsoft Outlook.app"):
        order = [MAIL_CLIENTS["outlook"], MAIL_CLIENTS["mail"]]
    else:
        order = [MAIL_CLIENTS["mail"], MAIL_CLIENTS["outlook"]]
    errors = []
    for name, fn in order:
        ok, err = fn(to, subject, body, files, html)
        if ok:
            return True, name
        errors.append(f"{name}: {err.splitlines()[-1] if err else 'failed'}")
    print(YELLOW("  Could not create an email draft automatically: " + " | ".join(errors)))
    return False, ""


# ============================ Evidence pipeline ============================

def quarter_evidence_exists(quarter: str, root: str = EVIDENCE_ROOT) -> bool:
    folder = os.path.join(root, quarter)
    return os.path.isdir(folder) and any(n.startswith("report-") and n.endswith(".json")
                                         for n in os.listdir(folder))


def run_pipeline(report: Report, to: str, evidence_root: str,
                 screenshots: bool, email: bool, mail_app: Optional[str] = None) -> int:
    stamp = report.when.strftime("%Y%m%d-%H%M%S")
    folder = os.path.join(evidence_root, report.quarter)
    os.makedirs(folder, exist_ok=True)

    print(report.render(color=USE_COLOR))
    sys.stdout.flush()

    txt = os.path.join(folder, f"report-{stamp}.txt")
    js = os.path.join(folder, f"report-{stamp}.json")
    with open(txt, "w") as f:
        f.write(report.render(color=False) + "\n")
    with open(js, "w") as f:
        json.dump(report.to_dict(), f, indent=2)
    attachments = [txt, js]

    print()
    print(BOLD("Collecting evidence") + f"  ->  {folder}")

    if screenshots:
        # 1) Terminal window showing the report above.
        time.sleep(0.5)
        shot = os.path.join(folder, f"terminal-{stamp}.png")
        print("  Capturing the terminal window...")
        if capture_window(terminal_app_name(), shot, "terminal"):
            attachments.append(shot)

        # 2) Passwords app. It must be unlocked by a person, so we wait for that.
        print("  Opening the Passwords app...")
        run(["open", "-a", "Passwords"])
        wait_for_window("Passwords", 15)
        if is_interactive():
            try:
                input(YELLOW("  Unlock Passwords (Touch ID or password) so your list is visible, then press Return here... "))
            except EOFError:
                pass
        else:
            time.sleep(3)
        shot = os.path.join(folder, f"passwords-{stamp}.png")
        if capture_window("Passwords", shot, "Passwords"):
            attachments.append(shot)
        term = terminal_app_name()
        if term:
            run(["open", "-a", term])
        print(DIM(SCREEN_RECORDING_NOTE))

    print("  Saved:")
    for a in attachments:
        print(f"    {os.path.basename(a)}")

    if email:
        subject = f"Device Compliance Report {report.quarter} - {report.computer} - {report.user}"
        body, html = build_email_bodies(report, attachments)
        print("  Creating the email draft...")
        ok, client = create_email_draft(to, subject, body, attachments, html, mail_app)
        if ok:
            dest = f"to {to}" if to else "with no recipient (add one)"
            print(GREEN(f"  Draft opened in {client} {dest}. Review it and click Send."))
        else:
            run(["open", folder])
            print(YELLOW(f"  Attach the files in {folder} to an email to your security admin manually."))
    else:
        run(["open", folder])

    return 0 if report.compliant else 2


# ============================ Quarterly schedule ============================

def _plist_path() -> str:
    return os.path.expanduser(f"~/Library/LaunchAgents/{LAUNCH_AGENT_LABEL}.plist")


def _wrapper_path() -> str:
    return os.path.join(APP_SUPPORT, "Device Compliance Companion.command")


def build_wrapper(script_path: str) -> str:
    return ("#!/bin/bash\n"
            "# Opened by the quarterly reminder. Runs the full compliance pipeline in Terminal.\n"
            f"cd {shlex.quote(os.path.dirname(script_path))}\n"
            f"/usr/bin/env python3 {shlex.quote(script_path)}\n"
            "echo\n"
            "read -n 1 -s -r -p 'Press any key to close this window.'\n"
            "echo\n")


def build_plist(script_path: str, python: str) -> bytes:
    return plistlib.dumps({
        "Label": LAUNCH_AGENT_LABEL,
        "ProgramArguments": [python, script_path, "--scheduled"],
        "StartCalendarInterval": {"Hour": SCHEDULE_HOUR, "Minute": SCHEDULE_MINUTE},
        "RunAtLoad": False,
        "StandardOutPath": os.path.join(APP_SUPPORT, "scheduled.log"),
        "StandardErrorPath": os.path.join(APP_SUPPORT, "scheduled.log"),
    })


def install_schedule() -> int:
    script_path = os.path.abspath(__file__)
    os.makedirs(APP_SUPPORT, exist_ok=True)
    os.makedirs(os.path.dirname(_plist_path()), exist_ok=True)

    with open(_wrapper_path(), "w") as f:
        f.write(build_wrapper(script_path))
    os.chmod(_wrapper_path(), 0o755)

    with open(_plist_path(), "wb") as f:
        f.write(build_plist(script_path, sys.executable))

    uid = os.getuid()
    run(["launchctl", "bootout", f"gui/{uid}/{LAUNCH_AGENT_LABEL}"])
    rc, out, err = run(["launchctl", "bootstrap", f"gui/{uid}", _plist_path()])
    if rc != 0:
        print(RED(f"launchctl failed: {err or out}"))
        return 1
    print(GREEN("Quarterly reminder installed."))
    print(f"  Checks daily at {SCHEDULE_HOUR:02d}:{SCHEDULE_MINUTE:02d}. At the start of each quarter, until that")
    print(f"  quarter's evidence exists in {EVIDENCE_ROOT},")
    print("  it opens Terminal and runs the full pipeline.")
    print(f"  Script path recorded: {script_path}")
    print(YELLOW("  Keep the script at that path. If you move it, run --install-schedule again."))
    return 0


def uninstall_schedule() -> int:
    uid = os.getuid()
    run(["launchctl", "bootout", f"gui/{uid}/{LAUNCH_AGENT_LABEL}"])
    removed = False
    for p in (_plist_path(), _wrapper_path()):
        if os.path.exists(p):
            os.remove(p)
            removed = True
    print(GREEN("Quarterly reminder removed.") if removed else "No reminder was installed.")
    return 0


def scheduled_tick() -> int:
    """Runs daily under launchd, with no terminal. Opens one if evidence is due."""
    q = quarter_label()
    if quarter_evidence_exists(q):
        return 0
    if not os.path.isfile(_wrapper_path()):
        with open(_wrapper_path(), "w") as f:
            f.write(build_wrapper(os.path.abspath(__file__)))
        os.chmod(_wrapper_path(), 0o755)
    _osascript(f'display notification "Quarterly device compliance evidence for {q} is due. '
               f'Terminal is opening to collect it." with title "Device Compliance Companion"')
    rc, _, err = run(["open", "-a", "Terminal", _wrapper_path()])
    print(f"{datetime.datetime.now().isoformat()} evidence for {q} due; opened Terminal rc={rc} {err}")
    return rc


# ============================ Main ============================

def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Device Compliance Companion: checks + evidence collection.")
    p.add_argument("--check-only", action="store_true", help="print the report only; save nothing")
    p.add_argument("--json", action="store_true", help="print the report as JSON (implies --check-only)")
    p.add_argument("--all-checks", action="store_true",
                   help="also run the additional Drata-baseline checks (firewall, pending macOS updates); "
                        "they are reported for information and never affect pass/fail")
    p.add_argument("--to", metavar="EMAIL", default=None, help="recipient for the email draft")
    p.add_argument("--no-screenshots", action="store_true", help="skip the terminal and Passwords screenshots")
    p.add_argument("--no-email", action="store_true", help="save evidence but do not open an email draft")
    p.add_argument("--mail-app", choices=["outlook", "mail"], default=None,
                   help="which app creates the draft (default: Outlook if installed, else Apple Mail)")
    p.add_argument("--evidence-dir", metavar="DIR", default=None, help=f"override evidence root (default: {EVIDENCE_ROOT})")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--install-schedule", action="store_true", help="install the quarterly reminder (launchd)")
    p.add_argument("--uninstall-schedule", action="store_true", help="remove the quarterly reminder")
    p.add_argument("--scheduled", action="store_true", help=argparse.SUPPRESS)
    return p.parse_args(argv)


def main(argv: List[str]) -> int:
    global USE_COLOR
    args = parse_args(argv)
    USE_COLOR = sys.stdout.isatty() and not args.no_color and not os.getenv("NO_COLOR")

    if platform.system() != "Darwin":
        print("This tool only runs on macOS.")
        return 1
    if args.install_schedule:
        return install_schedule()
    if args.uninstall_schedule:
        return uninstall_schedule()
    if args.scheduled:
        return scheduled_tick()

    report = Report(run_all_checks(include_additional=args.all_checks))

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0 if report.compliant else 2
    if args.check_only:
        print(report.render(color=USE_COLOR))
        return 0 if report.compliant else 2

    to = args.to if args.to is not None else os.environ.get("SECURITY_ADMIN_EMAIL", SECURITY_ADMIN_EMAIL)
    return run_pipeline(report, to, args.evidence_dir or EVIDENCE_ROOT,
                        screenshots=not args.no_screenshots, email=not args.no_email,
                        mail_app=args.mail_app)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(130)
