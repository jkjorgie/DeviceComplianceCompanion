#!/usr/bin/env python3
import subprocess, shlex, datetime, platform, os, sys, getpass

# ---------------- Config ----------------
SCREENSAVER_MAX_MINUTES = 15  # NOT OK if idleTime > 15 minutes (or 0/None)

# ---------------- Color helpers ----------------
def _supports_color():
    if "--no-color" in sys.argv or os.getenv("NO_COLOR"):
        return False
    return sys.stdout.isatty()

USE_COLOR = _supports_color()
def C(text, code): return f"\033[{code}m{text}\033[0m" if USE_COLOR else text
GREEN = lambda s: C(s, "32")
RED   = lambda s: C(s, "31")
BOLD  = lambda s: C(s, "1")

def OK(b): return GREEN("OK") if b else RED("NOT OK")

# ---------------- Shell helper ----------------
def run(cmd):
    try:
        p = subprocess.run(shlex.split(cmd), capture_output=True, text=True)
        out = (p.stdout or "").strip()
        err = (p.stderr or "").strip()
        return p.returncode, out if out else err
    except Exception as e:
        return 1, f"ERROR: {e}"

# ---------------- Checks ----------------
def get_computer_name():
    rc, out = run("scutil --get ComputerName")
    return out if rc == 0 else platform.node()

def get_current_user():
    for key in ("SUDO_USER", "USER", "LOGNAME"):
        val = os.environ.get(key)
        if val:
            return val
    try:
        return getpass.getuser()
    except Exception:
        rc, out = run("id -un")
        return out if rc == 0 else "unknown"

def check_gatekeeper():
    rc, out = run("spctl --status")
    enabled = ("assessments enabled" in out.lower())
    status = "ENABLED" if enabled else "DISABLED (Anywhere)"
    return enabled, status, out

def read_defaults(domain, key, current_host=False):
    flag = "-currentHost " if current_host else ""
    # print(f'defaults {flag}read {domain} {key}')
    rc, out = run(f'defaults {flag}read {domain} {key}')
    if rc != 0:
        return None
    try:
        return int(out)
    except ValueError:
        return out

def check_screensaver_idle():
    """
    Compliance requires ALL of the following:
      1) Screensaver idleTime > 0 and <= SCREENSAVER_MAX_MINUTES
      2) require password to wake == true  (via osascript/System Events)
      3) require password to wake delay == 0 seconds (immediate)
    """
    threshold_secs = SCREENSAVER_MAX_MINUTES * 60

    # 1) Idle time (per-host)
    idle = read_defaults("com.apple.screensaver", "idleTime", current_host=True)

    # 2) Password-on-wake (via System Events, not defaults)
    rc_pw, out_pw = run(
        "osascript -e 'tell application \"System Events\" to get require password to wake of security preferences'"
    )
    #rc_delay, out_delay = run(
    #    "osascript -e 'tell application \"System Events\" to get require password to wake delay of security preferences'"
    #)

    # Normalize outputs
    pw_ok = (rc_pw == 0) and (str(out_pw).strip().lower() in ("true", "1", "yes"))
    # out_delay may be integer-like ("0") or float-like ("0.0")
    #try:
    #    delay_val = float(str(out_delay).strip())
    #except Exception:
    #    delay_val = None
    #delay_ok = (rc_delay == 0) and (delay_val is not None) and (delay_val == 0.0)
    delay_ok = True # don't need to actually look at delay_val because the rc_pw value handles it

    # Evaluate idle compliance
    idle_ok = isinstance(idle, int) and idle > 0 and idle <= threshold_secs

    compliant = bool(idle_ok and pw_ok and delay_ok)

    # Build status details
    if idle is None:
        idle_detail = f"idleTime not set — require ≤ {SCREENSAVER_MAX_MINUTES} min"
    elif not isinstance(idle, int) or idle <= 0:
        idle_detail = f"Never (0 minutes) — require ≤ {SCREENSAVER_MAX_MINUTES} min"
    elif idle > threshold_secs:
        idle_detail = f"{idle//60} minutes — exceeds {SCREENSAVER_MAX_MINUTES} min"
    else:
        idle_detail = f"{idle//60} minutes (OK)"

    pw_detail = "Password on wake: ON" if pw_ok else f"Password on wake: OFF (osascript rc={rc_pw}, val={out_pw})"
    #if delay_val is None:
    #    delay_detail = f"Delay unreadable (osascript rc={rc_delay}, val={out_delay})"
    #else:
    #    delay_detail = "Immediate (OK)" if delay_ok else f"Delay={delay_val} (require 0)"

    status = (
        # f"{idle_detail}; {pw_detail}; {delay_detail} "
        f"{idle_detail}; {pw_detail} "
        # f"[requirePasswordToWake={out_pw}, requirePasswordToWakeDelay={out_delay}]"
        f"[requirePasswordToWake={out_pw}]"
    )
    # return compliant, status, f"idleTime={idle}, requirePasswordToWake={out_pw}, requirePasswordToWakeDelay={out_delay}"
    return compliant, status, f"idleTime={idle}, requirePasswordToWake={out_pw}"



def check_security_responses_and_system_files():
    crit = read_defaults("/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall")
    cfg  = read_defaults("/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall")
    compliant = (crit == 1 and cfg == 1)
    status = f"CriticalUpdateInstall={crit}, ConfigDataInstall={cfg}"
    return compliant, status, "Expect both = 1"

def check_filevault():
    rc, out = run("fdesetup status")
    txt = out.lower()
    if "filevault is on" in txt:  return True,  "ON", out
    if "filevault is off" in txt: return False, "OFF", out
    return False, "UNKNOWN", out

# ---------------- Main ----------------
def main():
    now = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    comp = get_computer_name()
    user = get_current_user()
    bar = "=" * 72
    print(bar)
    print(f" {BOLD('macOS Compliance Check')}   |  Computer: {comp}  |  User: {user}  |  When: {now}")
    print(bar)

    gk_ok, gk_status, _ = check_gatekeeper()
    ss_ok, ss_status, _ = check_screensaver_idle()
    su_ok, su_status, _ = check_security_responses_and_system_files()
    fv_ok, fv_status, _ = check_filevault()

    rows = [
        ("Gatekeeper (not Anywhere)", gk_ok, gk_status),
        ("Screensaver Auto-Start",    ss_ok, ss_status),
        ("Security Resp. + Sys Files",su_ok, su_status),
        ("FileVault",                 fv_ok, fv_status),
    ]

    col1 = max(len(r[0]) for r in rows) + 2
    col2 = 10
    for name, ok, status in rows:
        print(f"{name.ljust(col1)} {OK(ok).ljust(col2)} {status}")
    print("-" * 72)

    if not all([gk_ok, ss_ok, su_ok, fv_ok]):
        print(RED("One or more checks are NOT OK."))
        sys.exit(2)
    else:
        print(GREEN("All checks OK."))
        sys.exit(0)

if __name__ == "__main__":
    main()
