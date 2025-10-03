#!/bin/zsh

set -euo pipefail

run() { eval "$1" 2>&1; }

computer_name=$(scutil --get ComputerName 2>/dev/null || hostname)
timestamp=$(date "+%Y-%m-%d %H:%M:%S %Z")

print "========================================================================"
print " macOS Compliance Check   |  Computer: $computer_name  |  When: $timestamp"
print "========================================================================"

# Gatekeeper (not 'Anywhere')
gk_raw=$(spctl --status 2>&1 || true)
if [[ "${gk_raw:l}" == *"assessments enabled"* ]]; then
  gk_ok="OK"
  gk_status="ENABLED"
else
  gk_ok="NOT OK"
  gk_status="DISABLED (Anywhere)"
fi

# Screen Saver idle time (seconds) - current host
idle=$(defaults -currentHost read com.apple.screensaver idleTime 2>/dev/null || true)
if [[ -z "$idle" ]]; then
  ss_ok="NOT OK"; ss_status="Not set (treated as Never)"
elif [[ "$idle" -le 0 ]]; then
  ss_ok="NOT OK"; ss_status="Never (0 minutes)"
else
  mins=$(( idle / 60 ))
  ss_ok="OK"; ss_status="${mins} minute(s) (idleTime=${idle}s)"
fi

# Install Security Responses and system files
crit=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null || echo "0")
cfg=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall 2>/dev/null || echo "0")
if [[ "$crit" == "1" && "$cfg" == "1" ]]; then
  su_ok="OK"
else
  su_ok="NOT OK"
fi
su_status="CriticalUpdateInstall=${crit}, ConfigDataInstall=${cfg}"

# FileVault status
fv_raw=$(fdesetup status 2>&1 || true)
fv_lower="${fv_raw:l}"
if [[ "$fv_lower" == *"filevault is on"* ]]; then
  fv_ok="OK"; fv_status="ON"
elif [[ "$fv_lower" == *"filevault is off"* ]]; then
  fv_ok="NOT OK"; fv_status="OFF"
else
  fv_ok="NOT OK"; fv_status="UNKNOWN"
fi

# Output table
printf "%-32s %-10s %s\n" "Gatekeeper (not Anywhere)" "$gk_ok" "$gk_status"
printf "%-32s %-10s %s\n" "Screensaver Auto-Start"    "$ss_ok" "$ss_status"
printf "%-32s %-10s %s\n" "Security Resp. + Sys Files" "$su_ok" "$su_status"
printf "%-32s %-10s %s\n" "FileVault"                  "$fv_ok" "$fv_status"
print "------------------------------------------------------------------------"

# Exit non-zero if anything is NOT OK
if [[ "$gk_ok$ss_ok$su_ok$fv_ok" == *"NOT OK"* ]]; then
  print "One or more checks are NOT OK."
  exit 2
else
  print "All checks OK."
  exit 0
fi
