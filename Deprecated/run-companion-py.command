#!/bin/bash
cd "$(dirname "$0")"

if command -v python3 >/dev/null 2>&1; then
  /usr/bin/env python3 ./check_macos_compliance.py
  exit $?
fi

# Offer to install CLT (shows Apple GUI prompt)
/usr/bin/xcode-select --install >/dev/null 2>&1 || true
echo
echo "If an install prompt appeared, complete it, then re-run this file."
echo "Alternatively, run the zsh version: ./check_macos_compliance.zsh"
read -n 1 -p "Press any key to close..."
