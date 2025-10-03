#!/bin/bash
cd "$(dirname "$0")"
chmod +x ./check_macos_compliance.zsh
/usr/bin/env zsh ./check_macos_compliance.zsh ; read -n 1 -p "Press any key to close..."
