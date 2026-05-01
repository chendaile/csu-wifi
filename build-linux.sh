#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
python3 -m PyInstaller --onefile --clean --name csu-wifi csu_wifi.py
