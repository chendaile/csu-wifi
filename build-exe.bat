@echo off
setlocal
cd /d "%~dp0"
python -m PyInstaller --onefile --clean --name csu-wifi csu_wifi.py
