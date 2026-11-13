@echo off
setlocal
cd /d "%~dp0"
python -m pip install -r requirements-build.txt
if errorlevel 1 exit /b 1
python -B -m unittest discover -s tests
if errorlevel 1 exit /b 1
python tools\check_frontend.py
if errorlevel 1 exit /b 1
python -m PyInstaller --noconfirm --clean --onefile --noconsole --name GuardTowarr --icon icon.ico --add-data "webpage.html;." --add-data "icon.ico;." --hidden-import pystray._win32 monitor.py
if errorlevel 1 exit /b 1
echo Built dist\GuardTowarr.exe
