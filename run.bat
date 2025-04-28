@echo off
setlocal enabledelayedexpansion

REM Save environment folder name
set "ENV_FOLDER=.local"

REM 1) cd into the script’s folder (project root)
cd /d "%~dp0"

REM 2) bootstrap your virtualenv in %ENV_FOLDER% if it doesn't exist
if not exist "%ENV_FOLDER%\Scripts\activate.bat" (
    echo → Creating virtualenv in %ENV_FOLDER%…
    python -m venv "%ENV_FOLDER%"
)

REM 3) activate it
call "%ENV_FOLDER%\Scripts\activate.bat"

REM 4) install deps once
if exist requirements.txt (
    echo → Installing dependencies…
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
)

REM 5) hand off to main.py with no extra args—let it prompt you
echo → Launching fuzzer interactive shell…
python main.py

endlocal
