@echo off
setlocal enabledelayedexpansion

:: Configuration
set "APP_DIR=DjangoWebApplication"
set "VENV_DIR=virtual"

:: 1) Ensure the Django project folder exists
if not exist "%APP_DIR%" (
    echo ❌ Error: Directory '%APP_DIR%' not found. Run me from the parent folder.
    exit /b 1
)

:: 2) Enter the Django project directory
cd "%APP_DIR%"

:: 3) Create venv if it doesn’t exist
if not exist "%VENV_DIR%" (
    echo → Creating virtual environment in .\%VENV_DIR%…
    python -m venv "%VENV_DIR%"
)

:: 4) Activate the virtualenv
echo → Activating virtual environment…
call "%VENV_DIR%\Scripts\activate.bat"

:: 5) Install requirements
if exist "requirements.txt" (
    echo → Upgrading pip and installing dependencies…
    python -m pip install --upgrade pip
    pip install -r requirements.txt
    echo ✅ Dependencies installed.
) else (
    echo ❌ Error: requirements.txt not found in %cd%.
    call "%VENV_DIR%\Scripts\deactivate.bat"
    exit /b 1
)

echo 🎉 Django environment setup complete. Virtualenv is active.
