@echo off
setlocal enabledelayedexpansion

:: Configuration
set "APP_DIR=DjangoWebApplication"
set "VENV_DIR=virtual"

:: Step 1: Ensure Django project folder exists
if not exist "%APP_DIR%" (
    echo ❌ Error: Directory '%APP_DIR%' not found. Run me from the parent folder.
    exit /b 1
)

:: Step 2: Enter the Django project directory
cd "%APP_DIR%"

:: Step 3: Create venv if it doesn't exist
if not exist "%VENV_DIR%" (
    echo → Creating virtual environment in .\%VENV_DIR%
    python -m venv "%VENV_DIR%"
)

:: Step 4: Activate the virtual environment
echo → Activating virtual environment…
call "%VENV_DIR%\Scripts\activate.bat"

:: Step 5: Install requirements
if exist requirements.txt (
    echo → Upgrading pip and installing dependencies…
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
    echo ✅ Dependencies installed.

    :: Pre-warming Django server
    echo → Pre-warming Django server...
    start /b python manage.py runserver 0.0.0.0:8000
    set SERVER_PID=%ERRORLEVEL%
    timeout /t 5 > nul
    taskkill /f /im python.exe
    echo ✅ Django server pre-warmed.
) else (
    echo ❌ Error: requirements.txt not found in %CD%.
    exit /b 1
)

echo 🎉 Django environment setup complete. Virtualenv is active.
