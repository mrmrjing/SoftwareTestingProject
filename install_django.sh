#!/usr/bin/env bash
set -euo pipefail

# Configuration
APP_DIR="DjangoWebApplication"
VENV_DIR="virtual"

# 1) Ensure the Django project folder exists
if [ ! -d "$APP_DIR" ]; then
  echo "❌ Error: Directory '$APP_DIR' not found. Run me from the parent folder."
  exit 1
fi

# 2) Enter the Django project directory
cd "$APP_DIR"

# 3) Create venv if it doesn’t exist
if [ ! -d "virtual" ]; then
  echo "→ Creating virtual environment in ./virtual…"
  python3 -m venv "virtual"
fi

# 4) Activate the virtualenv
echo "→ Activating virtual environment…"
# shellcheck disable=SC1090
source "virtual/bin/activate"

# 5) Install requirements
if [ -f requirements.txt ]; then
  echo "→ Upgrading pip and installing dependencies…"
  pip install --upgrade pip
  pip install -r requirements.txt
  echo "✅ Dependencies installed."
else
  echo "❌ Error: requirements.txt not found in $(pwd)."
  deactivate || true
  exit 1
fi

echo "🎉 Django environment setup complete. Virtualenv is active."
