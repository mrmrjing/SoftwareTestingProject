#!/usr/bin/env bash
set -euo pipefail

# Configuration
APP_DIR="DjangoWebApplication"
VENV_DIR="virtual"

set -euo pipefail

# 1) Ensure the Django project folder exists
if [ ! -d "$APP_DIR" ]; then
  echo "❌ Error: Directory '$APP_DIR' not found. Run me from the parent folder."
  exit 1
fi

# 2) Enter the Django project directory
cd "$APP_DIR"

# 3) Create venv if it doesn’t exist
if [ ! -d "$VENV_DIR" ]; then
  echo "→ Creating virtual environment in ./$VENV_DIR"
  python3 -m venv "$VENV_DIR"
fi

# 4) Activate the virtualenv
echo "→ Activating virtual environment…"
# shellcheck disable=SC1090
source "virtual/bin/activate"

# # 5) Install requirements
# if [ -f requirements.txt ]; then
#   echo "→ Upgrading pip and installing dependencies…"
#   pip install --upgrade pip
#   pip install -r requirements.txt
#   echo "✅ Dependencies installed."
#   python manage.py runserver 0.0.0.0:8000 &
#   SERVER_PID=$!
#   sleep 5  # give it a few seconds to compile .pyc etc
#   kill $SERVER_PID
#   echo "✅ Django server pre-warmed."
# else
#   echo "❌ Error: requirements.txt not found in $(pwd)."
#   deactivate || true
#   exit 1
# fi

if [ -f requirements.txt ]; then
  echo "→ Upgrading pip and installing dependencies…"
  
  pip install --upgrade pip
  pip install -r requirements.txt
  
  echo "✅ Dependencies installed."

  # Only AFTER pip install is 100% done, pre-warm Django
  echo "→ Pre-warming Django server..."
  python manage.py runserver 0.0.0.0:8000 > /dev/null 2>&1 &
  SERVER_PID=$!
  sleep 5  # let Django compile .pyc etc
  kill $SERVER_PID
  echo "✅ Django server pre-warmed."

else
  echo "❌ Error: requirements.txt not found in $(pwd)."
  deactivate || true
  exit 1
fi


echo "🎉 Django environment setup complete. Virtualenv is active."
