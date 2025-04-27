#!/usr/bin/env bash
set -euo pipefail

# Save environment folder name at the top
ENV_FOLDER=".local"

# 1) cd into the script’s folder (project root)
cd "$(dirname "$0")"

# 2) bootstrap your virtualenv in $ENV_FOLDER if it doesn't exist
if [ ! -d "$ENV_FOLDER" ]; then
  echo "→ Creating virtualenv in $ENV_FOLDER…"
  python3 -m venv "$ENV_FOLDER"
fi

# 3) activate it
source "$ENV_FOLDER/bin/activate"

# 4) install deps once
if [ -f requirements.txt ]; then
  echo "→ Installing dependencies…"
  pip install --upgrade pip
  pip install -r requirements.txt
fi

# 5) hand off to main.py with no extra args—let it prompt you
echo "→ Launching fuzzer interactive shell…"
exec python main.py
