#!/usr/bin/env python3
import logging
import sys
from pathlib import Path
from typing import List
from simple_fuzzer2 import main as fuzz_main
from colorama import init, Fore, Style
from typing import List
import os
from dotenv import load_dotenv

load_dotenv(".env")

init(autoreset=True)

VALID_PROJECT_TYPES = {
    "BLE": False,
    "DJANGO": True,
}

DJANGO_APP_DIR_NAME = os.getenv("DJANGO_APP_DIR_NAME")
VENV_FILE_NAME = os.getenv("DJANGO_VENV_FIlE_NAME")

def ensure_django_app_available():
    base = Path(__file__).parent
    django_dir = base / DJANGO_APP_DIR_NAME

    if not django_dir.is_dir():
        print(Fore.RED + f"ERROR: required folder '{DJANGO_APP_DIR_NAME}' not found at {django_dir!r}")
        sys.exit(1)

    venv_file = django_dir / VENV_FILE_NAME
    if not venv_file.is_dir():
        print(Fore.RED + f"ERROR: venv file '{VENV_FILE_NAME}' not found in {django_dir!r}")
        sys.exit(1)

def print_commands() -> None:
    print(Fore.MAGENTA + "Possible commands:")
    print(Fore.MAGENTA + "  DJANGO")
    print(Fore.MAGENTA + "  DJANGO <filepath>")
    print(Fore.MAGENTA + "  BLE" + Style.RESET_ALL)


def get_args_interactive() -> List[str]:
    prompt = Fore.CYAN + "Enter command: " + Style.RESET_ALL

    # show available commands once at start
    print_commands()

    while True:
        raw = input(prompt).strip()
        if not raw:
            # empty input → retry
            continue

        # split into at most two parts: project and optional filepath
        parts = raw.split(maxsplit=1)
        proj = parts[0].upper()

        # validate project type
        if proj not in VALID_PROJECT_TYPES:
            valid_choices = ", ".join(VALID_PROJECT_TYPES.keys())
            print(Fore.RED + f"  ✖ Unknown project type '{proj}'. Valid choices: {valid_choices}")
            print_commands()
            continue
        if not VALID_PROJECT_TYPES[proj]:
            print(Fore.RED + f"  ✖ '{proj}' support is currently disabled.")
            print_commands()
            continue

        args = [proj]

        # if DJANGO and user supplied a second token, treat it as filepath
        if proj == "DJANGO" and len(parts) == 2 and parts[1].strip():
            fp = parts[1].strip()
            path = Path(fp)
            if not path.exists():
                print(Fore.YELLOW + f"  ⚠ Warning: '{fp}' does not exist (continuing anyway).")
            args.append(fp)

        # valid args gathered
        return args


def main():
    # We still configure logging in case you want to switch back later
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    args = get_args_interactive()
    if(args[0]=="DJANGO"):
        ensure_django_app_available()
        # check if all django stuff exists so we can run the fuzzer
        if(len(args) > 1):
            # Check if the provided path is a valid file
            path = Path(args[1])
            fuzz_main(path)
        else:
            fuzz_main()
    elif(args[0]=="BLE"):
         print(Fore.RED+ "Not Supported YEt ")
    
if __name__ == "__main__":
    main()
