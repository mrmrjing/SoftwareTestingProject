#!/usr/bin/env python3
import logging
import sys
from pathlib import Path
from typing import List
from simple_fuzzer2 import main as fuzz_main
from BLE.Smartlock import start_ble_fuzzing as ble_main
from colorama import init, Fore, Style
from typing import List
import os
from dotenv import load_dotenv
PROJECT_ROOT = Path(__file__).parent 

load_dotenv(".env")

init(autoreset=True)

VALID_PROJECT_TYPES = {
    "BLE": True,
    "DJANGO": True,
}

DJANGO_APP_DIR_NAME = "DjangoWebApplication"
VENV_FILE_NAME="virtual"

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
    
    print(Fore.MAGENTA + "  BLE --resume <filepath>" + Style.RESET_ALL)


def get_args_interactive() -> List[str]:
    prompt = Fore.CYAN + "Enter command: " + Style.RESET_ALL

    print_commands()

    while True:
        raw = input(prompt).strip()
        if not raw:
            continue

        parts = raw.split()

        proj = parts[0].upper()

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

        if proj == "DJANGO":
            if len(parts) >= 2:
                filepath = parts[1].strip()
                path = Path(filepath)
                if not path.exists():
                    print(Fore.YELLOW + f"  ⚠ Warning: Django file '{filepath}' does not exist (continuing anyway).")
                args.append(filepath)

        elif proj == "BLE":
            if len(parts) >= 3 and parts[1] == "--resume":
                raw_path   = parts[2].strip()                
                if not raw_path.lower().endswith(".json"):
                    print(Fore.RED + "  ✖ BLE resume file must be a .json file.")
                    print_commands()
                    continue

                abs_path = (PROJECT_ROOT /"BLE" / raw_path).expanduser().resolve()
                print(abs_path)
                if not abs_path.exists():
                    print(Fore.RED + f"  ✖ BLE resume file '{raw_path}' not found. Please check the path.")
                    print_commands()
                    continue
                args.extend(["--resume", str(raw_path)])             # store absolute path
            else:
                print(Fore.RED + "  ✖ For BLE, use: BLE --resume <filepath> or BLE")
                print_commands()
                continue
        return args


def ensure_ble_app_available():
    base = Path(__file__).parent
    smartlock_file = base / "BLE/Smartlock.py"

    if not smartlock_file.is_file():
        print(Fore.RED + f"ERROR: 'Smartlock.py' not found at {smartlock_file!r}")
        sys.exit(1)
 
def main():

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    current_abs_path = Path(__file__).resolve()
    logging.info(f"Current absolute path: {current_abs_path}")
    args = get_args_interactive()
    if not args:
        print(Fore.RED + "ERROR: No arguments provided.")
        sys.exit(1)

    proj = args[0]

    if proj == "DJANGO":
        ensure_django_app_available()
        if len(args) > 1:
            fuzz_main(Path(args[1]))
        else:
            fuzz_main()

    elif proj == "BLE":
        ensure_ble_app_available()
        if len(args) >= 3 and args[1] == "--resume":
            ble_main(args[2])  # args[2] = filepath
        else:
            ble_main()

if __name__ == "__main__":
    main()
