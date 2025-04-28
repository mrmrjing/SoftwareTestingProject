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
    print(Fore.MAGENTA + "  BLE JSON filepath" + Style.RESET_ALL)


# def get_args_interactive() -> List[str]:
#     prompt = Fore.CYAN + "Enter command: " + Style.RESET_ALL

#     # show available commands once at start
#     print_commands()

#     while True:
#         raw = input(prompt).strip()
#         if not raw:
#             # empty input → retry
#             continue

#         # split into at most two parts: project and optional filepath
#         parts = raw.split(maxsplit=1)
#         proj = parts[0].upper()

#         # validate project type
#         if proj not in VALID_PROJECT_TYPES:
#             valid_choices = ", ".join(VALID_PROJECT_TYPES.keys())
#             print(Fore.RED + f"  ✖ Unknown project type '{proj}'. Valid choices: {valid_choices}")
#             print_commands()
#             continue
#         if not VALID_PROJECT_TYPES[proj]:
#             print(Fore.RED + f"  ✖ '{proj}' support is currently disabled.")
#             print_commands()
#             continue

#         args = [proj]


#         if len(parts) == 2 and parts[1].strip():
#             args.append(parts[1].strip())
#         # valid args gathered
#         return args
    
def get_args_interactive() -> List[str]:
    prompt = Fore.CYAN + "Enter command: " + Style.RESET_ALL

    print_commands()

    while True:
        raw = input(prompt).strip()
        if not raw:
            continue

        parts = raw.split(maxsplit=1)
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

        # if user gave a second argument (filepath)
        if len(parts) == 2 and parts[1].strip():
            filepath = parts[1].strip()
            path = Path(filepath)

            if proj == "DJANGO":
                if not path.exists():
                    print(Fore.YELLOW + f"  ⚠ Warning: Django file '{filepath}' does not exist (continuing anyway).")
                args.append(filepath)

            elif proj == "BLE":
                if not path.exists():
                    print(Fore.RED + f"  ✖ BLE resume file '{filepath}' not found. Please check the path.")
                    continue  # force user to re-enter input
                args.append(filepath)

        return args
    

def ensure_ble_app_available():
    base = Path(__file__).parent
    smartlock_file = base / "BLE/Smartlock.py"

    if not smartlock_file.is_file():
        print(Fore.RED + f"ERROR: 'Smartlock.py' not found at {smartlock_file!r}")
        sys.exit(1)
    
def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    args = get_args_interactive()
    if not args:
        print(Fore.RED + "ERROR: No arguments provided.")
        sys.exit(1)

    if args[0] == "DJANGO":
        ensure_django_app_available()
        if len(args) > 1:
            fuzz_main(Path(args[1]))
        else:
            fuzz_main()

    elif args[0] == "BLE":
        ensure_ble_app_available()
        if len(args) > 1:
            ble_main(args[1])
        else:
            ble_main()
    


    
if __name__ == "__main__":
    main()
