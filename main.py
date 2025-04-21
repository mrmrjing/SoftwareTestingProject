
#!/usr/bin/env python3
import logging
import sys
from pathlib import Path
from typing import List

from colorama import init, Fore, Style

# Initialize colorama (on Windows this will convert ANSI codes into Win32 calls)
init(autoreset=True)

# Dictionary of valid project types and their enabled/disabled status.
VALID_PROJECT_TYPES = {
    "BLE": False,
    "DJANGO": True,
}


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

    # Print a green confirmation instead of raw logging
    print(Fore.GREEN + f"✔ Launching fuzzer with args: {args}")

    # … dispatch to your fuzzer entrypoint here …


if __name__ == "__main__":
    main()
