import sys
from dataclasses import dataclass
from typing import Optional
import os

try:
    from simple_fuzzer_v1 import fuzz as django_default_fuzzer
    from simple_fuzzer_v2 import main as django_v2_fuzzer
except ImportError as e:
    print(f"Error: Could not import fuzzer modules.s {e}")
    print("Make sure simple_fuzzer_v1.py and simple_fuzzer_v2.py are in the same directory as main.py.")
    sys.exit(1)

# Dictionary of valid project types and their enabled/disabled status.
VALID_PROJECT_TYPES = {
    "BLE": False,
    "DJANGO": True,
}

@dataclass
class CLIArgs:
    """
    Dataclass to store command-line arguments.

    Attributes:
        project_type (str): The type of project to fuzz (e.g., DJANGO).
        project_mode (str): The mode of operation ("default" or "custom").
        energy (Optional[int]): The energy parameter for custom mode. Defaults to None.
    """
    project_type: str
    project_mode: str  # either "default" or "custom"
    energy: Optional[int] = None

def validate_command_line_args() -> CLIArgs:
    """
    Validates command-line arguments and returns a CLIArgs object.

    The accepted argument lengths are:
      - 1: No additional arguments provided; displays usage.
      - 3: Default mode (project_type and project_mode provided).
      - 4: Custom mode (project_type, project_mode, and energy provided).

    If the arguments do not match one of these cases, the program exits with an error message.

    Returns:
        CLIArgs: The validated command-line arguments.
    """
    arg_len = len(sys.argv)
    
    if arg_len == 1:
        # No arguments provided.
        print("\nNo arguments provided.")
        print("Usage: make run ARG=<project_type> <project_mode> [<energy> if project_mode is custom]")
        print("Available project types:")
        for project, is_enabled in VALID_PROJECT_TYPES.items():
            status = "ENABLED" if is_enabled else "DISABLED"
            print(f" - {project} [{status}]")
        sys.exit(1)
        
    elif arg_len == 3:
        # Default mode: project_type and project_mode provided.
        project_type = sys.argv[1].upper()
        project_mode = sys.argv[2].lower()
        energy = None
        
    elif arg_len == 4:
        # Custom mode: project_type, project_mode, and energy provided.
        project_type = sys.argv[1].upper()
        project_mode = sys.argv[2].lower()
        try:
            energy = int(sys.argv[3])
        except ValueError:
            print(f"\nError: Energy '{sys.argv[3]}' is not a valid integer.")
            sys.exit(1)
        if energy < 1:
            print("\nError: Energy must be a positive integer.")
            sys.exit(1)
    else:
        print("\nInvalid number of arguments.")
        print("Usage: make run ARG=<project_type> <project_mode> [<energy> if project_mode is custom]")
        sys.exit(1)

    # Validate project_mode
    if project_mode not in ["default", "custom"]:
        print(f"\nInvalid project mode: '{project_mode}'")
        print("Valid project modes are: default, custom")
        sys.exit(1)

    # Validate project_type
    if project_type not in VALID_PROJECT_TYPES:
        print(f"\nInvalid project type: '{project_type}'")
        print("Valid project types are:")
        for project in VALID_PROJECT_TYPES:
            print(f" - {project}")
        sys.exit(1)

    if not VALID_PROJECT_TYPES[project_type]:
        print(f"\nProject '{project_type}' is currently DISABLED.")
        sys.exit(1)

    print(f"Starting {project_type} Fuzzer in {project_mode} mode" + (f" with energy {energy}" if energy is not None else ""))
    return CLIArgs(project_type=project_type, project_mode=project_mode, energy=energy)

def main():
    """
    Main function that validates command-line arguments and starts the appropriate fuzzer.
    """
    args = validate_command_line_args()
    print(f"Validated arguments: {args}") # Keep for confirmation

    if args.project_type == "DJANGO":
        if args.project_mode == "v1":
            print("\n---> Starting Django Default Fuzzer <---")
            try:
                django_default_fuzzer() 
                print("\n---> Django Default Fuzzer Finished <---")
            except Exception as e:
                print(f"\nError during Django fuzzing: {e}")
                sys.exit(1)
        elif args.project_mode == "v2":
            print("\n---> Starting Django V2 fuzzer <---")
            try:
                django_v2_fuzzer() 
                print("\n---> Django Default Fuzzer Finished <---")
            except Exception as e:
                print(f"\nError during Django fuzzing: {e}")
                sys.exit(1)
        elif args.project_mode == "custom":
            print(f"\n---> Starting Django Custom Fuzzer (Energy: {args.energy}) <---")
            print("Note: Custom Django fuzzing is not fully implemented yet.")
            print("Running default Django fuzzer as a placeholder...")
            try:
                django_default_fuzzer() # Or call a custom version: django_custom_fuzzer(args.energy)
                print("\n---> Django Custom Fuzzer Finished (Placeholder) <---")
            except Exception as e:
                print(f"\nError during placeholder custom Django fuzzing: {e}")
                sys.exit(1)

if __name__ == "__main__":
    main()

