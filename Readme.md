# Fuzzer CLI

This project is a command-line interface (CLI) for launching a fuzzing tool. The tool supports different project types and modes, allowing you to configure the fuzzing run through command-line arguments.

Currently, the available project types are:  
- **DJANGO** (enabled)  
- **BLE** (disabled)

The CLI accepts a project type and a project mode. The project mode can be either:
- **default** – Run with default parameters.
- **custom** – In this mode, you must also provide an energy value (a positive integer) that configures the fuzzing intensity.

## Usage

The expected command-line syntax is:

```bash
make run ARG=<project_type> <project_mode> [<energy> if project_mode is custom]
```

### Examples

- **Default mode (custom energy not required):**
  ```bash
  make run ARG=DJANGO default
  ```
- **Custom mode (energy must be provided):**
  ```bash
  make run ARG=DJANGO custom 100
  ```

If no arguments are provided, or if an invalid number of arguments is given, the tool prints a usage message and exits.

## How It Works

1. **Argument Parsing:**
   - If no extra arguments are provided, the CLI prints a usage message along with the list of available project types.
   - If three arguments are provided, the tool assumes you want to run in _default_ mode.
   - If four arguments are provided, the tool assumes you want to run in _custom_ mode and attempts to parse the energy value.

2. **Validation:**
   - The CLI validates that the given project type exists and is enabled.
   - It checks that the project mode is either `default` or `custom`.
   - For custom mode, it ensures that the energy is a valid, positive integer.

3. **Dispatching:**
   - After successful validation, the CLI prints a startup message showing the chosen configuration.
   - The tool is then ready to dispatch to the appropriate fuzzing logic (e.g., DJANGO or BLE). Currently, the dispatch code is a placeholder.

## Inline Code Documentation

```python
import sys
from dataclasses import dataclass
from typing import Optional

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
    Main function that validates command-line arguments and starts the fuzzer.
    """
    args = validate_command_line_args()
    print(args)

if __name__ == "__main__":
    main()
```

## Future Enhancements

- **Additional Parameters:**  
  More arguments can be added for further configuration (e.g., target URL, log file location, etc.).

- **Enhanced Dispatching:**  
  The current dispatch mechanism for different project types can be extended as new fuzzing targets are enabled.

- **Error Handling and Logging:**  
  Consider integrating a logging framework for better runtime diagnostics.

---

This documentation and README should help users understand the purpose, usage, and internal workings of your CLI tool while making it easier to extend in the future.