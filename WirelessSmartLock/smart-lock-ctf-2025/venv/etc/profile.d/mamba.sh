echo "WARNING: /Users/hongjingtoh/Downloads/WirelessSmartLock/smart-lock-ctf-2025/venv/etc/profile.d/mamba.sh (the file emitting this warning) is deprecated."
echo "WARNING: This file will be removed in mamba 2.1.0."
echo "WARNING: Please use 'mamba shell init' to get the correct shell scripts for your shell."

if [ -z "" ]; then
    echo "WARNING: The MAMBA_ROOT_PREFIX environment variable is not set."
    echo "WARNING: This is required for mamba to work correctly as of 2.0."
    echo "WARNING: "
    echo "WARNING: For now, we are setting 'MAMBA_ROOT_PREFIX' to '/Users/hongjingtoh/Downloads/WirelessSmartLock/smart-lock-ctf-2025/venv'."
    echo "WARNING: "
    echo "WARNING: Please make sure this is consistent with your installation or alternatively (by order of preference):"
    echo "WARNING:   - rerun 'mamba shell init -s posix' to get the correct value"
    echo "WARNING:   - manually set 'MAMBA_ROOT_PREFIX' to the root of your installation in your shell profile script."
    echo "WARNING:   - use the '-r,--root-prefix' CLI option when calling mamba."
    echo "WARNING: "
    echo "WARNING: This message originates from /Users/hongjingtoh/Downloads/WirelessSmartLock/smart-lock-ctf-2025/venv/etc/profile.d/mamba.sh"
    export MAMBA_ROOT_PREFIX="/Users/hongjingtoh/Downloads/WirelessSmartLock/smart-lock-ctf-2025/venv"
fi

__mamba_setup="$("/Users/hongjingtoh/Downloads/WirelessSmartLock/smart-lock-ctf-2025/venv//mamba" shell hook --shell posix 2> /dev/null)"
if [ $? -eq 0 ]; then
    eval "$__mamba_setup"
else
    alias mamba="/Users/hongjingtoh/Downloads/WirelessSmartLock/smart-lock-ctf-2025/venv//mamba"  # Fallback on help from mamba activate
fi
unset __mamba_setup
