#!/usr/bin/env python3
import sys
import asyncio
from BLEClient import BLEClient
import datetime
import contextlib
import io

DEVICE_NAME = "Smart Lock [Group 11]"

async def run_test():
    session_output = io.StringIO()
    logs = []

    with contextlib.redirect_stdout(session_output):
        ble = BLEClient()
        ble.init_logs()

        print(f'[1] Connecting to "{DEVICE_NAME}"...')
        await ble.connect(DEVICE_NAME)
        print("[!] Connected.")

        try:
            # ---------------------------------
            #  PLACE YOUR TEST HERE 

            PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
            delay = 0.01
            print("Starting AUTH opcode flood (0x01 to 0xFF)...")

            success = 0
            failures = 0
            errors = 0

            for auth_opcode in range(1, 11):  # Or 1 to 256
                command = [auth_opcode] + PASSCODE
                now = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]

                # Record previous logs to detect new ones after this command
                logs_before = ble.read_logs()

                try:

                    sixty_three = [0X3F,0X3F,0X3F,0X3F,0X3F,0X3F,0X3F]
                    n = 0
                    while (n < 10):
                        res = await ble.write_command(sixty_three)
                        n += 1
                        await asyncio.sleep(delay)
                        now = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
                        print(f"[{now}] [{auth_opcode:03}] AUTH=0x{auth_opcode:x} → Response: {res}")
                        if res and res[0] == 0:
                            success += 1
                        else:
                            failures += 1
                except Exception as e:
                    print(f"[{now}] [CMD {auth_opcode:03}] AUTH=0x{auth_opcode:x} → Exception: {e}")
                    errors += 1

                await asyncio.sleep(delay)
            #  END TEST BLOCK 
            # ---------------------------------

        except Exception as e:
            print(f"\n[!] Exception during test: {e}")

        finally:
            print("[!] Disconnecting...")
            await ble.disconnect()

            logs = ble.read_logs()
            print("\n[ Full ESP32 Logs from this session]")
            if logs:
                for line in logs:
                    log_time = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
                    print(f"[{log_time}]  ESP → {line}")
            else:
                print(" No logs were captured.")

        #  Write all output to log file inside the same redirected block
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        log_filename = f"test_logs_{timestamp}.txt"

        with open(log_filename, "w", encoding="utf-8") as f:
            f.write("[Full Console Output + ESP32 Logs]\n\n")
            f.write(session_output.getvalue())

        print(f"\n[✔] Logs saved to {log_filename}")


if __name__ == "__main__":
    try:
        asyncio.run(run_test())
    except KeyboardInterrupt:
        print("\nProgram Exited by User!")
