import asyncio
import random
import os
import datetime
import sys
from BLEClient import BLEClient

DEVICE_NAME = "Smart Lock [Group 11]"
PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
AUTH_OPCODE = 0x00

# --- Configuration ---
SEED_INPUTS = [
    [0x00],               # AUTH
    [0x00, 0x01],         # AUTH → OPEN
    [0x00, 0x01, 0x02],   # AUTH → OPEN → CLOSE
    [0xAA],               # Hidden command
    [0xA],
    [0xB],
    [0x3F]
]
VALID_OPCODES = [0x00, 0x01, 0x02, 0xAA]
MAX_ITERATIONS = 50
SLEEP_BETWEEN_COMMANDS = 2.0
SLEEP_AFTER_RECONNECT = 5.0
timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
OUTPUT_DIR = os.path.join("fuzz_outputs", f"session_{timestamp}")
os.makedirs(OUTPUT_DIR, exist_ok=True)

#global set, used to store seen log lines, for is_interesting criteria
seen_log_lines = set()


# --- Mutation Engine ---
def mutate_input(seed):
    # m = seed.copy()
    # mutation_type = random.choice(['flip', 'append', 'delete', 'replace', 'insert_random'])

    # if mutation_type == 'flip' and len(m) > 0:
    #     idx = random.randint(0, len(m) - 1)
    #     m[idx] ^= 0xFF

    # elif mutation_type == 'append':
    #     m.append(random.randint(0x00, 0xFF))  # Append a fully random byte
    # elif mutation_type == 'delete' and len(m) > 1:
    #     idx = random.randint(0, len(m) - 1)
    #     del m[idx]
    # elif mutation_type == 'replace' and len(m) > 0:
    #     idx = random.randint(0, len(m) - 1)
    #     m[idx] = random.randint(0x00, 0xFF)  # Replace with random byte
    # elif mutation_type == 'insert_random':
    #     idx = random.randint(0, len(m))
    #     m.insert(idx, random.randint(0x00, 0xFF))  # Insert random byte at random position

    # return m[:256]

# --- Interesting Detection ---
def is_interesting(responses, logs):
    # global seen_log_lines
    # interesting = False

    # for line in logs:
    #     if line not in seen_log_lines:
    #         seen_log_lines.add(line)
    #         interesting = True
    # return interesting

# --- Save Result ---
def save_input(input_seq, logs, label="interesting"):
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filepath = os.path.join(OUTPUT_DIR, f"{label}_{ts}.txt")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("Input: " + " ".join(hex(x) for x in input_seq) + "\n")
        f.write("Logs:\n")
        for l in logs:
            f.write("  " + l.strip() + "\n")
    print(f"[✓] Saved {label} input to {filepath}")

# --- Run Input on Device ---
async def run_target(ble, input_seq):
    responses = []
    full_logs = []

    for opcode in input_seq:
        command = [opcode]
        if opcode == AUTH_OPCODE:
            command += PASSCODE

        ble.read_new_logs()  # Clear previous logs
        try:
            res = await ble.write_command(command)
            await asyncio.sleep(SLEEP_BETWEEN_COMMANDS)
            logs = ble.read_new_logs()
        except Exception as e:
            res = [999]
            logs = [f"Exception during BLE write: {e}"]

        responses.append(res)
        full_logs.extend(logs)
        for line in logs:
            print("  [ESP]", line)

    return responses, full_logs

# --- Wait for ESP Reboot Indicator ---
async def wait_for_esp_reboot_logs(ble, timeout=5):
    print("[*] Waiting for ESP reboot logs...")
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        logs = ble.read_new_logs()
        if any("boot:" in line.lower() or "esp-rom" in line.lower() for line in logs):
            print("[✓] Detected ESP reboot.")
            return True
        await asyncio.sleep(0.5)
    print("[!] ESP reboot not detected within timeout.")
    return False

def choose_next(queue):
    if random.random() < 0.7:
        return queue[-1]  # new discovery
    return random.choice(queue)

def assign_energy(seed):
    return random.randint(2, 5)

# --- Main Fuzzer ---
async def afl_fuzz():
    queue = SEED_INPUTS[:]

    try:
        for i in range(MAX_ITERATIONS): #limitation, else can remove to run forever
            print(f"\n[#{i:03}] Starting new test cycle...")
            print(f"length of queue: {len(queue)}")
            ble = BLEClient()

            try:
                #1. choose a seed from queue, then assign energy
                seed = random.choice(queue)
                energy = assign_energy(seed)
                #example seed ([0x00, 0x01, ....] || [0x01] etc...)

                for _ in range(energy):
                    #connecting and rebooting esp logs
                    await ble.connect(DEVICE_NAME)
                    ble.init_logs()
                    await asyncio.sleep(SLEEP_AFTER_RECONNECT)
                    await wait_for_esp_reboot_logs(ble)

                    #2. mutate input
                    mutated = mutate_input(seed)
                    print(f"MUTATED SEED BEING TESTED: {mutated}")
                    responses, logs = await run_target(ble, mutated)
                    print(f"RESULTING LOGS: {logs}")
                    if is_interesting(responses, logs):
                        save_input(mutated, logs, "interesting")
                        queue.append(mutated)

                    await ble.disconnect()
                    print(f"[#{i:03}] Disconnected and reset complete.")
                    await asyncio.sleep(SLEEP_AFTER_RECONNECT)

            except Exception as e:
                print(f"[!] Exception during test #{i}: {e}")

            finally:
                await ble.disconnect()
                print(f"[#{i:03}] Disconnected and reset complete.")
                await asyncio.sleep(SLEEP_AFTER_RECONNECT)

    except KeyboardInterrupt:
        print("\n[!] Fuzzing interrupted by user.")

    print("\n[✓] Fuzzing complete.")
    sys.exit(0)

if __name__ == "__main__":
    asyncio.run(afl_fuzz())
