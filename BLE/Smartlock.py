import asyncio
import random
import os
import datetime
import sys
import json
from pathlib import Path
import argparse


BASE_DIR = Path(__file__).parent.resolve()
os.chdir(BASE_DIR)
sys.path.append(str(BASE_DIR))

from BLEClient import BLEClient
# === Configuration ===
DEVICE_NAME = "Smart Lock [Group 11]"
PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
AUTH_OPCODE = 0x00

SEED_INPUTS = [
    [[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]],
    [[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06], [0x01]],
    [[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06], [0x01], [0x02]],
    [[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06], [0xAA]],
    [[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06], [0xA]],
    [[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06], [0xB]],
    [[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06], [0x3F]],
    [[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06], [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]],
    [[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06], [0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F]]
]

MAX_ITERATIONS = 10
SLEEP_BETWEEN_COMMANDS = 1.5
SLEEP_AFTER_RECONNECT = 3.0
WEIGHT_DECAY = 0.9
HIGH_WEIGHT = 3.0
LOW_WEIGHT = 0.5

timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
OUTPUT_DIR = os.path.join("AFL_Fuzz_Outputs", f"session_{timestamp}")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# === Globals for tracking ===
seen_log_lines = set()
seen_responses = set()
seen_inputs = set()

# === Helper ===
def make_hashable(x):
    if isinstance(x, list):
        return tuple(make_hashable(i) for i in x)
    return x

# === Mutation ===
def mutate_input(seed):
    # Deep copy the seed properly
    m = [cmd.copy() for cmd in seed]  # every element is a list
    num_mutations = random.randint(1, 4)

    for _ in range(num_mutations):
        mutation_type = random.choice([
            'insert_list', 'delete_list', 'duplicate_list', 'mutate_inside_list'
        ])

        if mutation_type == 'insert_list':
            idx = random.randint(0, len(m))
            new_list = [random.randint(0, 255) for _ in range(random.randint(1, 6))]
            m.insert(idx, new_list)

        elif mutation_type == 'delete_list' and len(m) > 1:
            idx = random.randint(0, len(m) - 1)
            del m[idx]

        elif mutation_type == 'duplicate_list' and len(m) > 0:
            idx = random.randint(0, len(m) - 1)
            m.insert(idx, m[idx].copy())

        elif mutation_type == 'mutate_inside_list' and len(m) > 0:
            idx = random.randint(0, len(m) - 1)
            elem_list = m[idx]
            if len(elem_list) > 0:
                sub_mutation = random.choice(['flip_byte', 'insert_byte', 'delete_byte', 'replace_byte'])

                byte_idx = random.randint(0, len(elem_list) - 1)

                if sub_mutation == 'flip_byte':
                    elem_list[byte_idx] ^= 1 << random.randint(0,7)

                elif sub_mutation == 'insert_byte':
                    elem_list.insert(byte_idx, random.randint(0, 255))

                elif sub_mutation == 'delete_byte' and len(elem_list) > 1:
                    del elem_list[byte_idx]

                elif sub_mutation == 'replace_byte':
                    elem_list[byte_idx] = random.randint(0, 255)

    return m[:256]  # Limit total number of lists

# === Energy Assignment ===
def assign_energy(seed):
    base_energy = 5
    bonus = min(len(seed) // 2, 5)
    return base_energy + bonus

# === Queue Selection ===
def choose_next(queue):
    total_weight = sum(w for _, w in queue)
    choice = random.uniform(0, total_weight)
    upto = 0
    for seq, weight in queue:
        if upto + weight >= choice:
            return seq
        upto += weight
    return random.choice(queue)[0]

# === Interestingness Heuristic ===
def is_interesting(responses, logs):
    global seen_log_lines, seen_responses
    interesting = False

    for line in logs:
        normalized_line = line.strip().lower()
        if normalized_line not in seen_log_lines:
            seen_log_lines.add(normalized_line)
            interesting = True

    for res in responses:
        tuple_res = tuple(res)
        if tuple_res not in seen_responses:
            seen_responses.add(tuple_res)
            interesting = True

    return interesting

# === Save and Load Queue (JSON version) ===
def save_queue(queue):
    filepath = os.path.join(OUTPUT_DIR, "saved_queue.json")
    save_data = {
        "queue": [{"input": seq, "weight": weight} for seq, weight in queue],
        "seen_log_lines": list(seen_log_lines),
        "seen_responses": [list(res) for res in seen_responses],
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(save_data, f, indent=2)
    print(f"[✓] Full state saved to {filepath}")

def load_queue(path):
    global seen_log_lines, seen_responses

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    loaded_queue = [(entry["input"], entry["weight"]) for entry in data["queue"]]
    seen_log_lines = set(data.get("seen_log_lines", []))
    seen_responses = set(tuple(res) for res in data.get("seen_responses", []))

    for input_seq, _ in loaded_queue:
        seen_inputs.add(make_hashable(input_seq))

    print(f"[✓] Loaded {len(loaded_queue)} inputs and full seen sets from {path}")
    return loaded_queue

# === Save interesting test case ===
def save_input(input_seq, logs, responses=None, label="interesting"):
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filepath = os.path.join(OUTPUT_DIR, f"{label}_{ts}.txt")
    with open(filepath, "w", encoding="utf-8") as f:
        # Save input using JSON so it preserves nested structure
        f.write("Input:\n")
        f.write(json.dumps(input_seq, indent=2))
        f.write("\n\n")

        # Save responses if provided
        if responses is not None:
            f.write("Responses:\n")
            f.write(json.dumps(responses, indent=2))
            f.write("\n\n")

        # Save logs
        f.write("Logs:\n")
        for l in logs:
            f.write("  " + l.strip() + "\n")

    print(f"[✓] Saved {label} input to {filepath}")


# === Run Input ===
async def run_target(ble, input_seq):
    responses = []
    logs = []


    for item in input_seq:
        if isinstance(item, list):
            command = item
        else:
            command = [item]

        ble.read_new_logs()
        try:
            res = await ble.write_command(command)
            await asyncio.sleep(SLEEP_BETWEEN_COMMANDS)
            new_logs = ble.read_new_logs()
            print("  [ESP LOGS]")
            for line in new_logs:
                print("   ", line)
        except Exception as e:
            res = [999]
            new_logs = [f"Exception: {e}"]

        responses.append(res)
        logs.extend(new_logs)
    return responses, logs

# === Wait for ESP reboot ===
async def wait_for_esp_reboot_logs(ble, timeout=5):
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        logs = ble.read_new_logs()
        if any("boot:" in line.lower() or "esp-rom" in line.lower() for line in logs):
            return True
        await asyncio.sleep(0.5)
    return False

# === Print Queue Debug Overview ===
def print_queue_overview(queue, top_n=5):
    print("\n[Queue Overview]")
    sorted_q = sorted(queue, key=lambda x: -x[1])
    for idx, (seq, weight) in enumerate(sorted_q[:top_n]):
        print(f" {idx+1:02d}. Weight={weight:.2f} | Input={seq}")
    print(f" [Total entries: {len(queue)}]\n")

# === Main fuzz loop ===
async def afl_fuzz(queue):
    try:
        for i in range(MAX_ITERATIONS):
            print(f"\n[#{i:03}] Starting test cycle...")
            ble = BLEClient()
            ble.init_logs()
            try:
                seed = choose_next(queue)
                energy = assign_energy(seed)
                # ble.init_logs()

                for _ in range(energy):
                    await ble.connect(DEVICE_NAME)
                    await asyncio.sleep(SLEEP_AFTER_RECONNECT)
                    await wait_for_esp_reboot_logs(ble)
                    # Always send valid authentication first
                    print("AUTHENTICATING FIRST BEFORE TESTING")
                    auth_command = [0x00] + PASSCODE
                    await ble.write_command(auth_command)
                    await asyncio.sleep(SLEEP_BETWEEN_COMMANDS)
                    print("AUTHENTICATING COMPLETE, RUNNING TEST")
                    mutated = mutate_input(seed)

                    if make_hashable(mutated) in seen_inputs:
                        print("[!] Skipping duplicate mutated input.")
                        await ble.disconnect()
                        await asyncio.sleep(SLEEP_AFTER_RECONNECT)
                        continue

                    print("Currently testing mutated input:", mutated)
                    responses, logs = await run_target(ble, mutated)

                    is_interesting_case = is_interesting(responses, logs)
                    new_weight = HIGH_WEIGHT if is_interesting_case else LOW_WEIGHT
                    queue.append((mutated, new_weight))
                    seen_inputs.add(make_hashable(mutated))

                    if is_interesting_case:
                        save_input(mutated, logs, responses)

                    await ble.disconnect()
                    await asyncio.sleep(SLEEP_AFTER_RECONNECT)

                for idx in range(len(queue)):
                    seq, w = queue[idx]
                    queue[idx] = (seq, w * WEIGHT_DECAY)

                print_queue_overview(queue)

            except Exception as e:
                print(f"[!] Error in cycle #{i}: {e}")
                await ble.disconnect()

    except KeyboardInterrupt:
        print("\n[!] Fuzzing interrupted.")

    finally:
        save_queue(queue)
        print("\n[✓] Fuzzing complete.")
        sys.exit(0)


def start_ble_fuzzing(optional_resume_file: str = None):
    if optional_resume_file:
        if os.path.exists(optional_resume_file):
            print(f"[✓] Resuming from {optional_resume_file}")
            queue = load_queue(optional_resume_file)
        else:
            print(f"[X] Queue file not found: {optional_resume_file}")
            sys.exit(1)
    else:
        queue = [(seed, 1.0) for seed in SEED_INPUTS]
        for seed in SEED_INPUTS:
            seen_inputs.add(make_hashable(seed))

    asyncio.run(afl_fuzz(queue))


# === Entrypoint ===
if __name__ == "__main__":
    print("This is a fun script to fuzz a BLE device.")

    parser = argparse.ArgumentParser()
    parser.add_argument("--resume", type=str, help="Path to previous saved_queue.json")
    args = parser.parse_args()

    start_ble_fuzzing(args.resume)

# if __name__ == "__main__":
#     print("This is a fun script to fuzz a BLE device.")
    

#     parser = argparse.ArgumentParser()
#     parser.add_argument("--resume", type=str, help="Path to previous saved_queue.json")
#     args = parser.parse_args()

#     if args.resume:
#         if os.path.exists(args.resume):
#             queue = load_queue(args.resume)
#         else:
#             print(f"[X] Queue file not found: {args.resume}")
#             sys.exit(1)
#     else:
#         queue = [(seed, 1.0) for seed in SEED_INPUTS]
#         for seed in SEED_INPUTS:
#             seen_inputs.add(make_hashable(seed))

#     asyncio.run(afl_fuzz(queue))
