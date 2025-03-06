import requests
import random
import json
import copy
import time
from coverage import Coverage

# ==============================================================
# Configuration Parameters
# ==============================================================

# URL configuration for your Django app
BASE_URL = 'http://127.0.0.1:8000/datatb/product/'
ENDPOINT = 'add/'

# Adjust headers with valid CSRF and session tokens as needed.
HEADERS = {
    'Content-Type': 'application/json',
    'Cookie': 'csrftoken=VALID_CSRF_TOKEN; sessionid=VALID_SESSION_ID',
}
# Naive way of assigning energy: Fixed initial energy and maximum iterations
INITIAL_ENERGY = 10
MAX_ITERATIONS = 50  # Adjust as needed

# ==============================================================
# Coverage Tracking System
# ==============================================================
class CoverageManager:
    def __init__(self):
        self.cov = Coverage()
        self.covered_lines = set()
        
    def start_tracking(self):
        """Start measuring code coverage"""
        self.cov.start()
        
    def stop_tracking(self):
        """Stop measuring, update and return new coverage count"""
        self.cov.stop()
        self.cov.save()
        coverage_data = self.cov.get_data()
        new_lines = set()
        
        for file in coverage_data.measured_files():
            lines = coverage_data.lines(file)
            new_lines.update([(file, line) for line in lines])
            
        # New coverage lines are those not already seen
        new_coverage = new_lines - self.covered_lines
        self.covered_lines.update(new_lines)
        return len(new_coverage)

# ==============================================================
# Seed Generation (from fill_table.py)
# ==============================================================
def generate_seed():
    """
    Generate a seed payload with random form data.
    This seed will be used as the starting point for fuzzing.
    """
    random_name = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=10))
    random_info = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=4))
    random_price = random.randint(1, 100)
    form_data = {
        'name': random_name,
        'info': random_info,
        'price': random_price,
    }
    return form_data

# ==============================================================
# Mutation Engine with Dynamic Energy
# ==============================================================
def mutate_form_data(form_data, energy):
    """
    Apply multiple mutations based on the given energy level.
    For each mutation, a random field is selected and modified.
    """
    mutated = copy.deepcopy(form_data)
    # More energy results in a higher chance for multiple mutations.
    num_mutations = random.randint(1, max(1, energy // 2))
    for _ in range(num_mutations):
        field = random.choice(list(mutated.keys()))
        if field == 'price':
            mutated[field] = random.choice([-100, 0, 10**6, 'NaN', '100'])
        else:
            mutated[field] = ''.join(random.choices(
                'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\x00<>\'\"&%$#@!',
                k=random.randint(0, 1000)
            ))
    return mutated

# ==============================================================
# Django Target Interface
# ==============================================================
def send_post_request(payload):
    """
    Sends an HTTP POST request with the given payload to the Django application.
    Returns the response object or None if an exception occurs.
    """
    try:
        response = requests.post(
            BASE_URL + ENDPOINT,
            headers=HEADERS,
            data=json.dumps(payload),
            timeout=5
        )
        return response
    except Exception:
        return None

# ==============================================================
# Energy Calculation Based on Coverage
# ==============================================================
def calculate_energy(new_coverage_count):
    """
    Dynamically assign energy based on the number of new coverage lines.
    """
    return max(1, INITIAL_ENERGY + new_coverage_count * 2)

# ==============================================================
# Greybox Fuzzer with Corpus Management
# ==============================================================
class GreyboxFuzzer:
    def __init__(self):
        self.cov_mgr = CoverageManager()
        # Each corpus entry holds the payload, its current energy, and the last coverage count.
        self.corpus = [{
            'payload': generate_seed(),
            'energy': INITIAL_ENERGY,
            'coverage': 0
        }]
        self.crashes = []
        
    def run_iteration(self):
        if not self.corpus:
            return False
        
        # Select the seed with the highest energy from the corpus.
        seed_entry = max(self.corpus, key=lambda x: x['energy'])
        
        # Mutate the selected seed based on its energy.
        mutated = mutate_form_data(seed_entry['payload'], seed_entry['energy'])
        
        # Measure code coverage for this mutated input.
        self.cov_mgr.start_tracking()
        response = send_post_request(mutated)
        new_coverage = self.cov_mgr.stop_tracking()
        
        # Determine the outcome based on the response.
        status = "success"
        if response is None:
            status = "crash"
        elif response.status_code >= 500:
            status = "crash"
        
        # If new coverage is discovered or a crash occurs, add the mutated input to the corpus.
        if new_coverage > 0 or status == "crash":
            new_energy = calculate_energy(new_coverage)
            self.corpus.append({
                'payload': mutated,
                'energy': new_energy,
                'coverage': new_coverage
            })
            if status == "crash":
                self.crashes.append(mutated)
        
        # Reduce the energy of the current seed; remove it if exhausted.
        seed_entry['energy'] -= 1
        if seed_entry['energy'] <= 0:
            self.corpus.remove(seed_entry)
            
        return True
    
    def print_stats(self):
        print(f"\n[Stats] Corpus: {len(self.corpus)} | Crashes: {len(self.crashes)}")
        print(f"Total coverage: {len(self.cov_mgr.covered_lines)} lines")

# ==============================================================
# Execution
# ==============================================================
def main():
    fuzzer = GreyboxFuzzer()
    print("Starting greybox fuzzer...")
    
    for i in range(MAX_ITERATIONS):
        print(f"\n--- Iteration {i+1}/{MAX_ITERATIONS} ---")
        if not fuzzer.run_iteration():
            break
        if (i+1) % 10 == 0:
            fuzzer.print_stats()
        time.sleep(0.1)
    
    print("\n=== Final Results ===")
    fuzzer.print_stats()
    if fuzzer.crashes:
        print("\nCrashes found:")
        for crash in fuzzer.crashes:
            print(json.dumps(crash, indent=2))

if __name__ == "__main__":
    main()
