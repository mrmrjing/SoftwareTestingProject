import requests
import random
import json
import copy
import time
import subprocess  

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

# Energy Generation: Naive approach of assigning a fixed energy value to each input 
ENERGY = 10


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
# Mutation Engine 
# ==============================================================

def mutate_form_data(form_data):
    """
    Apply a mutation on the input form data.
    For numeric fields, generate edge cases (negative or high values).
    For string fields, either append extra characters or truncate the string.
    """
    mutated_data = copy.deepcopy(form_data)
    # Choose a random field to mutate
    field = random.choice(list(mutated_data.keys()))
    
    if field == 'price':
        # For the price, sometimes generate negative or unusually high values.
        if random.random() < 0.5:
            mutated_data[field] = random.randint(-100, 0)  # Negative edge case
        else:
            mutated_data[field] = random.randint(100, 1000)  # High value edge case
    else:
        # For 'name' and 'info', either append or truncate characters.
        if random.random() < 0.5:
            mutated_data[field] += ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=3))
        else:
            mutated_data[field] = mutated_data[field][:max(1, len(mutated_data[field]) - 2)]
    return mutated_data

# ==============================================================
# Django Target Interface 
# ==============================================================

def send_post_request(form_data):
    """
    Sends an HTTP POST request with the given form_data to the Django application.
    Returns the response object or None if there's an exception.
    """
    url = BASE_URL + ENDPOINT
    try:
        response = requests.post(url, headers=HEADERS, data=json.dumps(form_data))
        return response
    except requests.exceptions.RequestException as e:
        print("Error sending request:", e)
        return None

def check_response(response):
    """
    Analyze the response from the Django server.
    Returns a dictionary with:
      - status: "success", "crash", "unexpected", or "error"
      - status_code: the HTTP response code
      - response_text: the response body
    """
    result = {}
    if response is None:
        result['status'] = "error"
        result['error'] = "No response"
        return result
    
    result['status_code'] = response.status_code
    result['response_text'] = response.text

    if response.status_code in [200, 201]:
        result['status'] = "success"
    elif response.status_code >= 500:
        result['status'] = "crash"
    else:
        result['status'] = "unexpected"
    return result

# ==============================================================
# Feedback Engine
# ==============================================================

def evaluate_response(response_result):
    """
    Evaluate whether the response is interesting.
    For now, an "interesting" response is one that indicates a server crash.
    This function can be extended with additional heuristics.
    """
    if response_result.get("status") == "crash":
        return True
    return False

# ==============================================================
# Coverage Integration
# ==============================================================

def update_and_print_coverage():
    """
    Integrate with coverage.py to update and print the current coverage report.
    Assumes that your Django server is running with coverage enabled.
    This function runs:
      - 'coverage combine' to combine data from parallel runs, and
      - 'coverage report' to print the report.
    """
    try:
        # Combine coverage data (if Django was run with parallel mode)
        subprocess.run(["coverage", "combine"], check=True)
        # Run the coverage report command and capture its output
        result = subprocess.run(["coverage", "report"], check=True, capture_output=True, text=True)
        print("\n=== Coverage Report ===")
        print(result.stdout)
    except Exception as e:
        print("Coverage update failed:", e)

# ==============================================================
# Main Fuzzer Loop
# ==============================================================

def main():
    # Initialize the seed corpus with a single seed
    # Each entry in the corpus is a dictionary representing containing the following: 
    #   - 'payload': the HTTP input (a dictionary)
    #   - 'energy': number of times to fuzz this input.
    corpus = [{'payload': generate_seed(), 'energy': ENERGY}]
    
    iteration = 0
    max_iterations = 50  # Adjust the total number of iterations as needed

    while iteration < max_iterations and corpus:
        print(f"\nIteration: {iteration}")
        
        # Select the first seed from the corpus
        seed_entry = corpus[0]
        seed = seed_entry['payload']
        
        # Apply a mutation to the seed payload
        mutated_input = mutate_form_data(seed)
        print("Mutated input:", mutated_input)
        
        # Send the mutated input to the Django target
        response = send_post_request(mutated_input)
        
        # Analyze the response from the Django application
        result = check_response(response)
        print("Response result:", result)
        
        # Evaluate the response using the feedback engine
        if evaluate_response(result):
            print("Found interesting input (crash detected)! Adding it to the corpus.")
            # Add the mutated input as a new seed with full energy.
            corpus.append({'payload': mutated_input, 'energy': ENERGY})
        else:
            print("Input not interesting.")
        
        # Reduce the energy of the current seed by 1
        seed_entry['energy'] -= 1
        # Remove the seed if its energy is exhausted.
        if seed_entry['energy'] <= 0:
            corpus.pop(0)
        
        iteration += 1

        # Optionally update and print the coverage report every 10 iterations
        if iteration % 10 == 0:
            update_and_print_coverage()
        
        time.sleep(0.5)  # Delay to avoid overloading the server

if __name__ == "__main__":
    main()