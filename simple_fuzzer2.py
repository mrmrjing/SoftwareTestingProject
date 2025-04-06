# fuzzer_v2.py

import hashlib
import requests
import random
import string
import copy
import logging
import time
import json
import os
import datetime
import traceback
import subprocess


# --- Logging configuration ---
# Set up a logger for the fuzzer with both file and console handlers

logger = logging.getLogger("GreyboxFuzzer")
logger.setLevel(logging.INFO)

# Ensure the directory for log files exists
os.makedirs("logs", exist_ok=True)

# Create a timestamp to uniquely name log files
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

# Set up a file handler for logging to a file
file_handler = logging.FileHandler(f"logs/fuzz_log_{timestamp}.txt")
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Set up a console handler to output logs to the console
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# --- Define endpoints and HTTP methods ---
# These are the target API endpoints and the methods to be tested

ENDPOINTS = [
    "/datatb/product/",
    "/datatb/product/add/",
    "/datatb/product/edit/{id}/",
    "/datatb/product/delete/{id}/",
    "/datatb/product/export/"
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE"]

# Default payload used for requests that require a payload
DEFAULT_PAYLOAD = {
    "name": "test_product",
    "info": "test_info",
    "price": 100
}

# --- Request data structure ---
# A helper class to encapsulate HTTP requests for fuzzing

class Request:
    def __init__(self, method, url, payload=None, headers=None):
        self.method = method        # HTTP method (GET, POST, etc.)
        self.url = url              # Full URL for the request
        self.payload = payload      # Optional payload (for POST/PUT requests)
        self.headers = headers or {}  # Headers (default to empty dict if None)
    
    def __str__(self):
        return f"Request({self.method} {self.url}, payload={self.payload})"
    
    def to_dict(self):
        """Convert request details into a dictionary for logging purposes.
           Excludes sensitive headers (e.g., authorization tokens)."""
        return {
            "method": self.method,
            "url": self.url,
            "payload": self.payload,
            "headers": {k: v for k, v in self.headers.items() if k.lower() != "authorization"}
        }

# --- Fuzzer Client class ---
# Encapsulates the logic for interacting with the target application, including authentication and crash logging

class FuzzerClient:
    def __init__(self, base_url="http://127.0.0.1:8000"):
        self.base_url = base_url
        self.headers = {}
        
        # Initialize SeedQ and FailureQ
        self.SeedQ = self.initialize_seed_queue()
        self.FailureQ = {}
        
        # For tracking interesting tests
        self.interesting_time = {0: datetime.datetime.now().isoformat()}
        self.failure_time = {0: datetime.datetime.now().isoformat()}
        self.tests = {0: datetime.datetime.now().isoformat()}
        self.test_id = 1
        
        # Create directory for session data
        self.session_folder = self.create_session_folder()
    
    def create_session_folder(self):
        """Create a numbered session folder for storing results"""
        base_folder = os.path.join("sessions", "http")
        os.makedirs(base_folder, exist_ok=True)
        
        session_folders = [f for f in os.listdir(base_folder) if f.startswith("session")]
        if session_folders:
            session_folders.sort(key=lambda x: int(x.split()[-1]))
            last_session = session_folders[-1]
            session_number = int(last_session.split()[-1]) + 1
        else:
            session_number = 1
            
        session_folder = os.path.join(base_folder, f"session {session_number}")
        os.makedirs(session_folder, exist_ok=True)
        return session_folder
    
    def initialize_seed_queue(self):
        """Initialize the SeedQ with endpoints and their valid methods/payloads"""
        SeedQ = {}
        
        for endpoint in ENDPOINTS:
            # For endpoints with ID parameters, we'll add them with placeholders
            SeedQ[endpoint] = {
                "methods": {},
                "seeds": [copy.deepcopy(DEFAULT_PAYLOAD)]
            }
            
            # Assign appropriate methods for each endpoint
            if endpoint == "/datatb/product/add/":
                SeedQ[endpoint]["methods"] = {"POST": True, "GET": True}
            elif "/edit/" in endpoint:
                SeedQ[endpoint]["methods"] = {"PUT": True, "GET": True}
            elif "/delete/" in endpoint:
                SeedQ[endpoint]["methods"] = {"DELETE": True, "GET": True}
            elif "/export/" in endpoint:
                SeedQ[endpoint]["methods"] = {"GET": True, "POST": True}
            else:
                SeedQ[endpoint]["methods"] = {method: True for method in HTTP_METHODS}
        
        return SeedQ
    
    def register_user(self, username, password, email):
        """Register a user account using the provided credentials"""
        registration_url = f"{self.base_url}/accounts/register/"
        payload = {
            "username": username,
            "email": email,
            "password1": password,
            "password2": password
        }
        try:
            response = requests.post(registration_url, data=payload, timeout=10)
            if response.status_code in (200, 201):
                logger.info("User registration successful!")
                return True
            else:
                logger.error(f"User registration failed. Status code: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Registration exception: {e}")
            return False

    def login_user(self, username, password):
        """
        Log in a user using provided credentials.
        Returns the authentication token if login is successful.
        """
        login_url = f"{self.base_url}/login/jwt/"
        payload = {"username": username, "password": password}
        try:
            response = requests.post(login_url, json=payload, timeout=10)
            if response.status_code == 200:
                token = response.json().get("token")
                if token:
                    logger.info("Login successful!")
                    return token
                else:
                    logger.error("Login response did not contain a token")
                    return None
            else:
                logger.error(f"Login failed. Status code: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Login exception: {e}")
            return None

    def ensure_authenticated(self):
        """Ensure that the client is authenticated"""
        test_username = "example"
        test_password = "example"
        test_email = "example@example.com"
        
        token = self.login_user(test_username, test_password)
        if token is None:
            logger.info("Test user not found or login failed; attempting registration...")
            if self.register_user(test_username, test_password, test_email):
                time.sleep(2)
                token = self.login_user(test_username, test_password)
                if token:
                    self.headers["Authorization"] = f"Token {token}"
                else:
                    logger.error("Could not authenticate test user")
            return token
        else:
            self.headers["Authorization"] = f"Token {token}"
            return token
    
    def save_session_data(self):
        """Save all session data to files in the session folder"""
        with open(os.path.join(self.session_folder, "SeedQ.json"), "w") as f:
            json.dump(self.SeedQ, f, indent=2)
            
        with open(os.path.join(self.session_folder, "FailureQ.json"), "w") as f:
            json.dump(self.FailureQ, f, indent=2)
            
        with open(os.path.join(self.session_folder, "interesting.json"), "w") as f:
            json.dump(self.interesting_time, f, indent=2)
            
        with open(os.path.join(self.session_folder, "failure.json"), "w") as f:
            json.dump(self.failure_time, f, indent=2)
            
        with open(os.path.join(self.session_folder, "tests.json"), "w") as f:
            json.dump(self.tests, f, indent=2)
        
        logger.info(f"Session data saved to {self.session_folder}")

    def mutate_input(self, s):
        """Implementation of MutateInput from the algorithm"""
        path = s["path"]
        method = s["method"]
        seed = s["seed"]
        
        # Replace {id} in path with a random ID if needed
        current_path = path
        if "{id}" in path:
            id_value = get_random_id()
            current_path = path.replace("{id}", id_value)
        
        # Mutate the seed with varying strategies based on previous results
        # Sometimes make small mutations, sometimes larger ones
        if random.random() < 0.7:  # 70% small mutations
            mutated_seed = mutate_payload(seed, mutation_count=random.randint(1, 3))
        else:  # 30% larger mutations
            mutated_seed = mutate_payload(seed, mutation_count=random.randint(4, 10))
        
        # Generate a unique hash for this mutation to track it
        mutation_id = hashlib.md5(
            json.dumps((method, current_path, mutated_seed), sort_keys=True).encode()
        ).hexdigest()
        
        # Create a request object
        request = Request(
            method=method,
            url=f"{self.base_url}{current_path}",
            payload=mutated_seed if method in ["POST", "PUT"] else None
        )
        request.headers.update(self.headers)
        
        return {
            "request": request,
            "path": path,
            "method": method,
            "seed": mutated_seed,
            "current_path": current_path,
            "mutation_id": mutation_id
        }
    
    def choose_next(self, SeedQ):
        """Implementation of ChooseNext from the algorithm"""
        # Prioritize seeds that haven't been tested yet
        untested_paths = []
        for path in SeedQ:
            methods = [m for m in SeedQ[path]["methods"] if SeedQ[path]["methods"][m]]
            for method in methods:
                if len(SeedQ[path]["seeds"]) > 0:
                    untested_paths.append((path, method))
        
        if untested_paths:
            path, method = random.choice(untested_paths)
            seed = random.choice(SeedQ[path]["seeds"])
            return {"path": path, "method": method, "seed": seed}
        
        return None

    def assign_energy(self, s):
        """Implementation of AssignEnergy from the algorithm"""
        # For simplicity, we'll use a constant energy value
        # In a more sophisticated implementation, you could adjust based on 
        # how much new coverage this seed is likely to generate
        return random.randint(5, 15)  # Try 5-15 mutations for each seed


    # --- Helper functions for the coverage tracking ---

    def read_coverage_data(self):
        """Read the coverage data file produced by the Django middleware"""
        coverage_file = os.path.join("DjangoWebApplication", "coverage_data.json")
        try:
            if os.path.exists(coverage_file):
                with open(coverage_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logger.error(f"Error reading coverage data: {e}")
            return {}

    def get_last_coverage_hash(self):
        """Get the hash of the most recent coverage data"""
        coverage_data = self.read_coverage_data()
        if not coverage_data:
            return None
        
        # Sort by timestamp to get the most recent entry
        sorted_entries = sorted(
            coverage_data.values(), 
            key=lambda x: x.get('timestamp', 0),
            reverse=True
        )
        
        if sorted_entries:
            return sorted_entries[0].get('coverage_hash')
        return None

    def is_interesting(self, s_prime):
        """Check if the mutated input produced new coverage"""
        coverage_data = self.read_coverage_data()
        if not coverage_data:
            return False
        
        # Sort coverage data by timestamp (newest first)
        sorted_entries = sorted(
            coverage_data.values(), 
            key=lambda x: x.get('timestamp', 0),
            reverse=True
        )
        
        # Look for the most recent entry
        if sorted_entries:
            latest_entry = sorted_entries[0]
            # Check if this entry has new coverage
            if latest_entry.get('is_new_coverage', False):
                logger.info(f"Found new coverage path with hash: {latest_entry.get('coverage_hash')}")
                
                # Log some details about what made this interesting
                method = latest_entry.get('method', '')
                path = latest_entry.get('path', '')
                logger.info(f"New coverage from: {method} {path}")
                
                return True
        
        return False


# --- Server control functions ---
def start_django_server():
    """Start the Django development server with coverage enabled"""
    try:
        # Determine the directory of the Django project
        base_dir = os.path.dirname(os.path.abspath(__file__))
        cwd = os.path.join(base_dir, "DjangoWebApplication")
        logger.info(f"Starting Django server with coverage from: {cwd}")

        # Build the command to run the Django server with coverage
        # Using subprocess to run: coverage run manage.py runserver
        cmd = ["coverage", "run", "manage.py", "runserver"]

        # Start the server process
        server_process = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        logger.info("Django server process started with coverage")
        return server_process

    except Exception as e:
        logger.error(f"Failed to start Django server: {e}")
        return None

def wait_for_server(url, timeout=30, interval=0.5):
    """Poll the URL until the server responds or timeout is reached"""
    logger.info(f"Waiting for server at {url} to be available (timeout: {timeout}s)")
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(url, timeout=2)
            logger.info(f"Server is up and running! Status code: {response.status_code}")
            return True
        except requests.RequestException:
            time.sleep(interval)
    logger.error("Server did not start within the specified timeout")
    return False

# --- Mutation helper functions ---
def mutate_string(s, num_mutations=1):
    """Mutate a string by changing, adding, or removing characters"""
    if not s or not isinstance(s, str):
        return s
    
    s_list = list(s)
    for _ in range(num_mutations):
        mutation_type = random.choice(["change", "add", "remove"])
        
        if mutation_type == "change" and s_list:
            index = random.randint(0, len(s_list) - 1)
            s_list[index] = random.choice(string.printable)
        elif mutation_type == "add":
            index = random.randint(0, len(s_list))
            s_list.insert(index, random.choice(string.printable))
        elif mutation_type == "remove" and s_list:
            index = random.randint(0, len(s_list) - 1)
            s_list.pop(index)
    
    return "".join(s_list)

def mutate_integer(n, min_delta=-100, max_delta=100):
    """Mutate an integer by adding a random delta"""
    if not isinstance(n, int):
        try:
            n = int(n)
        except:
            return n
    
    delta = random.randint(min_delta, max_delta)
    return n + delta

def mutate_payload(payload, mutation_count=1):
    """Apply mutations to a payload dictionary with controllable intensity"""
    if not payload:
        return payload
    
    mutated = copy.deepcopy(payload)
    
    # Apply the specified number of mutations
    for _ in range(mutation_count):
        # Choose a mutation strategy
        mutation_type = random.choice([
            "modify_field", "add_field", "remove_field", 
            "change_type", "empty_field", "inject_special_chars"
        ])
        
        if mutation_type == "modify_field" and mutated:
            # Modify an existing field
            if not mutated:
                continue
            key = random.choice(list(mutated.keys()))
            if isinstance(mutated[key], str):
                mutated[key] = mutate_string(mutated[key], random.randint(1, 3))
            elif isinstance(mutated[key], int):
                mutated[key] = mutate_integer(mutated[key])
        
        elif mutation_type == "add_field":
            # Add a new field
            field_name = "".join(random.choices(string.ascii_letters, k=random.randint(3, 10)))
            field_value = random.choice([
                "test_value",
                random.randint(-1000, 1000),
                True,
                [1, 2, 3],
                {"nested": "object"}
            ])
            mutated[field_name] = field_value
        
        elif mutation_type == "remove_field" and mutated:
            # Remove an existing field
            if not mutated:
                continue
            key = random.choice(list(mutated.keys()))
            del mutated[key]
        
        elif mutation_type == "change_type" and mutated:
            # Change the type of an existing field
            if not mutated:
                continue
            key = random.choice(list(mutated.keys()))
            current_value = mutated[key]
            new_type = random.choice(["string", "int", "bool", "list", "dict"])
            
            if new_type == "string":
                mutated[key] = str(current_value)
            elif new_type == "int":
                try:
                    mutated[key] = int(float(str(current_value)))
                except:
                    mutated[key] = random.randint(-1000, 1000)
            elif new_type == "bool":
                mutated[key] = bool(current_value)
            elif new_type == "list":
                mutated[key] = [current_value]
            elif new_type == "dict":
                mutated[key] = {"value": current_value}
        
        elif mutation_type == "empty_field" and mutated:
            # Set a field to empty value
            if not mutated:
                continue
            key = random.choice(list(mutated.keys()))
            mutated[key] = ""
        
        elif mutation_type == "inject_special_chars" and mutated:
            # Inject special characters into a string field
            if not mutated:
                continue
            key = random.choice(list(mutated.keys()))
            if isinstance(mutated[key], str):
                special_chars = ["'", "\"", "<", ">", "&", ";", "|", "`", "$", "(", ")", "*", "\\", "\0", "\n", "\r"]
                char = random.choice(special_chars)
                pos = random.randint(0, len(mutated[key]))
                mutated[key] = mutated[key][:pos] + char + mutated[key][pos:]
    
    return mutated

def get_random_id():
    """Generate a random ID for use in endpoint URLs"""
    if random.random() < 0.7:
        return str(random.randint(1, 100))
    
    return random.choice([
        "-1",
        "0", 
        "abc", 
        mutate_string(str(random.randint(1, 100))),
        str(random.randint(1000000, 10000000))
    ])

def choose_next_seed(SeedQ):
    """Choose a random path and seed from SeedQ"""
    # Get a random path from SeedQ
    path = random.choice(list(SeedQ.keys()))
    
    # If this path has no methods, return None
    if not SeedQ[path]["methods"]:
        return None, None
    
    # Get a random seed for this path
    if SeedQ[path]["seeds"]:
        seed = random.choice(SeedQ[path]["seeds"])
    else:
        seed = copy.deepcopy(DEFAULT_PAYLOAD)
    
    return path, seed

def send_request(request, timeout=5.0):
    """Send an HTTP request using the provided Request object"""
    start_time = time.time()
    response = None
    error = None
    
    try:
        if request.payload is not None:
            response = requests.request(
                request.method, 
                request.url, 
                json=request.payload, 
                headers=request.headers, 
                timeout=timeout
            )
        else:
            response = requests.request(
                request.method, 
                request.url, 
                headers=request.headers, 
                timeout=timeout
            )
    except requests.exceptions.Timeout as e:
        error = e
    except requests.exceptions.ConnectionError as e:
        error = e
    except Exception as e:
        error = e
    
    end_time = time.time()
    response_time = end_time - start_time
    
    return response, response_time, error


def fuzz_application():
    """Main fuzzing function that uses SeedQ and FailureQ for tracking test cases"""
    # Start the Django server
    server_process = start_django_server()
    if not server_process:
        logger.error("Failed to start Django server. Exiting.")
        return
    
    base_url = "http://127.0.0.1:8000"
    
    # Wait for server to start
    if not wait_for_server(base_url, timeout=30):
        logger.error("Server failed to start within the timeout period. Exiting.")
        return
    
    # Initialize client
    client = FuzzerClient(base_url)
    
    # Make sure we're authenticated
    token = client.ensure_authenticated()
    if not token:
        logger.error("Authentication failed. Exiting.")
        return
    
    logger.info("Authentication successful. Starting greybox fuzzing...")
    start_time = time.time()
    
    # Main fuzzing loop implementing the algorithm in the image
    try:
        num_tests = 0
        num_crashes = 0
        num_interesting = 0
        
        while num_tests < 1000:  # Limit to 1000 tests or timeout
            # Choose next seed from SeedQ (ChooseNext function)
            s = client.choose_next(client.SeedQ)
            if s is None:
                logger.warning("No more seeds in the queue to test!")
                break
            
            # Assign energy for this seed (AssignEnergy function)
            energy = client.assign_energy(s)
            logger.info(f"Selected seed with energy {energy}: {s['method']} {s['path']}")
            
            # Perform mutations based on energy
            for k in range(energy):
                # Mutate input (MutateInput function)
                s_prime = client.mutate_input(s)
                request = s_prime["request"]
                
                logger.info(f"Mutation {k+1}/{energy}: {request.method} {s_prime['current_path']}")
                if request.payload:
                    logger.info(f"Payload: {request.payload}")
                
                # Send the request
                response, response_time, error = send_request(request)
                
                # Log the test
                client.tests[client.test_id] = datetime.datetime.now().isoformat()
                client.test_id += 1
                num_tests += 1
                
                # Check for failures or crashes
                reveals_bug = False
                
                if server_process.poll() is not None:
                    # Server crashed
                    reveals_bug = True
                    logger.warning("Server crashed! Process terminated unexpectedly.")
                    num_crashes += 1
                elif error:
                    # Request error
                    reveals_bug = True
                    logger.warning(f"Request error: {error}")
                    num_crashes += 1
                elif response and response.status_code >= 500:
                    # Server error
                    reveals_bug = True
                    logger.warning(f"Server error detected! Status code: {response.status_code}")
                    num_crashes += 1
                
                if reveals_bug:
                    # Add s_prime to FailureQ
                    path = s_prime["path"]
                    method = s_prime["method"]
                    
                    if path not in client.FailureQ:
                        client.FailureQ[path] = {}
                    
                    if method not in client.FailureQ[path]:
                        client.FailureQ[path][method] = {}
                    
                    status_code = "CRASH" if server_process.poll() is not None else str(response.status_code) if response else "ERROR"
                    if status_code not in client.FailureQ[path][method]:
                        client.FailureQ[path][method][status_code] = []
                    
                    failure_info = {
                        "input": s_prime["seed"],
                        "timestamp": datetime.datetime.now().isoformat(),
                        "mutation_id": s_prime["mutation_id"]
                    }
                    
                    if response:
                        failure_info["response"] = response.text[:1000]
                    if error:
                        failure_info["error"] = str(error)
                    
                    client.FailureQ[path][method][status_code].append(failure_info)
                    
                    # If this is the first failure of this type, record the time
                    if len(client.FailureQ[path][method][status_code]) == 1:
                        client.failure_time[len(client.failure_time)] = datetime.datetime.now().isoformat()
                    
                    # Restart the server if it crashed
                    if server_process.poll() is not None:
                        logger.info("Restarting the server...")
                        server_process.terminate()
                        time.sleep(2)  # Give it time to shut down
                        server_process = start_django_server()
                        
                        if not wait_for_server(base_url, timeout=30):
                            logger.error("Failed to restart server. Aborting.")
                            break
                        
                        # Re-authenticate after server restart
                        token = client.ensure_authenticated()
                        if not token:
                            logger.error("Failed to re-authenticate after server restart. Aborting.")
                            break
                
                # Check if this input produced new coverage (IsInteresting function)
                elif client.is_interesting(s_prime):
                    # Add s_prime to SeedQ
                    path = s_prime["path"]
                    method = s_prime["method"]
                    mutated_seed = s_prime["seed"]
                    
                    client.SeedQ[path]["seeds"].append(mutated_seed)
                    client.interesting_time[len(client.interesting_time)] = {
                        "timestamp": datetime.datetime.now().isoformat(),
                        "path": path,
                        "method": method,
                        "input": mutated_seed
                    }
                    num_interesting += 1
                    logger.info(f"Found interesting test case with new coverage: {method} {path}")
                
                # Display progress
                if num_tests % 10 == 0:
                    elapsed_time = time.time() - start_time
                    logger.info(f"Progress: {num_tests} tests, {num_crashes} crashes, {num_interesting} interesting cases, {elapsed_time:.2f} seconds elapsed")
                
                # Respect the server by adding a small delay between requests
                time.sleep(0.1)
    
    except KeyboardInterrupt:
        logger.info("Fuzzing interrupted by user")
    except Exception as e:
        logger.error(f"Exception during fuzzing: {e}")
        logger.error(traceback.format_exc())
    finally:
        # Save all data
        client.save_session_data()
        
        # Print summary
        print("\n" + "=" * 50)
        print("FUZZING SUMMARY")
        print("=" * 50)
        print(f"Total tests executed: {num_tests}")
        print(f"Total crashes found: {num_crashes}")
        print(f"Interesting test cases: {num_interesting}")
        print(f"Session data saved to: {client.session_folder}")
        
        # Terminate the server
        if server_process and server_process.poll() is None:
            logger.info("Terminating server process...")
            server_process.terminate()
            server_process.wait()
        
        return client

def add_to_seed_queue(client, endpoint, method, payload):
    """Manually add a seed to the SeedQ"""
    if endpoint not in client.SeedQ:
        client.SeedQ[endpoint] = {
            "methods": {method: True},
            "seeds": [payload]
        }
    else:
        if method not in client.SeedQ[endpoint]["methods"]:
            client.SeedQ[endpoint]["methods"][method] = True
        client.SeedQ[endpoint]["seeds"].append(payload)
    
    logger.info(f"Added seed to queue: {endpoint} {method}")

def main():
    """Main entry point for the fuzzer"""
    logger.info("Starting Django fuzzer")
    client = fuzz_application()
    
    if client:
        # Analyze failures
        num_failures = sum(len(methods) for path_data in client.FailureQ.values() 
                        for methods in path_data.values())
        
        if num_failures > 0:
            print("\nFAILURE ANALYSIS")
            print("=" * 50)
            
            for path in client.FailureQ:
                for method in client.FailureQ[path]:
                    for status_code in client.FailureQ[path][method]:
                        failures = client.FailureQ[path][method][status_code]
                        print(f"{method} {path} - Status code: {status_code}")
                        print(f"  Number of failures: {len(failures)}")
                        if failures:
                            print(f"  Example input: {failures[0]['input']}")
                        print()
        
        logger.info("Fuzzing completed")
    else:
        logger.error("Fuzzing failed to start")

if __name__ == "__main__":
    main()
