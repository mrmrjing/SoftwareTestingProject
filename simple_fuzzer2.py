# fuzzer_v2.py

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
from collections import defaultdict

# --- Logging configuration ---
# Set up a logger for the fuzzer with both file and console handlers

logger = logging.getLogger("GreyboxFuzzer")
logger.setLevel(logging.INFO)

# Ensure the directory for log files exists
os.makedirs("logs", exist_ok=True)

# Create a timestamp to uniquely name log files
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

# Set up a file handler for logging to a file, with INFO level
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

# --- Define crash types ---
# Enumerates the types of crashes/failures detected during fuzzing

class CrashType:
    SERVER_ERROR = "SERVER_ERROR"            # HTTP 500 errors
    TIMEOUT = "TIMEOUT"                      # Request timeout occurred
    CONNECTION_ERROR = "CONNECTION_ERROR"    # Failed to connect to the server
    UNEXPECTED_RESPONSE = "UNEXPECTED_RESPONSE"  # Any other unexpected behavior
    LONG_RESPONSE_TIME = "LONG_RESPONSE_TIME"    # Response took longer than acceptable
    SERVER_CRASH = "SERVER_CRASH"        # Server crashed completely and needed restart

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
        
        # Create directory for crash logs
        os.makedirs("crash_logs", exist_ok=True)
        
        # Define a path to store the crash report as a JSON file
        self.crash_report_path = f"crash_logs/crash_report_{timestamp}.json"
        
        # Initialize statistics for crashes, categorized by type, endpoint, and HTTP method
        self.crash_stats = {
            "total_crashes": 0,
            "by_type": defaultdict(int),
            "by_endpoint": defaultdict(int),
            "by_method": defaultdict(int)
        }
        
        # List to store detailed information about each crash
        self.crashes = []
        
    def register_user(self, username, password, email):
        """
        Register a user account using the provided credentials.
        Returns True if registration is successful.
        """
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
                logger.error(f"User registration failed. Status code: {response.status_code}. Response: {response.text}")
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
                    logger.error("Login response did not contain a token.")
                    return None
            else:
                logger.error(f"Login failed. Status code: {response.status_code}. Response: {response.text}")
                return None
        except Exception as e:
            logger.error(f"Login exception: {e}")
            return None

    def ensure_authenticated(self):
        """
        Ensure that the client is authenticated.
        Attempts to log in a test user, and if that fails, attempts to register then log in.
        """
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
                    logger.error("Could not authenticate test user.")
            return token
        else:
            self.headers["Authorization"] = f"Token {token}"
            return token
    
    def record_crash(self, request, crash_type, response=None, response_time=None, error=None):
        """
        Record detailed crash information for a given request.
        Updates statistics and logs the crash details.
        """
        self.crash_stats["total_crashes"] += 1
        self.crash_stats["by_type"][crash_type] += 1
        
        # Determine the endpoint pattern by removing the base URL
        endpoint = request.url.replace(self.base_url, "")
        # Try to match the endpoint to a known pattern by replacing ID placeholders
        for pattern in ENDPOINTS:
            if pattern.replace("{id}", "\\d+") in endpoint:
                endpoint_pattern = pattern
                self.crash_stats["by_endpoint"][endpoint_pattern] += 1
                break
        else:
            # If no pattern match, use the actual endpoint
            self.crash_stats["by_endpoint"][endpoint] += 1
        
        self.crash_stats["by_method"][request.method] += 1
        
        # Build a detailed record of the crash
        crash_record = {
            "timestamp": datetime.datetime.now().isoformat(),
            "crash_type": crash_type,
            "request": request.to_dict(),
            "response_time_ms": response_time * 1000 if response_time else None,
        }
        
        if response:
            crash_record["response"] = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text[:1000]  # Limit response body size for logging
            }
        
        if error:
            crash_record["error"] = {
                "type": type(error).__name__,
                "message": str(error),
                "traceback": traceback.format_exc()
            }
        
        # Store the crash record
        self.crashes.append(crash_record)
        
        # Log the crash details
        logger.info(f"Crash detected: {crash_type} - {request.method} {request.url}")
        if crash_type == CrashType.SERVER_ERROR and response:
            logger.info(f"Server error response: {response.status_code} - {response.text[:200]}")
        elif crash_type == CrashType.TIMEOUT:
            logger.info(f"Request timed out after {response_time:.2f} seconds")
        elif crash_type == CrashType.CONNECTION_ERROR:
            logger.info(f"Connection error: {error}")
    
    def save_crash_report(self):
        """
        Save all crash records and summary statistics to a JSON file.
        Also creates a human-readable summary text file.
        """
        report = {
            "summary": self.crash_stats,
            "crashes": self.crashes
        }
        
        with open(self.crash_report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Crash report saved to {self.crash_report_path}")
        
        # Save a summary in a separate text file
        summary_path = self.crash_report_path.replace('.json', '_summary.txt')
        with open(summary_path, 'w') as f:
            f.write(f"FUZZING CRASH REPORT - {datetime.datetime.now()}\n")
            f.write(f"{'='*50}\n\n")
            f.write(f"Total crashes: {self.crash_stats['total_crashes']}\n\n")
            
            f.write("Crashes by type:\n")
            for crash_type, count in self.crash_stats['by_type'].items():
                f.write(f"  {crash_type}: {count}\n")
            f.write("\n")
            
            f.write("Crashes by endpoint:\n")
            for endpoint, count in self.crash_stats['by_endpoint'].items():
                f.write(f"  {endpoint}: {count}\n")
            f.write("\n")
            
            f.write("Crashes by method:\n")
            for method, count in self.crash_stats['by_method'].items():
                f.write(f"  {method}: {count}\n")
            f.write("\n")
            
            f.write(f"Detailed crash information available in: {self.crash_report_path}\n")
        
        logger.info(f"Crash summary saved to {summary_path}")


# --- Server control functions ---

def start_django_server():
    """
    Start the Django development server.
    Uses subprocess to run 'manage.py runserver' from the appropriate directory.
    """
    try:
        # Determine the directory of the Django project relative to this script
        base_dir = os.path.dirname(os.path.abspath(__file__))
        cwd = os.path.join(base_dir, "DjangoWebApplication")
        logger.info(f"Starting Django server from: {cwd}")

        # Build the command to run the Django server
        cmd = ["python", "manage.py", "runserver"]

        # Start the server process
        server_process = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        logger.info("Django server process started")
        return server_process

    except Exception as e:
        logger.error(f"Failed to start Django server: {e}")
        return None


def wait_for_server(url, timeout=30, interval=0.5):
    """
    Poll the given URL until the server responds or the timeout is reached.
    Returns True if the server becomes available, otherwise False.
    """
    logger.info(f"Waiting for server at {url} to be available (timeout: {timeout}s)")
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(url, timeout=2)
            logger.info(f"Server is up and running! Status code: {response.status_code}")
            return True
        except requests.RequestException as e:
            logger.debug(f"Server not yet available: {str(e)}")
            time.sleep(interval)
    logger.error("Server did not start within the specified timeout.")
    return False

# --- Mutation helper functions ---
# Functions to mutate strings, integers, and payloads to generate varied test inputs

def mutate_string(s, num_mutations=1):
    """
    Mutate a string by performing a specified number of random changes:
    - Changing a character
    - Adding a character
    - Removing a character
    """
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
    """
    Mutate an integer by adding a random delta within the given range. A random delta is a random integer between
    min_delta and max_delta (inclusive). If n is not an integer, it will be returned as is.
    """
    if not isinstance(n, int):
        try:
            n = int(n)
        except:
            return n
    
    delta = random.randint(min_delta, max_delta)
    return n + delta


def mutate_payload(payload):
    """
    Apply mutations to a payload dictionary.
    Occasionally completely change the structure, otherwise mutate individual fields.
    """
    if not payload:
        return payload
    
    mutated = copy.deepcopy(payload)
    
    # Occasionally perform a structural mutation (10% chance)
    if random.random() < 0.1:
        mutation_type = random.choice(["empty", "add_fields", "remove_fields", "change_types"])
        
        if mutation_type == "empty":
            return {}
        elif mutation_type == "add_fields":
            mutated["extra_field"] = random.choice([
                "some_string", 
                123, 
                True, 
                [1, 2, 3], 
                {"nested": "object"}
            ])
        elif mutation_type == "remove_fields" and mutated:
            key_to_remove = random.choice(list(mutated.keys()))
            del mutated[key_to_remove]
        elif mutation_type == "change_types":
            for key in mutated:
                if isinstance(mutated[key], str):
                    mutated[key] = random.choice([123, True, [1, 2, 3], {"nested": "object"}])
                elif isinstance(mutated[key], int):
                    mutated[key] = random.choice(["123", True, [1, 2, 3], {"nested": "object"}])
    
    # Otherwise, simply mutate each field based on its type
    else:
        for key, value in mutated.items():
            if isinstance(value, str):
                mutated[key] = mutate_string(value, random.randint(1, 3))
            elif isinstance(value, int):
                mutated[key] = mutate_integer(value)
    
    return mutated


def get_random_id():
    """
    Generate a random ID.
    70% chance to return a likely valid numeric ID,
    30% chance to return an invalid or unexpected ID.
    """
    if random.random() < 0.7:
        return str(random.randint(1, 100))
    
    return random.choice([
        "-1",
        "0", 
        "abc", 
        mutate_string(str(random.randint(1, 100))),
        str(random.randint(1000000, 10000000))  # Likely out of range
    ])


def get_random_endpoint():
    """
    Select a random endpoint and, if necessary, fill in the {id} placeholder.
    """
    endpoint = random.choice(ENDPOINTS)
    
    if "{id}" in endpoint:
        endpoint = endpoint.replace("{id}", get_random_id())
    
    return endpoint


def get_random_request(base_url="http://127.0.0.1:8000"):
    """
    Generate a random Request object using a random HTTP method and endpoint.
    For POST and PUT requests on add/edit endpoints, attach a (possibly mutated) payload.
    """
    method = random.choice(HTTP_METHODS)
    endpoint = get_random_endpoint()
    url = f"{base_url}{endpoint}"
    
    payload = None
    if method in ["POST", "PUT"] and ("/add/" in endpoint or "/edit/" in endpoint):
        payload = copy.deepcopy(DEFAULT_PAYLOAD)
        # 80% chance to mutate the payload
        if random.random() < 0.8:
            payload = mutate_payload(payload)
    
    return Request(method, url, payload)


def send_request(request, timeout=5.0):
    """
    Send an HTTP request using the provided Request object.
    Returns a tuple: (response, response_time, error) where error is None if successful.
    """
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


def execute_fuzz_request(client, request, slow_threshold=3.0, server_process=None):
    """Execute a single fuzz request and log results with server recovery capability"""
    logger.info(f"Executing: {request.method} {request.url}")
    if request.payload:
        logger.info(f"Payload: {request.payload}")
    
    request.headers.update(client.headers)
    response, response_time, error = send_request(request)
    
    # Check if server has crashed completely
    server_crashed = (isinstance(error, requests.exceptions.ConnectionError) or 
                     (server_process and server_process.poll() is not None))
    
    if server_crashed:
        logger.warning("Server appears to have crashed. Attempting restart...")
        
        # Record the crash
        client.record_crash(request, CrashType.SERVER_CRASH, error=error)
        
        # Terminate the existing process if it's still running
        if server_process and server_process.poll() is None:
            server_process.terminate()
            server_process.wait()
        
        # Start a new server process
        server_process = start_django_server()
        
        # Wait for it to become available
        if wait_for_server(client.base_url, timeout=30):
            logger.info("Server successfully restarted")
            
            # Re-authenticate if needed
            client.ensure_authenticated()
            
            return True, server_process
        else:
            logger.error("Failed to restart server after crash")
            return True, None
    
    # Normal crash detection logic
    crash_detected = False
    
    if error:
        if isinstance(error, requests.exceptions.Timeout):
            client.record_crash(request, CrashType.TIMEOUT, response_time=response_time, error=error)
            crash_detected = True
        elif isinstance(error, requests.exceptions.ConnectionError):
            client.record_crash(request, CrashType.CONNECTION_ERROR, response_time=response_time, error=error)
            crash_detected = True
        else:
            client.record_crash(request, CrashType.UNEXPECTED_RESPONSE, response_time=response_time, error=error)
            crash_detected = True
    elif response:
        logger.info(f"Response status: {response.status_code}")
        
        # Record server errors (500)
        if response.status_code == 500:
            client.record_crash(request, CrashType.SERVER_ERROR, response=response, response_time=response_time)
            crash_detected = True
        # Record unusually slow responses
        elif response_time > slow_threshold:
            client.record_crash(request, CrashType.LONG_RESPONSE_TIME, response=response, response_time=response_time)
            crash_detected = True
    
    return crash_detected, server_process



def fuzz_random(client, num_requests=100, server_process=None):
    """Execute a specified number of random fuzz requests with server recovery"""
    crashes = 0
    
    for i in range(num_requests):
        logger.info(f"Random fuzzing iteration {i+1}/{num_requests}")
        request = get_random_request(client.base_url)
        
        crash_detected, server_process = execute_fuzz_request(client, request, server_process=server_process)
        
        if crash_detected:
            crashes += 1
            
        # If server couldn't be restarted, abort
        if server_process is None:
            logger.error("Server couldn't be restarted. Aborting fuzzing.")
            break
        
        # Small delay between requests
        time.sleep(0.1)
    
    return crashes, server_process



def fuzz_systematic(client, server_process=None):
    """Perform systematic fuzzing of all endpoints with all methods"""
    crashes = 0
    ids = [str(i) for i in range(1, 5)]  # Test with IDs 1-4
    
    # Test each endpoint
    for endpoint_template in ENDPOINTS:
        endpoint = endpoint_template
        
        # Fill in IDs if needed
        if "{id}" in endpoint:
            for id_value in ids:
                filled_endpoint = endpoint.replace("{id}", id_value)
                
                # Try all HTTP methods
                for method in HTTP_METHODS:
                    request = Request(
                        method=method,
                        url=f"{client.base_url}{filled_endpoint}",
                        payload=DEFAULT_PAYLOAD if method in ["POST", "PUT"] else None
                    )
                    
                    crash_detected, server_process = execute_fuzz_request(client, request, server_process=server_process)
                    
                    if crash_detected:
                        crashes += 1
                    
                    # If server couldn't be restarted, abort
                    if server_process is None:
                        logger.error("Server couldn't be restarted. Aborting fuzzing.")
                        return crashes, server_process
                    
                    # Small delay
                    time.sleep(0.1)
        else:
            # For endpoints without IDs
            for method in HTTP_METHODS:
                request = Request(
                    method=method,
                    url=f"{client.base_url}{endpoint}",
                    payload=DEFAULT_PAYLOAD if method in ["POST", "PUT"] else None
                )
                
                crash_detected, server_process = execute_fuzz_request(client, request, server_process=server_process)
                
                if crash_detected:
                    crashes += 1
                
                # If server couldn't be restarted, abort
                if server_process is None:
                    logger.error("Server couldn't be restarted. Aborting fuzzing.")
                    return crashes, server_process
                
                # Small delay
                time.sleep(0.1)
    
    return crashes, server_process



def fuzz_specific_vulnerabilities(client, server_process=None, consecutive_fails_limit=3):
    """
    Test specific known vulnerabilities or patterns that might cause problems
    based on the information provided
    """
    crashes = 0
    consecutive_connection_errors = 0
    
    # Test the specific endpoints mentioned:
    vulnerabilities = [
        # For /datatb/product/add/ 
        Request("POST", f"{client.base_url}/datatb/product/add/", {"name": "test", "info": "test", "price": 100}),
        Request("PUT", f"{client.base_url}/datatb/product/add/", {"name": "test", "info": "test", "price": 100}),
        Request("DELETE", f"{client.base_url}/datatb/product/add/"),
        Request("GET", f"{client.base_url}/datatb/product/add/"),
        
        # For /datatb/product/edit/<id>
        Request("POST", f"{client.base_url}/datatb/product/edit/1/", {"name": "test", "info": "test", "price": 100}),
        Request("PUT", f"{client.base_url}/datatb/product/edit/1/", {"name": "test", "info": "test", "price": 100}),
        Request("DELETE", f"{client.base_url}/datatb/product/edit/1/"),
        Request("GET", f"{client.base_url}/datatb/product/edit/1/"),
        
        # For /datatb/product/delete/<id>
        Request("POST", f"{client.base_url}/datatb/product/delete/1/"),
        Request("PUT", f"{client.base_url}/datatb/product/delete/1/"),
        Request("DELETE", f"{client.base_url}/datatb/product/delete/1/"),
        Request("GET", f"{client.base_url}/datatb/product/delete/1/"),
        
        # For /datatb/product/export/
        Request("GET", f"{client.base_url}/datatb/product/export/"),
        Request("POST", f"{client.base_url}/datatb/product/export/")
    ]
    
    # Test specific payloads that might cause issues
    special_payloads = [
        {"name": "", "info": "", "price": 0},
        {"name": "a" * 1000, "info": "b" * 1000, "price": 999999999},
        {"name": "<script>alert('XSS')</script>", "info": "<img src=x onerror=alert('XSS')>", "price": -1},
        {"name": "'; DROP TABLE products; --", "info": "SQL Injection Test", "price": 1},
        {},  # Empty payload
        {"name": "test", "info": "test"},  # Missing required field
        {"name": "test", "info": "test", "price": "not_a_number"},  # Wrong type
    ]
    
    # Known crash-inducing export payloads
    export_payloads = [
        {"search": "", "hidden_cols":[], "type": "pdf"},  # Known to cause a server crash
        {"search": "test", "hidden_cols":[], "type": "pdf"},
        {"search": "", "hidden_cols":[1, 2], "type": "pdf"},
        {"search": "", "hidden_cols":None, "type": "pdf"},
        {"search": "", "hidden_cols":[], "type": "csv"},
        {"search": "", "hidden_cols":[], "type": "invalid_type"},
        {"search": "", "hidden_cols":"not_a_list", "type": "pdf"},
        # More extreme versions to potentially trigger other issues
        {"search": "a" * 1000, "hidden_cols":[], "type": "pdf"},
        {"search": "", "hidden_cols":[i for i in range(100)], "type": "pdf"},
        {"search": "<script>alert('XSS')</script>", "hidden_cols":[], "type": "pdf"},
    ]
    
    logger.info("Testing known vulnerabilities for specific endpoints")
    
    # Test vulnerabilities with provided endpoint info
    for request in vulnerabilities:
        crash_detected = execute_fuzz_request(client, request)
        
        if crash_detected:
            crashes += 1
            
            # Check if this was a connection error
            if client.crashes and client.crashes[-1]["crash_type"] == CrashType.CONNECTION_ERROR:
                consecutive_connection_errors += 1
            else:
                consecutive_connection_errors = 0
        else:
            consecutive_connection_errors = 0
        
        # If we've had multiple connection errors in a row, restart the server
        if consecutive_connection_errors >= consecutive_fails_limit:
            logger.warning("Multiple consecutive connection errors detected. Server may have crashed. Restarting...")
            
            # Terminate the existing process if it's still running
            if server_process and server_process.poll() is None:
                server_process.terminate()
                server_process.wait()
            
            # Start a new server process
            server_process = start_django_server()
            
            # Wait for it to become available
            if wait_for_server(client.base_url, timeout=30):
                logger.info("Server successfully restarted")
                
                # Re-authenticate if needed
                client.ensure_authenticated()
                consecutive_connection_errors = 0
            else:
                logger.error("Failed to restart server after crash. Aborting fuzzing.")
                return crashes, server_process
                
        time.sleep(0.1)
    
    logger.info("Testing special payloads on add and edit endpoints")
    
    # Test special payloads on add and edit endpoints
    for payload in special_payloads:
        # Test on add endpoint
        request = Request("POST", f"{client.base_url}/datatb/product/add/", payload)
        crash_detected = execute_fuzz_request(client, request)
        
        if crash_detected:
            crashes += 1
            
            # Check for connection errors
            if client.crashes and client.crashes[-1]["crash_type"] == CrashType.CONNECTION_ERROR:
                consecutive_connection_errors += 1
            else:
                consecutive_connection_errors = 0
        else:
            consecutive_connection_errors = 0
            
        # Server restart logic if needed
        if consecutive_connection_errors >= consecutive_fails_limit:
            logger.warning("Multiple consecutive connection errors detected. Server may have crashed. Restarting...")
            
            # Terminate the existing process if it's still running
            if server_process and server_process.poll() is None:
                server_process.terminate()
                server_process.wait()
            
            # Start a new server process
            server_process = start_django_server()
            
            # Wait for it to become available
            if wait_for_server(client.base_url, timeout=30):
                logger.info("Server successfully restarted")
                
                # Re-authenticate if needed
                client.ensure_authenticated()
                consecutive_connection_errors = 0
            else:
                logger.error("Failed to restart server after crash. Aborting fuzzing.")
                return crashes, server_process
            
        # Test on edit endpoint
        request = Request("PUT", f"{client.base_url}/datatb/product/edit/1/", payload)
        crash_detected = execute_fuzz_request(client, request)
        
        if crash_detected:
            crashes += 1
            
            # Check for connection errors
            if client.crashes and client.crashes[-1]["crash_type"] == CrashType.CONNECTION_ERROR:
                consecutive_connection_errors += 1
            else:
                consecutive_connection_errors = 0
        else:
            consecutive_connection_errors = 0
            
        # Server restart logic if needed
        if consecutive_connection_errors >= consecutive_fails_limit:
            logger.warning("Multiple consecutive connection errors detected. Server may have crashed. Restarting...")
            
            # Terminate the existing process if it's still running
            if server_process and server_process.poll() is None:
                server_process.terminate()
                server_process.wait()
            
            # Start a new server process
            server_process = start_django_server()
            
            # Wait for it to become available
            if wait_for_server(client.base_url, timeout=30):
                logger.info("Server successfully restarted")
                
                # Re-authenticate if needed
                client.ensure_authenticated()
                consecutive_connection_errors = 0
            else:
                logger.error("Failed to restart server after crash. Aborting fuzzing.")
                return crashes, server_process
        
        time.sleep(0.1)
    
    logger.info("Testing specific crash-inducing export payloads")
    
    # Test export payloads specifically targeting the known vulnerability
    for payload in export_payloads:
        request = Request("POST", f"{client.base_url}/datatb/product/export/", payload)
        logger.info(f"Testing known crash-inducing export payload: {payload}")
        
        crash_detected = execute_fuzz_request(client, request)
        
        if crash_detected:
            crashes += 1
            logger.warning(f"Export payload {payload} caused a crash!")
            
            # Check for connection errors
            if client.crashes and client.crashes[-1]["crash_type"] == CrashType.CONNECTION_ERROR:
                consecutive_connection_errors += 1
            else:
                consecutive_connection_errors = 0
        else:
            consecutive_connection_errors = 0
            
        # Server restart logic if needed
        if consecutive_connection_errors >= consecutive_fails_limit:
            logger.warning("Multiple consecutive connection errors detected. Server may have crashed. Restarting...")
            
            # Terminate the existing process if it's still running
            if server_process and server_process.poll() is None:
                server_process.terminate()
                server_process.wait()
            
            # Start a new server process
            server_process = start_django_server()
            
            # Wait for it to become available
            if wait_for_server(client.base_url, timeout=30):
                logger.info("Server successfully restarted")
                
                # Re-authenticate if needed
                client.ensure_authenticated()
                consecutive_connection_errors = 0
            else:
                logger.error("Failed to restart server after crash. Aborting fuzzing.")
                return crashes, server_process
        
        time.sleep(0.1)
    
    return crashes, server_process


def start_fuzzing_session(base_url="http://127.0.0.1:8000", mode="all", num_random_requests=100, server_process=None):
    """
    Start a complete fuzzing session
    
    Args:
        base_url: Base URL of the target application
        mode: "all", "random", "systematic", or "targeted"
        num_random_requests: Number of random requests to send in random mode
        server_process: Current server process instance
    
    Returns:
        Dictionary with fuzzing results
    """
    logger.info(f"Starting fuzzing session - Mode: {mode}, Target: {base_url}")
    
    # Initialize client
    client = FuzzerClient(base_url)
    
    # Make sure we're authenticated
    token = client.ensure_authenticated()
    if not token:
        logger.error("Authentication failed. Exiting fuzzing session.")
        return {"status": "error", "reason": "authentication_failed"}
    
    # Make sure server is responsive
    if not wait_for_server(base_url, timeout=10):
        logger.error("Server not responding. Exiting fuzzing session.")
        return {"status": "error", "reason": "server_not_responding"}
    
    logger.info("Authentication successful and server responsive. Starting fuzzing...")
    
    total_crashes = 0
    
    try:
        # Execute the appropriate fuzzing strategy
        if mode == "all" or mode == "random":
            logger.info(f"Executing random fuzzing with {num_random_requests} requests")
            random_crashes, server_process = fuzz_random(client, num_random_requests, server_process)
            total_crashes += random_crashes
            logger.info(f"Random fuzzing completed. Crashes found: {random_crashes}")
            
            # If server couldn't be restarted, abort further fuzzing
            if server_process is None:
                raise Exception("Failed to restart server after crash. Aborting further fuzzing.")
        
        if mode == "all" or mode == "systematic":
            logger.info("Executing systematic fuzzing")
            systematic_crashes, server_process = fuzz_systematic(client, server_process)
            total_crashes += systematic_crashes
            logger.info(f"Systematic fuzzing completed. Crashes found: {systematic_crashes}")
            
            # If server couldn't be restarted, abort further fuzzing
            if server_process is None:
                raise Exception("Failed to restart server after crash. Aborting further fuzzing.")
        
        if mode == "all" or mode == "targeted":
            logger.info("Executing targeted vulnerability fuzzing")
            targeted_crashes, server_process = fuzz_specific_vulnerabilities(client, server_process)
            total_crashes += targeted_crashes
            logger.info(f"Targeted fuzzing completed. Crashes found: {targeted_crashes}")
    
    except Exception as e:
        logger.error(f"Exception during fuzzing: {e}")
        # Save crash report before exiting
        client.save_crash_report()
        return {
            "status": "error", 
            "reason": "exception", 
            "details": str(e),
            "crashes_found": total_crashes,
            "crash_report_path": client.crash_report_path,
            "server_process": server_process
        }
    finally:
        # Save the crash report in all cases
        client.save_crash_report()
    
    logger.info(f"Fuzzing session completed. Total crashes found: {total_crashes}")
    
    return {
        "status": "success",
        "crashes_found": total_crashes,
        "crash_report_path": client.crash_report_path,
        "server_process": server_process
    }


def get_crash_summary(json_report_path):
    """
    Generate a human-readable summary from a JSON crash report.
    Parses the JSON file and creates a summary string listing totals and top crashes.
    """
    try:
        with open(json_report_path, 'r') as f:
            report = json.load(f)
        
        summary = []
        summary.append("FUZZING CRASH REPORT SUMMARY")
        summary.append("=" * 40)
        summary.append(f"Total crashes: {report['summary']['total_crashes']}")
        summary.append("")
        
        summary.append("CRASHES BY TYPE:")
        for crash_type, count in report['summary']['by_type'].items():
            summary.append(f"  {crash_type}: {count}")
        summary.append("")
        
        summary.append("CRASHES BY ENDPOINT:")
        for endpoint, count in report['summary']['by_endpoint'].items():
            summary.append(f"  {endpoint}: {count}")
        summary.append("")
        
        summary.append("CRASHES BY METHOD:")
        for method, count in report['summary']['by_method'].items():
            summary.append(f"  {method}: {count}")
        summary.append("")
        
        summary.append("TOP 5 CRASHES:")
        for i, crash in enumerate(report['crashes'][:5]):
            summary.append(f"  {i+1}. {crash['crash_type']} - {crash['request']['method']} {crash['request']['url']}")
            if 'response' in crash and 'status_code' in crash['response']:
                summary.append(f"     Status code: {crash['response']['status_code']}")
            if 'response_time_ms' in crash:
                summary.append(f"     Response time: {crash['response_time_ms']:.2f} ms")
        
        return "\n".join(summary)
    except Exception as e:
        return f"Error generating summary: {e}"


def main():
    # Start the Django server
    server_process = start_django_server()
    if not server_process:
        logger.error("Failed to start Django server. Exiting.")
        return

    base_url = "http://127.0.0.1:8000"
    try:
        # Wait for the server to start
        if not wait_for_server(base_url, timeout=30):
            logger.error("Server failed to start within the timeout period. Exiting.")
            return

        # Execute the fuzzing session, passing in the server process
        results = start_fuzzing_session(base_url=base_url, mode="all", 
                                       num_random_requests=100, 
                                       server_process=server_process)
        
        # Update our reference to the server process which might have been restarted
        server_process = results.get('server_process', server_process)
        
        print("\n" + "=" * 50)
        print(f"Fuzzing completed with status: {results['status']}")
        print(f"Crashes found: {results.get('crashes_found', 0)}")
        print(f"Crash report saved to: {results.get('crash_report_path')}")
        
        # Display summary if report was created
        if 'crash_report_path' in results:
            print("\nCRASH SUMMARY:")
            print(get_crash_summary(results['crash_report_path']))
            
    finally:
        # Make sure we terminate the server process when done
        if server_process and server_process.poll() is None:
            logger.info("Terminating Django server process...")
            server_process.terminate()
            server_process.wait()
            logger.info("Django server process terminated")


if __name__ == "__main__":
    main()
