import hashlib
import requests
import random
import copy
import logging
import time
import json
import os
import datetime
import traceback
import subprocess
import re
import tabulate
from mutations import MutationEngine
from dotenv import load_dotenv
import os


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

# --- Create bug_samples directory ---
os.makedirs("bug_samples", exist_ok=True)

# --- Fallback default payload ---
DEFAULT_PAYLOAD = {
    "name": "test_product",
    "info": "test_info",
    "price": 100
}

# --- Bug classification functionality ---
class BugClassifier:
    """Identifies and classifies unique bugs from failures"""
    
    def __init__(self):
        self.unique_bugs = {}  # Mapping of bug signature to bug details
        self.bug_counter = 1   # Counter for assigning bug IDs
    
    def extract_error_signature(self, path, method, response_text=None, error_str=None, status_code=None):
        """
        Extract a meaningful signature from an error response or error message.
        Includes path and method to ensure bugs in different endpoints are considered unique.
        """
        # First, determine the error type
        error_type = self._determine_error_type(response_text, error_str, status_code)
        
        # Create the signature by combining path, method, and error type
        # This ensures that the same error in different endpoints is considered unique
        signature = f"{method}:{path}:{error_type}"
        
        return signature

    
    def _determine_error_type(self, response_text=None, error_str=None, status_code=None):
        """Helper method to determine the specific error type without path/method"""
        # Handle server crashes
        if status_code == "CRASH":
            if error_str:
                # Extract the exception type from the error string
                exception_match = re.search(r'([A-Za-z.]+Error|[A-Za-z.]+Exception)', error_str)
                if exception_match:
                    exception_type = exception_match.group(1)
                    # Look for common crash patterns
                    if "MemoryError" in exception_type:
                        return "OutOfMemory"
                    elif "TimeoutError" in exception_type:
                        return "Timeout"
                    elif "ConnectionError" in exception_type or "ConnectionRefused" in exception_type:
                        return "ConnectionIssue"
                    else:
                        return exception_type
            return "ServerTerminated"
        
        # Handle connection errors
        if status_code == "ERROR":
            if error_str:
                # Connection timeout
                if "timeout" in error_str.lower():
                    return "ConnectionTimeout"
                # Connection refused
                elif "connection refused" in error_str.lower() or "cannot connect" in error_str.lower():
                    return "ConnectionRefused"
                # DNS resolution issues
                elif "name resolution" in error_str.lower() or "getaddrinfo failed" in error_str.lower():
                    return "DNSResolutionFailure"
                # SSL/TLS errors
                elif "ssl" in error_str.lower() or "certificate" in error_str.lower():
                    return "SSLError"
                # Generic connection error
                elif "connection" in error_str.lower():
                    return "ConnectionIssue"
        
        # Handle HTTP 5xx responses
        if status_code and str(status_code).startswith('5'):
            if response_text:
                # Django-specific error patterns
                if "Django" in response_text and "Traceback" in response_text:
                    # Extract exception type
                    exception_match = re.search(r'Exception Type:\s*([^\n]+)', response_text)
                    if exception_match:
                        exception_type = exception_match.group(1).strip()
                        
                        # Extract exception value/message
                        message_match = re.search(r'Exception Value:\s*([^\n]+)', response_text)
                        exception_msg = message_match.group(1).strip() if message_match else ""
                        
                        # Normalize the exception message by removing specific values
                        normalized_msg = re.sub(r'\'[^\']+\'', "'VALUE'", exception_msg)
                        normalized_msg = re.sub(r'\d+', "N", normalized_msg)
                        
                        # Check for common Django error patterns
                        if "DoesNotExist" in exception_type:
                            return "ObjectNotFound"
                        elif "IntegrityError" in exception_type:
                            if "unique constraint" in normalized_msg.lower():
                                return "UniqueConstraintViolation"
                            elif "foreign key constraint" in normalized_msg.lower():
                                return "ForeignKeyConstraintViolation"
                            else:
                                return "DatabaseIntegrityError"
                        elif "ValidationError" in exception_type:
                            return "ValidationError"
                        elif "PermissionDenied" in exception_type:
                            return "PermissionDenied"
                        elif "TypeError" in exception_type:
                            if "NoneType" in normalized_msg:
                                return "NoneTypeError"
                            else:
                                return "TypeError"
                        elif "ValueError" in exception_type:
                            if "invalid literal" in normalized_msg.lower():
                                return "InvalidLiteralError"
                            else:
                                return "ValueError"
                        elif "KeyError" in exception_type:
                            return "KeyError"
                        elif "IndexError" in exception_type:
                            return "IndexError"
                        elif "AttributeError" in exception_type:
                            return "AttributeError"
                        else:
                            # Use the exception type as the signature
                            return exception_type
                
                # Look for JSON parsing errors
                if "json" in response_text.lower() and ("parse" in response_text.lower() or "syntax" in response_text.lower()):
                    return "JSONParseError"
                
                # Look for database errors
                if "database" in response_text.lower() or "sql" in response_text.lower() or "query" in response_text.lower():
                    if "timeout" in response_text.lower():
                        return "DatabaseTimeout"
                    elif "deadlock" in response_text.lower():
                        return "DatabaseDeadlock"
                    else:
                        return "DatabaseError"
                
                # Look for template rendering errors
                if "template" in response_text.lower() and "render" in response_text.lower():
                    return "TemplateRenderingError"
            
            # Generic 5xx error if no specific pattern matched
            return "ServerError"
        
        # Handle 4xx client errors
        if status_code and str(status_code).startswith('4'):
            if status_code == 400:
                return "BadRequest"
            elif status_code == 401:
                return "Unauthorized"
            elif status_code == 403:
                return "Forbidden"
            elif status_code == 404:
                return "NotFound"
            elif status_code == 405:
                return "MethodNotAllowed"
            elif status_code == 413:
                return "PayloadTooLarge"
            elif status_code == 429:
                return "TooManyRequests"
            else:
                return "ClientError"
        
        # If we still don't have a signature, create a more generic one
        if error_str:
            # Create a normalized version of the error string
            normalized_error = error_str.lower()
            normalized_error = re.sub(r'\d+', 'N', normalized_error)
            normalized_error = re.sub(r'\'[^\']+\'', "'VALUE'", normalized_error)
            
            # Generate a hash of the normalized error
            error_hash = hashlib.md5(normalized_error.encode()).hexdigest()[:8]
            return f"GenericError:{error_hash}"
        elif response_text:
            # For responses without clear error patterns, use a hash of the first 200 chars
            # This helps group similar responses together
            sample_text = response_text[:200].lower()
            sample_text = re.sub(r'\d+', 'N', sample_text)
            sample_text = re.sub(r'\'[^\']+\'', "'VALUE'", sample_text)
            
            text_hash = hashlib.md5(sample_text.encode()).hexdigest()[:8]
            return f"UnknownResponse:{text_hash}"
        
        # Fallback
        return "Unknown"
    
    def minimize_payload(self, original_payload):
        """
        Create a minimal version of the payload that still triggers the bug.
        This is a simplified version - in practice you'd want to test each minimization
        with the server to ensure it still triggers the bug.
        """
        # For dictionary payloads, we'll do a basic minimization
        if isinstance(original_payload, dict):
            # Try to keep only essential fields that are most likely to trigger bugs
            minimal = {}
            # Prioritize fields that are more likely to cause issues
            suspicious_fields = ["id", "pk", "name", "price", "user", "email", "type"]
            for field in suspicious_fields:
                if field in original_payload:
                    minimal[field] = original_payload[field]
            
            # If nothing was selected or the payload is very small, just return it as is
            if not minimal or len(original_payload) <= 3:
                return original_payload
            
            return minimal
        
        # For non-dict payloads, return as is
        return original_payload
    
    def classify_bug(self, path, method, status_code, seed, response_text=None, error_str=None):
        """
        Classify a bug and determine if it's unique.
        Returns a tuple of (is_new, bug_id, signature)
        """
        # Extract a signature to identify this particular bug
        # Pass path and method to the signature extraction
        signature = self.extract_error_signature(path, method, response_text, error_str, status_code)
        
        # Check if we've seen this signature before
        if signature in self.unique_bugs:
            bug_id = self.unique_bugs[signature]["id"]
            self.unique_bugs[signature]["occurrences"] += 1
            
            # Add this occurrence to the list of examples if tracking examples
            if "examples" in self.unique_bugs[signature]:
                if len(self.unique_bugs[signature]["examples"]) < 5:  # Limit to 5 examples
                    self.unique_bugs[signature]["examples"].append({
                        "seed": seed,
                        "response_sample": response_text[:200] if response_text else None,
                        "error_sample": error_str[:200] if error_str else None,
                        "timestamp": datetime.datetime.now().isoformat()
                    })
            
            return False, bug_id, signature
        
        # This is a new unique bug
        bug_id = f"BUG-{self.bug_counter}"
        self.bug_counter += 1
        
        # Create minimized test case
        minimal_payload = self.minimize_payload(seed)
        
        # Record information about this bug
        bug_info = {
            "id": bug_id,
            "signature": signature,
            "path": path,
            "method": method,
            "status_code": status_code,
            "first_seen": datetime.datetime.now().isoformat(),
            "occurrences": 1,
            "minimal_payload": minimal_payload,
            "original_payload": seed,
            "response_sample": response_text[:500] if response_text else None,
            "error_sample": error_str[:500] if error_str else None
        }
        
        # Add examples list if we're tracking examples
        if hasattr(self, '_track_examples') and self._track_examples:
            bug_info["examples"] = [{
                "seed": seed,
                "response_sample": response_text[:200] if response_text else None,
                "error_sample": error_str[:200] if error_str else None,
                "timestamp": datetime.datetime.now().isoformat()
            }]
        
        self.unique_bugs[signature] = bug_info
        
        return True, bug_id, signature


    def save_bug_samples(self, folder="bug_samples"):
        """Save all unique bugs as individual files in the designated folder"""
        if not self.unique_bugs:
            logger.info("No bugs to save")
            return
        
        os.makedirs(folder, exist_ok=True)
        
        # Create a summary file
        with open(os.path.join(folder, "bug_summary.txt"), "w") as f:
            f.write(self.generate_summary_table())
        
        # Create individual files for each bug
        for signature, bug in self.unique_bugs.items():
            filename = f"{bug['id']}.json"
            filepath = os.path.join(folder, filename)
            
            # Create a reproducible test case file
            with open(filepath, "w") as f:
                repro_case = {
                    "bug_id": bug["id"],
                    "signature": signature,
                    "endpoint": bug["path"],
                    "method": bug["method"],
                    "payload": bug["minimal_payload"],
                    "description": self._generate_bug_description(bug),
                    "reproduction_steps": [
                        f"1. Send a {bug['method']} request to {bug['path']}",
                        f"2. Use the following payload: {json.dumps(bug['minimal_payload'])}"
                    ]
                }
                json.dump(repro_case, f, indent=2)
            
            logger.info(f"Saved minimal test case for {bug['id']} to {filepath}")
    
    def _generate_bug_description(self, bug):
        """Generate a human-readable description of the bug"""
        status_code = bug["status_code"]
        
        if status_code == "CRASH":
            return f"Server crash when sending {bug['method']} request to {bug['path']}"
        elif status_code == "ERROR":
            return f"Connection error when sending {bug['method']} request to {bug['path']}"
        elif status_code.isdigit() and int(status_code) >= 500:
            return f"Server error {status_code} when sending {bug['method']} request to {bug['path']}"
        else:
            return f"Error when sending {bug['method']} request to {bug['path']}"

    def generate_summary_table(self):
        """Generate a text table summarizing all unique bugs"""
        if not self.unique_bugs:
            return "No bugs found"
        
        # Standard summary table
        headers = ["Bug ID", "Endpoint", "Method", "Status", "Occurrences", "Error Type"]
        rows = []
        
        for signature, bug in self.unique_bugs.items():
            # Extract the error type from the signature (format is METHOD:PATH:ERROR_TYPE)
            error_type = signature.split(":", 2)[2] if len(signature.split(":", 2)) > 2 else signature
            
            rows.append([
                bug["id"],
                bug["path"],
                bug["method"],
                bug["status_code"],
                bug["occurrences"],
                error_type
            ])
        
        # Sort by bug ID
        rows.sort(key=lambda x: x[0])
        
        # Generate the table
        table = tabulate.tabulate(rows, headers, tablefmt="grid")
        return table


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
    def __init__(self, openapi_file="open_api.json"):
        self.headers = {}
        # Load the OpenAPI specification and extract base URL if defined
        spec = self.load_openapi_spec(openapi_file)
        if "servers" in spec and spec["servers"]:
            self.base_url = spec["servers"][0].get("url", "http://127.0.0.1:8000").rstrip("/")
        else:
            self.base_url = "http://127.0.0.1:8000"
        logger.info(f"Using base URL: {self.base_url}")

        self.SeedQ = self.initialize_seed_queue_from_spec(spec)
        self.FailureQ = {}

        # For tracking interesting tests
        self.interesting_time = {0: datetime.datetime.now().isoformat()}
        self.failure_time = {0: datetime.datetime.now().isoformat()}
        self.tests = {0: datetime.datetime.now().isoformat()}
        self.test_id = 1

        # Create directory for session data
        self.session_folder = self.create_session_folder()

        # Initialize energy assignment tracking
        self.initialize_energy_tracking()

        # Initialize the mutation engine
        self.mutation_engine = MutationEngine()

        # Add bug classifier
        self.bug_classifier = BugClassifier()

    def load_openapi_spec(self, openapi_file):
        """Load the OpenAPI specification from a JSON file."""
        try:
            with open(openapi_file, "r") as f:
                spec = json.load(f)
            logger.info(f"Loaded OpenAPI specification from {openapi_file}")
            return spec
        except Exception as e:
            logger.error(f"Failed to load OpenAPI spec from {openapi_file}: {e}")
            raise

    def generate_default_payload(self, schema):
        """Generate a default payload based on the provided JSON schema.
        Uses any examples if available; otherwise, falls back to hardcoded types."""
        if not schema:
            return {}
        payload = {}
        properties = schema.get("properties", {})
        for key, prop in properties.items():
            if "example" in prop:
                # Handle examples that are arrays by selecting the first item
                example_value = prop["example"]
                if isinstance(example_value, list) and example_value:
                    payload[key] = example_value[0]  # Take the first example
                else:
                    payload[key] = example_value
            elif prop.get("type") == "string":
                payload[key] = "test"
            elif prop.get("type") == "integer":
                payload[key] = 1
            elif prop.get("type") == "number":
                payload[key] = 1.0
            elif prop.get("type") == "boolean":
                payload[key] = True
            elif prop.get("type") == "object":
                payload[key] = {}
            elif prop.get("type") == "array":
                payload[key] = []
            else:
                payload[key] = None
        return payload

    def initialize_seed_queue_from_spec(self, spec):
        """Initialize SeedQ by parsing the OpenAPI spec."""
        SeedQ = {}
        paths = spec.get("paths", {})
        components = spec.get("components", {})
        schemas = components.get("schemas", {})
        
        for path, methods in paths.items():
            SeedQ[path] = {"methods": {}, "seeds": []}
            
            for method, details in methods.items():
                method_upper = method.upper()
                SeedQ[path]["methods"][method_upper] = True
                
                # Skip generating payloads for GET and DELETE methods
                if method_upper in ["GET", "DELETE"]:
                    continue
                    
                payload = None
                if "requestBody" in details:
                    content = details["requestBody"].get("content", {})
                    if "application/json" in content:
                        schema = content["application/json"].get("schema", {})
                        
                        # Handle schema references
                        if "$ref" in schema:
                            schema_ref = schema["$ref"]
                            # Extract schema name from reference like "#/components/schemas/Product"
                            schema_name = schema_ref.split("/")[-1]
                            if schema_name in schemas:
                                schema = schemas[schema_name]
                        
                        payload = self.generate_default_payload(schema)
                        
                # If we couldn't generate a payload from the schema, use the default payload
                if payload is None and method_upper in ["POST", "PUT", "PATCH"]:
                    payload = copy.deepcopy(DEFAULT_PAYLOAD)
                    logger.info(f"Using default payload for {method_upper} {path}")
                
                # Add the payload to seeds if it exists
                if payload is not None:
                    SeedQ[path]["seeds"].append(payload)
                    logger.info(f"Added seed for {method_upper} {path}: {payload}")
            
            # If this path has no seeds but has methods that should have bodies,
            # add a default payload
            needs_body = any(m in ["POST", "PUT", "PATCH"] for m in SeedQ[path]["methods"])
            if needs_body and not SeedQ[path]["seeds"]:
                SeedQ[path]["seeds"].append(copy.deepcopy(DEFAULT_PAYLOAD))
                logger.info(f"Added default seed for {path}: {DEFAULT_PAYLOAD}")
        
        logger.info("Seed queue initialized from OpenAPI spec.")
        return SeedQ

    def initialize_energy_tracking(self):
        """Initialize tracking structures for energy assignment."""
        # Track seed performance (how many new paths each seed has found)
        self.seed_performance = {}
        
        # Track path execution counts (how many times we've fuzzed each endpoint)
        self.path_execution_count = {}
        
        # Track when seeds were discovered
        self.seed_discovery_time = {}
        
        # Track which paths/methods correlate with crashes
        self.crash_correlation = {}

    def update_energy_metrics(self, s_prime, reveals_bug, is_interesting):
        """Update metrics used for energy calculations."""
        path = s_prime["path"] 
        method = s_prime["method"]
        seed = s_prime["seed"]
        
        # Generate a unique ID for this seed
        seed_id = hashlib.md5(json.dumps(seed, sort_keys=True).encode()).hexdigest()
        path_method_key = f"{method}:{path}"
        
        # Update path execution count
        if not hasattr(self, 'path_execution_count'):
            self.path_execution_count = {}
        self.path_execution_count[path_method_key] = self.path_execution_count.get(path_method_key, 0) + 1
        
        # If this is a new seed, record discovery time
        if not hasattr(self, 'seed_discovery_time'):
            self.seed_discovery_time = {}
        if seed_id not in self.seed_discovery_time:
            self.seed_discovery_time[seed_id] = time.time()
        
        # Initialize seed performance tracking if needed
        if not hasattr(self, 'seed_performance'):
            self.seed_performance = {}
        if seed_id not in self.seed_performance:
            self.seed_performance[seed_id] = {'new_coverage_count': 0, 'executions': 0, 'crashes': 0}
        
        # Update execution count
        self.seed_performance[seed_id]['executions'] += 1
        
        # If this seed found new coverage, update its score
        if is_interesting:
            self.seed_performance[seed_id]['new_coverage_count'] += 1
        
        # If this seed caused a crash, update crash correlation
        if reveals_bug:
            self.seed_performance[seed_id]['crashes'] += 1
            
            if not hasattr(self, 'crash_correlation'):
                self.crash_correlation = {}
            if path not in self.crash_correlation:
                self.crash_correlation[path] = {}
            if method not in self.crash_correlation[path]:
                self.crash_correlation[path][method] = 0
            self.crash_correlation[path][method] += 1

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

        # Save bug samples
        self.bug_classifier.save_bug_samples()
        
        # Also save bug summary to session folder
        with open(os.path.join(self.session_folder, "bug_summary.txt"), "w") as f:
            f.write(self.bug_classifier.generate_summary_table())
        
        logger.info(f"Session data saved to {self.session_folder}")

    def mutate_input(self, s):
        """Implementation of MutateInput from the algorithm."""
        path = s["path"]
        method = s["method"]
        seed = s["seed"]

        current_path = path
        if "{id}" in path:
            id_value = get_random_id()
            current_path = path.replace("{id}", id_value)

        # Determine mutation intensity based on path/method performance
        if random.random() < 0.7:  # 70% small mutations
            mutation_count = random.randint(1, 3)
        else:  # 30% larger mutations
            mutation_count = random.randint(4, 10)
        
        # Use the MutationEngine instead of custom mutation functions
        mutated_seed = self.mutation_engine.mutate_payload(seed, num_mutations=mutation_count)
        
        # Generate a unique hash for this mutation to track it
        mutation_id = hashlib.md5(
            json.dumps((method, current_path, mutated_seed), sort_keys=True).encode()
        ).hexdigest()

        request = Request(
            method=method,
            url=f"{self.base_url}{current_path}",
            payload=mutated_seed if method in ["POST", "PUT", "PATCH"] else None
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
        """Implementation of ChooseNext"""
        untested_paths = []
        for path in SeedQ:
            # Skip paths with no methods
            if not SeedQ[path]["methods"]:
                continue
                
            # Initialize FailureQ structure if needed
            if path not in self.FailureQ:
                self.FailureQ[path] = {}
                
            methods = [m for m in SeedQ[path]["methods"] if SeedQ[path]["methods"][m]]
            for method in methods:
                # Initialize method in FailureQ
                if method not in self.FailureQ[path]:
                    self.FailureQ[path][method] = {}
                    
                if len(SeedQ[path]["seeds"]) > 0:
                    untested_paths.append((path, method))
                    
        if untested_paths:
            path, method = random.choice(untested_paths)
            if SeedQ[path]["seeds"]:
                seed = random.choice(SeedQ[path]["seeds"])
            else:
                # Provide a default seed if none exists
                seed = copy.deepcopy(DEFAULT_PAYLOAD)
                
            return {"path": path, "method": method, "seed": seed}
        return None

    def assign_energy(self, s):
        """
        Energy Assignment Factors Inspired by AFL:

        1. Code Coverage Impact:
        - Seeds that discover new paths get higher priority.
        2. Execution Time:
        - Faster inputs get more energy for efficient use of fuzzing time.
        3. Creation Time:
        - Newer seeds get temporarily higher energy.
        4. Queue Position:
        - Ensures all seeds in the queue get some attention.
        5. Input Size:
        - Smaller inputs often get priority as they're more manageable.
                
        """        
        seed = s["seed"]
        path = s["path"]
        method = s["method"]
        
        # --- Basic energy based on input complexity ---
        # Calculate base energy based on seed size/complexity
        seed_size = len(json.dumps(seed))  # Size in bytes when serialized
        
        # --- Factor 1: Input Size Consideration ---
        # Smaller inputs get more energy (up to a point)
        # This encourages finding minimal test cases
        if seed_size < 100:
            size_factor = 1.5  # Boost for very small payloads
        elif seed_size < 500:
            size_factor = 1.2  # Slight boost for reasonably sized payloads
        elif seed_size < 1000:
            size_factor = 1.0  # Normal energy
        else:
            size_factor = 0.7  # Penalty for very large payloads
        
        # --- Factor 2: Coverage Impact History ---
        # If we track interesting inputs discovered by this seed
        coverage_impact = 1.0
        seed_id = hashlib.md5(json.dumps(seed, sort_keys=True).encode()).hexdigest()
        
        if hasattr(self, 'seed_performance') and seed_id in self.seed_performance:
            # Reward seeds that previously found new coverage
            discoveries = self.seed_performance[seed_id].get('new_coverage_count', 0)
            if discoveries > 0:
                coverage_impact = min(2.0, 1.0 + (discoveries * 0.2))  # Cap at 2x
        
        # --- Factor 3: Path/Method Rarity ---
        # Prioritize less-fuzzed endpoints
        path_method_key = f"{method}:{path}"
        path_frequency = 1.0
        
        if hasattr(self, 'path_execution_count'):
            total_executions = sum(self.path_execution_count.values()) or 1
            path_count = self.path_execution_count.get(path_method_key, 0)
            if path_count > 0:
                # Less frequently tested paths get higher energy
                path_frequency = max(0.5, min(2.0, 0.5 * (total_executions / path_count / len(self.path_execution_count))))
        
        # --- Factor 4: Seed Age ---
        # Newer seeds get temporarily higher energy (like AFL)
        age_factor = 1.0
        if hasattr(self, 'seed_discovery_time') and seed_id in self.seed_discovery_time:
            age_seconds = time.time() - self.seed_discovery_time[seed_id]
            if age_seconds < 60:  # Last minute
                age_factor = 1.5
            elif age_seconds < 300:  # Last 5 minutes
                age_factor = 1.2
        
        # --- Factor 5: Prior Crash Correlation ---
        # If this seed or similar ones found crashes before, boost energy
        crash_factor = 1.0
        if hasattr(self, 'crash_correlation') and path in self.crash_correlation:
            if method in self.crash_correlation[path]:
                # This endpoint has produced crashes before
                crash_factor = 1.5
        
        # --- AFL Style Calculation ---
        # Base energy (calculated from input complexity)
        base_energy = max(5, min(20, int(seed_size / 20)))
        
        # Apply all our factors
        adjusted_energy = base_energy * size_factor * coverage_impact * path_frequency * age_factor * crash_factor
        
        # Enforce min/max bounds and ensure integer output
        final_energy = int(max(3, min(50, adjusted_energy)))
        
        # Log why this energy was assigned for debugging
        logger.debug(
            f"Energy assigned: {final_energy} for {method} {path} "
            f"(size:{seed_size}, size_factor:{size_factor:.2f}, "
            f"coverage:{coverage_impact:.2f}, path:{path_frequency:.2f}, "
            f"age:{age_factor:.2f}, crash:{crash_factor:.2f})"
        )
        
        return final_energy

    # --- Helper functions for coverage tracking ---
    def read_coverage_data(self):
        """Read the coverage data file produced by the Django middleware."""
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
        """Get the hash of the most recent coverage data."""
        coverage_data = self.read_coverage_data()
        if not coverage_data:
            return None
        sorted_entries = sorted(
            coverage_data.values(),
            key=lambda x: x.get('timestamp', 0),
            reverse=True
        )
        if sorted_entries:
            return sorted_entries[0].get('coverage_hash')
        return None

    def is_interesting(self, s_prime):
        """Check if the mutated input produced new coverage."""
        coverage_data = self.read_coverage_data()
        if not coverage_data:
            return False
        sorted_entries = sorted(
            coverage_data.values(),
            key=lambda x: x.get('timestamp', 0),
            reverse=True
        )
        if sorted_entries:
            latest_entry = sorted_entries[0]
            # Check if this entry has new coverage
            if latest_entry.get('is_new_coverage', False):
                logger.info(f"Found new coverage path with hash: {latest_entry.get('coverage_hash')}")
                method = latest_entry.get('method', '')
                path = latest_entry.get('path', '')
                logger.info(f"New coverage from: {method} {path}")
                return True
        return False

# --- Server control functions ---
def start_django_server(preserve_coverage=True):
    """Start the Django development server with coverage enabled."""
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        django_dir = os.path.join(base_dir, "DjangoWebApplication")
        cwd = os.path.join(base_dir, "DjangoWebApplication")  # This is correct - keeps pointing to where manage.py is
        if os.name=="nt":
            logger.error("Windows OS is not supported for server execution")
            return None
        else:
            python_path = os.path.join(django_dir, "virtual", "bin", "python")
            
        
        # Remove the coverage_data.json file if it exists to start fresh
        logger.info("Erasing previous coverage data...")
        coverage_file = os.path.join(cwd, "coverage_data.json")
        if not preserve_coverage and os.path.exists(coverage_file):
            logger.info("Erasing previous coverage data...")
            os.remove(coverage_file)
            logger.info("Deleted existing coverage_data.json.")
        elif preserve_coverage and not os.path.exists(coverage_file):
            # Create an empty coverage file if it doesn't exist
            with open(coverage_file, 'w') as f:
                json.dump({}, f)
            logger.info("Created new coverage_data.json file.")

        # Start the Django server with coverage using the full path to Python
        logger.info(f"Starting Django server with coverage from: {cwd}")
        
        cmd = [python_path, "-m", "coverage", "run", "manage.py", "runserver"]
        # cmd = [python_path, "-m", "coverage", "run", "manage.py", "runserver"]
        server_process = subprocess.Popen(
            cmd,
            cwd=cwd,  # Keep this as is - it needs to point to Django project root
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
    """Poll the URL until the server responds or timeout is reached."""
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


def get_random_id():
    """Generate a random ID for use in endpoint URLs."""
    if random.random() < 0.7:
        # Return a normal ID most of the time
        return str(random.randint(1, 100))
    
    # Use MutationEngine for the mutation 
    engine = MutationEngine()
    
    # For unusual IDs, choose from these options
    return random.choice([
        "-1",                                                
        "0",                                                 
        "abc",                                              
        engine.random_byte_str(str(random.randint(1, 100))),
        str(random.randint(1000000, 10000000))              
    ])

def choose_next_seed(SeedQ):
    """Choose a random path and seed from SeedQ."""
    path = random.choice(list(SeedQ.keys()))
    if not SeedQ[path]["methods"]:
        return None, None
    if SeedQ[path]["seeds"]:
        seed = random.choice(SeedQ[path]["seeds"])
    else:
        seed = copy.deepcopy(DEFAULT_PAYLOAD)
    return path, seed

def send_request(request, timeout=5.0):
    """Send an HTTP request using the provided Request object."""
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

def fuzz_application(openapi_file: str = "open_api.json"):
    """Main fuzzing function that uses SeedQ and FailureQ for tracking test cases."""
    server_process = start_django_server()
    if not server_process:
        logger.error("Failed to start Django server. Exiting.")
        return
    # Instantiate the client without needing to supply a base URL
    client = FuzzerClient(openapi_file)
    if not wait_for_server(client.base_url, timeout=30):
        logger.error("Server failed to start within the timeout period. Exiting.")
        return
    token = client.ensure_authenticated()
    if not token:
        logger.error("Authentication failed. Exiting.")
        return
    logger.info("Authentication successful. Starting greybox fuzzing...")
    start_time = time.time()
    try:
        num_tests = 0
        num_crashes = 0
        num_interesting = 0
        unique_bugs = 0
        while num_tests < 1000:
            s = client.choose_next(client.SeedQ)
            if s is None:
                logger.warning("No more seeds in the queue to test!")
                break
            energy = client.assign_energy(s)
            logger.info(f"Selected seed with energy {energy}: {s['method']} {s['path']}")
            for k in range(energy):
                s_prime = client.mutate_input(s)
                request_obj = s_prime["request"]
                logger.info(f"Mutation {k+1}/{energy}: {request_obj.method} {s_prime['current_path']}")
                if request_obj.payload:
                    logger.info(f"Payload: {request_obj.payload}")
                response, response_time, error = send_request(request_obj)
                client.tests[client.test_id] = datetime.datetime.now().isoformat()
                client.test_id += 1
                num_tests += 1
                
                # Check for server crashes or errors
                reveals_bug = False
                server_crashed = False
                
                # Check if the server process has terminated
                if server_process.poll() is not None:
                    reveals_bug = True
                    server_crashed = True
                    logger.warning("Server crashed! Process terminated unexpectedly.")
                    num_crashes += 1
                # Check for connection errors that indicate server is down
                elif error and ("Connection refused" in str(error) or 
                               "Failed to establish a new connection" in str(error) or
                               "Connection reset by peer" in str(error)):
                    reveals_bug = True
                    server_crashed = True
                    logger.warning(f"Server crashed! Connection error: {error}")
                    num_crashes += 1
                # Check for other errors or 5xx responses
                elif error:
                    reveals_bug = True
                    logger.warning(f"Request error: {error}")
                    num_crashes += 1
                elif response and response.status_code >= 500:
                    reveals_bug = True
                    logger.warning(f"Server error detected! Status code: {response.status_code}")
                    num_crashes += 1
                
                if reveals_bug:
                    path = s_prime["path"]
                    method = s_prime["method"]
                    status_code = "CRASH" if server_crashed else str(response.status_code) if response else "ERROR"

                    # Use bug classifier to identify if this is a unique bug
                    response_text = response.text if response else None
                    error_str = str(error) if error else None
                    
                    is_new_bug, bug_id, signature = client.bug_classifier.classify_bug(
                        path, method, status_code, s_prime["seed"], response_text, error_str
                    )
                    
                    if is_new_bug:
                        unique_bugs += 1
                        logger.warning(f"Discovered new unique bug: {bug_id} with signature {signature}")
                    else:
                        logger.info(f"Found instance of known bug: {bug_id}")

                    if path not in client.FailureQ:
                        client.FailureQ[path] = {}
                    if method not in client.FailureQ[path]:
                        client.FailureQ[path][method] = {}
                    if status_code not in client.FailureQ[path][method]:
                        client.FailureQ[path][method][status_code] = []
                    failure_info = {
                        "input": s_prime["seed"],
                        "timestamp": datetime.datetime.now().isoformat(),
                        "mutation_id": s_prime["mutation_id"],
                        "bug_id": bug_id,
                        "signature": signature,
                    }
                    if response:
                        failure_info["response"] = response.text[:1000]
                    if error:
                        failure_info["error"] = str(error)
                    client.FailureQ[path][method][status_code].append(failure_info)
                    if len(client.FailureQ[path][method][status_code]) == 1:
                        client.failure_time[len(client.failure_time)] = datetime.datetime.now().isoformat()
                    
                    # Restart the server if it crashed or connection was refused
                    if server_crashed:
                        logger.info("Restarting the server...")
                        # Make sure to terminate the process if it's still running
                        if server_process.poll() is None:
                            try:
                                server_process.terminate()
                                server_process.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                logger.warning("Server process did not terminate gracefully, killing it.")
                                server_process.kill()
                                server_process.wait()
                        
                        # Wait a moment before restarting
                        time.sleep(2)
                        
                        # Start a new server process
                        server_process = start_django_server(preserve_coverage=True)
                        if not server_process:
                            logger.error("Failed to restart server. Aborting.")
                            break
                            
                        # Wait for the server to be ready
                        if not wait_for_server(client.base_url, timeout=30):
                            logger.error("Failed to restart server. Aborting.")
                            break
                            
                        # Re-authenticate with the server
                        token = client.ensure_authenticated()
                        if not token:
                            logger.error("Failed to re-authenticate after server restart. Aborting.")
                            break
    
                # Check if the input is interesting (found new coverage)
                is_interesting = client.is_interesting(s_prime)            
                if is_interesting:
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
                # Update energy metrics after each test execution    
                client.update_energy_metrics(s_prime, reveals_bug, is_interesting)
                if num_tests % 10 == 0:
                    elapsed_time = time.time() - start_time
                    logger.info(f"Progress: {num_tests} tests, {num_crashes} crashes, {num_interesting} interesting cases, {elapsed_time:.2f} seconds elapsed")
                time.sleep(0.1)
    except KeyboardInterrupt:
        logger.info("Fuzzing interrupted by user")
    except Exception as e:
        logger.error(f"Exception during fuzzing: {e}")
        logger.error(traceback.format_exc())
    finally:
        client.save_session_data()
        print("\n" + "=" * 50)
        print("FUZZING SUMMARY")
        print("=" * 50)
        print(f"Total tests executed: {num_tests}")
        print(f"Total crashes found: {num_crashes}")
        print(f"Interesting test cases: {num_interesting}")
        print(f"Unique bugs identified: {unique_bugs}")
        print(f"Session data saved to: {client.session_folder}")
        print(f"Bug samples saved to: bug_samples/")

        # Print the bug summary table
        print("\n" + "=" * 50)
        print("UNIQUE BUGS SUMMARY")
        print("=" * 50)
        print(client.bug_classifier.generate_summary_table())

        if server_process and server_process.poll() is None:
            logger.info("Terminating server process...")
            server_process.terminate()
            server_process.wait()
        return client

def add_to_seed_queue(client, endpoint, method, payload):
    """Manually add a seed to the SeedQ."""
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

def main(openapi_file: str = "open_api.json"):
    """Main entry point for the fuzzer."""
    logger.info("Starting Django fuzzer")
    client = fuzz_application(openapi_file)
    if client:
        # Check if any bugs were found
        if client.bug_classifier.unique_bugs:
            print("\nBUG ANALYSIS")
            print("=" * 50)
            print(f"Found {len(client.bug_classifier.unique_bugs)} unique bugs.")
            print(f"Details saved to bug_samples/ directory.")
            print("\nTo reproduce these bugs, use the JSON files in the bug_samples/ directory.")
            
            # Print minimal reproduction steps for each bug
            print("\nMINIMAL REPRODUCTION STEPS:")
            print("=" * 50)
            for signature, bug in sorted(client.bug_classifier.unique_bugs.items(), 
                                         key=lambda x: x[1]['id']):
                print(f"Bug ID: {bug['id']}")
                print(f"Endpoint: {bug['method']} {bug['path']}")
                print(f"Payload: {json.dumps(bug['minimal_payload'])}")
                print("-" * 40)
        else:
            print("\nNo bugs were found during this fuzzing session.")
            
        logger.info("Fuzzing completed")
    else:
        logger.error("Fuzzing failed to start")

if __name__ == "__main__":
    main()
