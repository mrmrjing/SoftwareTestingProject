import sys
import requests
import random
import string
import copy
import logging
import time
import subprocess
import os

# --- Logging configuration ---
logger = logging.getLogger("GreyboxFuzzer")
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler("fuzz_log.txt")
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Crash report logger
crash_report = open("crash_report.txt", "w")


class FuzzerClient:
    def __init__(self):
        self.headers = {}

    def register_user(self, username, password, email):
        registration_url = "http://127.0.0.1:8000/accounts/register/"
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
        login_url = "http://127.0.0.1:8000/login/jwt/"
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


# Mutation helpers
def mutate_input(seed: str, num_mutations=1) -> str:
    if not seed:
        return seed
    seed_list = list(seed)
    for _ in range(num_mutations):
        index = random.randint(0, len(seed_list) - 1)
        seed_list[index] = random.choice(string.printable)
    return "".join(seed_list)


def mutate_payload(payload: dict) -> dict:
    mutated = copy.deepcopy(payload)
    for key, value in mutated.items():
        if isinstance(value, str):
            mutated[key] = mutate_input(value, random.randint(1, 3))
        elif isinstance(value, int):
            mutated[key] = value + random.randint(-5, 5)
    return mutated


def send_request(method, url, headers=None, payload=None):
    try:
        if payload is not None:
            response = requests.request(method, url, json=payload, headers=headers, timeout=5)
        else:
            response = requests.request(method, url, headers=headers, timeout=5)
        return response
    except Exception as e:
        logger.error(f"Error sending {method} to {url}: {e}")
        return None


def start_django_server():
    print("Trying to start django server")
    """
    Start the Django server normally (without using coverage).
    """
    try:
        # Compute the Django project directory relative to this script.
        base_dir = os.path.dirname(os.path.abspath(__file__))
        cwd = os.path.join(base_dir, "DjangoWebApplication")
        logger.info(f"Starting Django server from: {cwd}")
        # sys.exit(1)
        # # return "success"        
        # Command to run the Django development server normally.
        ENV_NAME = "env"
        cmd = [f"{ENV_NAME}/bin/python", "manage.py", "runserver"]
        
        server_process = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return server_process

    except Exception as e:
        logger.error(f"Failed to start Django server: {e}")
        return None


def wait_for_server(url, timeout=30, interval=0.5):
    """
    Repeatedly attempts to connect to the given URL until a response is received or the timeout is reached.
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(url, timeout=2)
            logger.info("Server is up and running!")
            return True
        except requests.RequestException:
            time.sleep(interval)
    logger.error("Server did not start within the specified timeout.")
    return False


def fuzz():
    client = FuzzerClient()
    django_proc = start_django_server()

    if django_proc is None:
        logger.error("Django server process failed to start. Exiting fuzzing.")
        return

    base_url = "http://127.0.0.1:8000"
    # Instead of using a fixed sleep, wait until the server is available.
    if not wait_for_server(base_url, timeout=30, interval=0.5):
        logger.error("Django server did not start. Exiting fuzzing.")
        django_proc.terminate()
        return

    token = client.ensure_authenticated()
    if not token:
        logger.error("Exiting fuzzing due to failed authentication.")
        django_proc.terminate()
        return

    headers = client.headers

    seed_data = {
        "/api/product/": {
            "methods": ["GET", "POST", "PUT", "DELETE"],
            "idSeeds": ["-1", "0", "abc", "1"],
            "payloadSeeds": [
                {"name": "api_product", "price": 30},
                {"name": "sample", "price": 25}
            ]
        }
    }

    failure_queue = {ep: {"id": [], "payload": []} for ep in seed_data}
    max_iterations = 100
    iteration = 0

    while iteration < max_iterations:
        for endpoint, config in seed_data.items():
            full_endpoint = base_url + endpoint
            methods = config.get("methods", [])
            for method in methods:
                method = method.upper()
                if method in ["GET", "DELETE"]:
                    seeds = config["idSeeds"][:]
                    if failure_queue[endpoint]["id"] and random.random() < 0.3:
                        seeds += failure_queue[endpoint]["id"]
                    for seed in seeds:
                        mutated_seed = mutate_input(seed, random.randint(1, 3))
                        if not mutated_seed.isdigit():
                            continue  # Skip invalid IDs
                        url = full_endpoint + mutated_seed + "/"
                        response = send_request(method, url, headers)
                        logger.info(f"{method} {url}")
                        if response and response.status_code == 500:
                            logger.info(f"Crash detected (500): on {url}")
                            crash_report.write(f"{method} {url}\n")
                            if mutated_seed not in failure_queue[endpoint]["id"]:
                                failure_queue[endpoint]["id"].append(mutated_seed)
                        time.sleep(0.05)
                elif method in ["POST", "PUT"]:
                    seeds = config["idSeeds"][:] if method == "PUT" else [None]
                    if failure_queue[endpoint]["id"] and random.random() < 0.3:
                        seeds += failure_queue[endpoint]["id"]
                    for seed in seeds:
                        mutated_seed = mutate_input(seed, random.randint(1, 3)) if seed is not None else None
                        if mutated_seed is not None and not mutated_seed.isdigit():
                            continue  # Skip invalid IDs
                        url = full_endpoint + (mutated_seed + "/" if mutated_seed is not None else "")
                        payloads = config["payloadSeeds"][:]
                        if failure_queue[endpoint]["payload"] and random.random() < 0.3:
                            payloads += failure_queue[endpoint]["payload"]
                        for payload in payloads:
                            mutated_payload = mutate_payload(payload)
                            response = send_request(method, url, headers, mutated_payload)
                            logger.info(f"{method} {url} with payload {mutated_payload}")
                            if response and response.status_code == 500:
                                logger.info(f"Crash detected (500): on {url} with payload {mutated_payload}")
                                crash_report.write(f"{method} {url} payload: {mutated_payload}\n")
                                if mutated_payload not in failure_queue[endpoint]["payload"]:
                                    failure_queue[endpoint]["payload"].append(mutated_payload)
                            time.sleep(0.05)
        iteration += 1
        logger.info(f"Iteration {iteration} complete. Failure queue state: {failure_queue}")

    logger.info("Fuzzing complete after reaching max iterations.")
    django_proc.terminate()
    crash_report.close()


if __name__ == "__main__":
    fuzz()
