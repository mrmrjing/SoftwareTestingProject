import sys
import requests
import random
import string
import copy
import logging
import time
import subprocess
import os
from coverage import Coverage

logger = logging.getLogger("EnhancedFuzzer")
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler("fuzz_log_v3.txt")
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

crash_report = open("crash_report_v3.txt", "w")
coverage = Coverage()

class EnhancedFuzzerClient:
    def __init__(self):
        self.headers = {}
        self.created_resources = set()
        self.coverage_file = "coverage_metrics.txt"
        
    def register_user(self, username, password, email):
        payload = {
            "username": username,
            "email": email,
            "password1": password,
            "password2": password
        }
        response = requests.post("http://127.0.0.1:8000/accounts/register/", data=payload)
        return response.status_code in (200, 201)

    def login_user(self, username, password):
        response = requests.post("http://127.0.0.1:8000/login/jwt/", json={"username": username, "password": password})
        if response.status_code == 200:
            self.headers["Authorization"] = f"Token {response.json().get('token')}"
            return True
        return False

    def ensure_auth(self):
        if not self.login_user("test", "test"):
            self.register_user("test", "test", "test@test.com")
            self.login_user("test", "test")

    # Metamorphic relation methods
    def create_resource(self, endpoint, data):
        response = requests.post(f"http://127.0.0.1:8000{endpoint}", json=data, headers=self.headers)
        if response.status_code == 201:
            resource_id = response.json().get('id')
            self.created_resources.add((endpoint, resource_id))
            return resource_id
        return None

    def verify_resource_exists(self, endpoint, resource_id):
        response = requests.get(f"http://127.0.0.1:8000{endpoint}{resource_id}/", headers=self.headers)
        return response.status_code == 200

    def delete_resource(self, endpoint, resource_id):
        response = requests.delete(f"http://127.0.0.1:8000{endpoint}{resource_id}/", headers=self.headers)
        if response.status_code == 204:
            self.created_resources.discard((endpoint, resource_id))
            return True
        return False

    def cleanup(self):
        for endpoint, resource_id in list(self.created_resources):
            self.delete_resource(endpoint, resource_id)

def mutate_input(seed: str, num_mutations=1) -> str:
    strategies = [
        lambda s: s + random.choice(['', '!', '@', '#', '$', '%']),
        lambda s: s[:-1] if len(s) > 0 else s,
        lambda s: s.upper(),
        lambda s: s.replace('a', 'aaaaa'),
        lambda s: ''.join(random.choices(string.printable, k=len(s)))
    ]
    for _ in range(num_mutations):
        seed = random.choice(strategies)(seed)
    return seed

def mutate_payload(payload: dict) -> dict:
    mutated = copy.deepcopy(payload)
    for key in mutated:
        if isinstance(mutated[key], int):
            mutated[key] = random.choice([
                mutated[key] + 1000,
                -mutated[key],
                0x7fffffff
            ])
        elif isinstance(mutated[key], str):
            mutated[key] = mutate_input(mutated[key], 2)
    return mutated

def start_coverage_server():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    cwd = os.path.join(base_dir, "DjangoWebApplication")
    cmd = ["coverage", "run", "manage.py", "runserver"]
    return subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

def read_coverage():
    coverage.load()
    covered = coverage.data.measured_files()
    with open("coverage_metrics.txt", "a") as f:
        f.write(f"{time.time()}: {len(covered)}\n")
    return len(covered)

def directed_fuzz(max_iterations=200):
    client = EnhancedFuzzerClient()
    client.ensure_auth()
    server_proc = start_coverage_server()
    
    seed_endpoints = {
        "/api/products/": {
            "methods": ["POST", "GET", "DELETE"],
            "payloads": [{"name": "Test", "price": 100}],
            "relations": [
                ("CREATE_DELETE", lambda: client.cleanup())
            ]
        }
    }

    coverage_history = set()
    iteration = 0
    
    while iteration < max_iterations:
        for endpoint, config in seed_endpoints.items():
            for method in config["methods"]:
                if method == "POST":
                    payload = mutate_payload(random.choice(config["payloads"]))
                    resource_id = client.create_resource(endpoint, payload)
                    if resource_id:
                        assert client.verify_resource_exists(endpoint, resource_id)
                        client.delete_resource(endpoint, resource_id)
                        assert not client.verify_resource_exists(endpoint, resource_id)
                
                current_coverage = read_coverage()
                if current_coverage not in coverage_history:
                    coverage_history.add(current_coverage)
                    logger.info(f"New coverage achieved: {current_coverage} files")
                
                url = f"http://127.0.0.1:8000{endpoint}"
                response = requests.request(
                    method,
                    url,
                    headers=client.headers,
                    json=mutate_payload({}) if method in ["POST", "PUT"] else None
                )
                if response.status_code >= 500:
                    crash_report.write(f"CRASH: {method} {url} - {response.status_code}\n")
        
        iteration += 1
        logger.info(f"Directed iteration {iteration} complete. Coverage: {len(coverage_history)}")

    server_proc.terminate()
    client.cleanup()
    crash_report.close()
    coverage.save()

if __name__ == "__main__":
    directed_fuzz()