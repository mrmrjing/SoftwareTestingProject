import sys
import requests
import random
import string
import copy
import logging
import time
import subprocess
import os
import json
from mutations import MutationEngine
from simple_fuzzer2 import FuzzerClient, Request, BugClassifier, start_django_server, wait_for_server

logger = logging.getLogger("EnhancedFuzzer")
logger.setLevel(logging.INFO)

class EnhancedFuzzerClient(FuzzerClient):
    """Extends FuzzerClient with metamorphic testing capabilities"""
    
    def __init__(self, openapi_file="open_api.json"):
        super().__init__(openapi_file)
        self.created_resources = set()  # Track (endpoint, resource_id)
        self.mutation_engine = MutationEngine()  # Inherited but reinitialized for safety

    # Metamorphic testing operations
    def create_resource(self, endpoint, data):
        """Create resource and track it for later verification"""
        request = Request(
            method="POST",
            url=f"{self.base_url}{endpoint}",
            payload=data,
            headers=self.headers
        )
        response, _, _ = self.send_request(request)
        
        if response and response.status_code == 201:
            resource_id = response.json().get('id')
            if resource_id:
                self.created_resources.add((endpoint, resource_id))
                logger.info(f"Created resource {endpoint}{resource_id}/")
                return resource_id
        return None

    def verify_resource_exists(self, endpoint, resource_id):
        """Verify a resource exists (should return 200)"""
        request = Request(
            method="GET",
            url=f"{self.base_url}{endpoint}{resource_id}/",
            headers=self.headers
        )
        response, _, _ = self.send_request(request)
        return response.status_code == 200 if response else False

    def delete_resource(self, endpoint, resource_id):
        """Delete a resource and remove from tracking"""
        request = Request(
            method="DELETE",
            url=f"{self.base_url}{endpoint}{resource_id}/",
            headers=self.headers
        )
        response, _, _ = self.send_request(request)
        
        if response and response.status_code == 204:
            self.created_resources.discard((endpoint, resource_id))
            logger.info(f"Deleted resource {endpoint}{resource_id}/")
            return True
        return False

    def cleanup(self):
        """Clean up all created resources"""
        for endpoint, resource_id in list(self.created_resources):
            self.delete_resource(endpoint, resource_id)

def directed_fuzz(max_iterations=200):
    """Enhanced fuzzing with metamorphic relationship checks"""
    server_process = start_django_server()
    if not server_process:
        logger.error("Failed to start Django server. Exiting.")
        return

    client = EnhancedFuzzerClient()
    if not wait_for_server(client.base_url, timeout=30):
        logger.error("Server failed to start within timeout period. Exiting.")
        return
    
    if not client.ensure_authenticated():
        logger.error("Authentication failed. Exiting.")
        return

    # Initialize seed queue with directed testing endpoints
    client.SeedQ = {
        "/api/products/": {
            "methods": {"POST": True, "GET": True, "DELETE": True},
            "seeds": [{"name": "Test Product", "price": 100}]
        }
    }

    iteration = 0
    unique_bugs = set()
    
    try:
        while iteration < max_iterations:
            s = client.choose_next(client.SeedQ)
            if not s:
                logger.warning("No more seeds in queue!")
                break

            # Mutate using enhanced mutation engine
            mutated_payload = client.mutation_engine.mutate_payload(s["seed"])
            logger.info(f"Testing mutated payload: {mutated_payload}")

            # Metamorphic testing sequence
            resource_id = client.create_resource(s["path"], mutated_payload)
            if resource_id:
                # Verify creation
                if not client.verify_resource_exists(s["path"], resource_id):
                    logger.error("Metamorphic violation: Resource not found after creation!")
                    client.bug_classifier.classify_bug(
                        s["path"], "POST", 500, mutated_payload,
                        "Resource not found after creation", None
                    )
                
                # Delete and verify deletion
                if client.delete_resource(s["path"], resource_id):
                    if client.verify_resource_exists(s["path"], resource_id):
                        logger.error("Metamorphic violation: Resource still exists after deletion!")
                        client.bug_classifier.classify_bug(
                            s["path"], "DELETE", 500, mutated_payload,
                            "Resource persists after deletion", None
                        )

            # Standard fuzzing path
            request = Request(
                method=s["method"],
                url=f"{client.base_url}{s["path"]}",
                payload=mutated_payload,
                headers=client.headers
            )
            
            response, _, error = client.send_request(request)
            reveals_bug = False
            
            # Error detection
            if error or (response and response.status_code >= 500):
                reveals_bug = True
                status_code = "CRASH" if error else str(response.status_code)
                error_str = str(error) if error else None
                response_text = response.text if response else None
                
                is_new, bug_id, _ = client.bug_classifier.classify_bug(
                    s["path"], s["method"], status_code,
                    mutated_payload, response_text, error_str
                )
                
                if is_new:
                    unique_bugs.add(bug_id)
                    logger.warning(f"New bug detected: {bug_id}")

            client.update_energy_metrics(s, reveals_bug, False)
            iteration += 1
            
            # Progress reporting
            if iteration % 10 == 0:
                logger.info(
                    f"Iteration {iteration}/{max_iterations} - "
                    f"Unique bugs: {len(unique_bugs)}"
                )

    except KeyboardInterrupt:
        logger.info("Fuzzing interrupted by user")
    finally:
        client.cleanup()
        client.save_session_data()
        logger.info(f"Completed {iteration} iterations with {len(unique_bugs)} unique bugs found")
        
        if server_process.poll() is None:
            server_process.terminate()
            logger.info("Server process terminated")

if __name__ == "__main__":
    directed_fuzz(max_iterations=500)