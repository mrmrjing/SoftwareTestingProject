import os
import json
import coverage
import threading
import hashlib
import time
import logging 

logger = logging.getLogger('coverage_middleware')
logger.setLevel(logging.DEBUG)
handler = logging.FileHandler('coverage_middleware.log')
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

class CoverageMiddleware:
    coverage_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'coverage_data.json')
    lock = threading.Lock()
    # Track global coverage for overall metrics
    global_coverage = {}
    
    def __init__(self, get_response):
        self.get_response = get_response
        # Create coverage file directory if it doesn't exist
        os.makedirs(os.path.dirname(self.coverage_file), exist_ok=True)
        # Initialize the coverage file if it doesn't exist
        if not os.path.exists(self.coverage_file):
            with open(self.coverage_file, 'w') as f:
                json.dump({}, f)
    
    def __call__(self, request):
        # Log request info 
        logger.debug(f"Processing request: {request.method} {request.path}")
        # Create a unique identifier for this request
        request_id = f"{request.method}:{request.path}:{int(time.time())}"
        request_hash = hashlib.md5(f"{request.method}:{request.path}:{request.body}".encode()).hexdigest()
        
        # Create a fresh Coverage instance for this request
        cov = coverage.Coverage(
            source=["core", "api", "home"],  # Change to include the specific source directories we want to track coverage for 
            data_file=None,  # Use memory storage, not a file
            config_file=False,
        )
        
        # Start coverage collection
        cov.start()
        
        # Process the request
        response = self.get_response(request)
        
        # Stop coverage collection
        cov.stop()
        
        # Extract coverage data for this request
        with self.lock:
            # Get coverage data
            data = cov.get_data()
            measured_files = data.measured_files()
            
            # Store line coverage information for each file
            file_coverage = {}
            for filename in measured_files:
                if os.path.exists(filename):
                    lines = data.lines(filename)
                    file_coverage[filename] = list(lines)
            
            # Generate coverage hash for this request
            coverage_hash = hashlib.md5(
                json.dumps(file_coverage, sort_keys=True).encode()
            ).hexdigest()
            
            # Load existing coverage data
            try:
                with open(self.coverage_file, 'r') as f:
                    coverage_data = json.load(f)
            except (IOError, json.JSONDecodeError):
                coverage_data = {}
            
            # Update the global coverage data
            for filename, lines in file_coverage.items():
                if filename not in self.global_coverage:
                    self.global_coverage[filename] = set()
                self.global_coverage[filename].update(lines)
            
            # Store this request's coverage and metadata
            coverage_data[request_hash] = {
                'id': request_id,
                'method': request.method,
                'path': request.path,
                'coverage': file_coverage,
                'coverage_hash': coverage_hash,
                'timestamp': time.time(),
                'status_code': response.status_code,
                # Include a sample of request body (if it exists)
                'request_body': request.body.decode('utf-8', errors='ignore')[:200] if request.body else None,
                # Track if this is new coverage
                'is_new_coverage': self._is_new_coverage(coverage_hash, coverage_data)
            }
            
            # Write updated coverage data to file
            try:
                with open(self.coverage_file, 'w') as f:
                    json.dump(coverage_data, f)
            except Exception as e:
                print(f"Error saving coverage data: {e}")
        
        return response
    
    def _is_new_coverage(self, coverage_hash, coverage_data):
        """Check if this coverage hash is new (not seen before)"""
        for entry in coverage_data.values():
            if 'coverage_hash' in entry and entry['coverage_hash'] == coverage_hash:
                return False
        return True
