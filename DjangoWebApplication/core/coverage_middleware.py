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
                json.dump({}, f, indent=2)
        
        logger.info("Coverage middleware initialized")
    
    def __call__(self, request):
        # Log request info 
        logger.debug(f"Processing request: {request.method} {request.path}")
        # Create a unique identifier for this request
        request_id = f"{request.method}:{request.path}:{int(time.time())}"
        request_hash = hashlib.md5(f"{request.method}:{request.path}:{request.body}".encode()).hexdigest()
        
        # Create a fresh Coverage instance for this request
        # No source parameter = track all Python modules imported during execution
        cov = coverage.Coverage(
            data_file=None,  # Use memory storage, not a file
            config_file=False,
            source=None,  # Track all modules
            include=["*"],  # Include all Python files
            omit=["*/site-packages/*", "*/dist-packages/*", "*/virtualenvs/*"]  # Omit standard libraries
        )
        
        # Start coverage collection
        cov.start()
        
        try:
            # Process the request
            response = self.get_response(request)
        except Exception as e:
            # Stop coverage even if there's an exception
            cov.stop()
            # Re-raise the exception
            raise
        
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
                    # Filter out only Django application files, not library files
                    # Focus on files in the current project
                    django_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                    if filename.startswith(django_root):
                        lines = data.lines(filename)
                        file_coverage[filename] = sorted(list(lines))  # Sort for consistent hashing
            
            # Skip if no coverage data was collected
            if not file_coverage:
                return response
            
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
            
            # Determine if this coverage is new
            is_new_coverage = self._is_new_coverage(coverage_hash, coverage_data, file_coverage)
            
            # If new, check for new lines specifically
            if not is_new_coverage:
                # Do a deeper check for new code lines
                all_covered_lines = {}
                for entry in coverage_data.values():
                    if 'coverage' in entry:
                        for filename, lines in entry['coverage'].items():
                            if filename not in all_covered_lines:
                                all_covered_lines[filename] = set()
                            all_covered_lines[filename].update(lines)
                
                # Check each file for new lines
                for filename, lines in file_coverage.items():
                    if filename not in all_covered_lines:
                        is_new_coverage = True
                        logger.info(f"New file covered: {filename}")
                        break
                    else:
                        new_lines = set(lines) - all_covered_lines[filename]
                        if new_lines:
                            is_new_coverage = True
                            logger.info(f"New lines covered in {filename}: {new_lines}")
                            break
            
            # Store this request's coverage and metadata
            coverage_data[request_hash] = {
                'id': request_id,
                'method': request.method,
                'path': request.path,
                'coverage': file_coverage,
                'coverage_hash': coverage_hash,
                'timestamp': time.time(),
                'status_code': getattr(response, 'status_code', 0),
                # Include a sample of request body (if it exists)
                'request_body': request.body.decode('utf-8', errors='ignore')[:200] if request.body else None,
                # Track if this is new coverage
                'is_new_coverage': is_new_coverage
            }
            
            # Write updated coverage data to file with indentation for readability
            try:
                with open(self.coverage_file, 'w') as f:
                    json.dump(coverage_data, f, indent=2)
            except Exception as e:
                logger.error(f"Error saving coverage data: {e}")
                print(f"Error saving coverage data: {e}")
        
        return response
    
    def _is_new_coverage(self, coverage_hash, coverage_data, file_coverage):
        """
        Check if this coverage represents new code paths.
        More sophisticated than just checking the hash.
        """
        # Check if the hash already exists in the coverage data
        for entry in coverage_data.values():
            if 'coverage_hash' in entry and entry['coverage_hash'] == coverage_hash:
                return False
        
        # If we have no previous coverage data, this is definitely new
        if not coverage_data:
            return True
        
        # Extract the current coverage information
        current_coverage = {}
        for filename, lines in file_coverage.items():
            current_coverage[filename] = set(lines)
        
        # Get the global coverage from all previous requests
        global_coverage = {}
        for entry in coverage_data.values():
            if 'coverage' in entry:
                for filename, lines in entry['coverage'].items():
                    if filename not in global_coverage:
                        global_coverage[filename] = set()
                    global_coverage[filename].update(lines)
        
        # Check if this coverage adds anything significant
        # 1. New files
        for filename in current_coverage:
            if filename not in global_coverage:
                logger.info(f"New file covered: {filename}")
                return True
        
        # 2. New lines in existing files - with a threshold
        for filename, lines in current_coverage.items():
            if filename in global_coverage:
                new_lines = lines - global_coverage[filename]
                # Only consider it new if we have a significant number of new lines
                # This filters out noise from timestamps, logging, etc.
                if len(new_lines) >= 3:  # Threshold of 3 new lines
                    logger.info(f"Significant new coverage in {filename}: {len(new_lines)} new lines")
                    return True
        
        # If we got here, the coverage is not significantly new
        return False

