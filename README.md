# Django Greybox Fuzzer
A coverage-guided fuzzer for Django applications with OpenAPI specification support 

## Overview
This project implements a greybox fuzzing tool that automatically tests Django web applications by generating HTTP requests based on an OpenAPI specification. The fuzzer uses code coverage feedback to guide test generation, allowing it to discover bugs more efficiently.

## Features
- OpenAPI Integration: Automatically builds test inputs from OpenAPI specifications
- Coverage Feedback: Uses runtime code coverage to guide the fuzzing process
- Smart Mutations: Applies various mutation strategies to discover edge cases
- Automated Authentication: Handles user registration and login for testing protected endpoints
- Crash Detection: Identifies server crashes, timeouts, and HTTP 500 errors
- Detailed Reporting: Tracks and saves all test data for analysis


## Architecture 
The fuzzer follows the standard greybox fuzzing loop:

- Select a seed from the queue
- Assign energy (mutation iterations)
- Generate mutations of the seed
- Test each mutation
- Add any crashes to the failure queue
- Add interesting inputs (new coverage) back to the seed queue

## TODO list for 19 April 2025: 
1. Seed Selection Strategy (choose_next)
  - [x] Random seed selection from OpenAPI spec
  - [ ] Modify choose_next_seed() to prioritize based on coverage metrics
 
2. Parallel Fuzzing (if we have time)
  - [ ] Add multi-threading support for concurrent request generation
  - [ ] Implement shared coverage information across processes
 
3. Evaluation of fuzzer 
### Effectiveness
  - [ ] Graph_1_1 Plot number of unique crashes agaisnt time 
  - [ ] Graph_1_2 Plot number of interesting test cases agaisnt time 
  - [ ] Graph_1_3 Plot number of interesting test cases agianst number of tests generated (use the tests.json file)
  - Coverage obtained with respect to time and generated tests 
  - Provide a table of all the unique bugs found


# How To Run Django Fuzzer : 

install everything inside the django webapplication 
get the location of your django env file 

What should the "api" do ?
start django fuzzer / start ble shit 
for django , allow users to specify their virtual env and shit 


allow passing in arguments for openapi file 



Install virtual environemnt , 
install the following libraries 

pip install requests tabulate coverage
from dotenv import load_dotenv
import os