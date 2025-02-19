# Project Meeting 0 
- Discuss the overall design of fuzzer (slides/hand-drawn/word)
    * Send mutated HTTP requests to a local Django test server and track coverage 
    * Send random BLE packets to the hardware lock and detect crashes or hangs

- Highlight which parts of the fuzzer we plan to implement ourselves 
- Discuss set of tools we plan to use out-of-the-box 
- Discuss which parts of the designs are generic, and which parts need to be configured/tuned based on the two case studies 
- Discuss the use cases for the fuzzer, i.e. how would someone use our fuzzer beyond the case studies 

1. What are the test inputs? 
For Django web app: 
    - HTTP/HTTPs requests containing form data, query parameters, create a seed_http.txt file 
For BLE application: 
    - Valid BLE packets including header fields and payload, create a seed_ble_txt file

2. Which file(s) do you use to start writing your fuzzer/ which file(s) show a demo test case? 
    - Create a test driver file called fuzzer.py 

3. How do you get code coverage for Django application? 
    - Instrument the Django server so that every route or function call is measured when a request is processed(?)
    - From the docs: coverage.py
    https://docs.djangoproject.com/en/5.0/topics/testing/advanced/#integration-with-coverage-py

4. How do you detect crashes and logical bugs? 
    - Crashes: Exit codes, unhandled exceptions, or logs that show internal server errors, or server shutting down unexpectedly 
    - Logical bugs: incorrect responses, unexpected states

5. What feedbacks to collect from test execution to improve fuzzer/which tests are interesting? 

6. How to improve the fuzzer to find more bugs efficiently? 


