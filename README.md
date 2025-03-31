Bugs found manually: 
1. Theres a problem with the http://127.0.0.1:8000/datatb/product/ endpoint as well, if u click export to pdf or run a GET /datatb/product/export/ u'll get a crash

2. there's another crash with the http://127.0.0.1:8000/datatb/product/edit/0/

3. another crash when we visit datatb/product/add/

4. datatb/product/export/?

5. GET http://127.0.0.1:8000/datatb/product/?entries=100/ (HOW to fit this into the fuzzer)


**31/3/2025**
TODO: Implement code coverage instrumentation
- [ ] Add Django coverage measurement tools
- [ ] Modify server startup to include coverage tracking
- [ ] Create an API to retrieve coverage data after each request
- [ ] Store coverage data efficiently for comparison

TODO: Add energy assignment algorithms
- [ ] Implement AssignEnergy() function based on seed performance
- [ ] Add metrics for determining seed value (code coverage, execution time)
- [ ] Develop dynamic scaling for energy values
- [ ] Track performance of different energy allocation strategies

TODO: Enhance seed selection strategy
- [ ] Modify choose_next_seed() to prioritize based on coverage metrics
- [ ] Implement weighted selection for seeds that reach rare code paths
- [ ] Add scheduling algorithm for balancing exploration vs exploitation
- [ ] Create seed performance history tracking

TODO: Add coverage-based interestingness detection
- [ ] Replace random probability with actual coverage comparison
- [ ] Implement efficient coverage difference calculation
- [ ] Add thresholds for determining significant coverage differences
- [ ] Create visualization of coverage growth over time

TODO: Optimize mutation strategies based on results
- [ ] Track which mutation types produce more interesting results
- [ ] Implement targeted mutations for specific data types
- [ ] Add adaptive mutation rates based on success history
- [ ] Develop grammar-based mutations for structured inputs

TODO: Improve session management and reporting
- [ ] Add detailed statistics on coverage growth
- [ ] Create visualizations of code coverage
- [ ] Generate more detailed crash reports with execution traces
- [ ] Implement resumable fuzzing sessions
