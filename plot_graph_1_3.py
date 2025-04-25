# Plot number of interesting test cases vs number of tests 

import json
import os
import matplotlib.pyplot as plt
import datetime
import argparse

def plot_interesting_vs_tests(session_folder):
    """
    Plot the number of interesting test cases versus the number of tests executed
    using interesting.json and tests.json.
    
    Args:
        session_folder: Path to the session folder containing the fuzzing data
    """
    # Load the interesting.json data
    interesting_path = os.path.join(session_folder, "interesting.json")
    if not os.path.exists(interesting_path):
        print(f"Error: interesting.json not found in {session_folder}")
        return
    
    # Load the tests.json data
    tests_path = os.path.join(session_folder, "tests.json")
    if not os.path.exists(tests_path):
        print(f"Error: tests.json not found in {session_folder}")
        return
    
    with open(interesting_path, 'r') as f:
        interesting_data = json.load(f)
    
    with open(tests_path, 'r') as f:
        tests_data = json.load(f)
    
    # Extract timestamps from interesting.json
    interesting_timestamps = []
    for _, entry in interesting_data.items():
        # Handle both formats: string timestamps and dictionary entries
        if isinstance(entry, str):
            interesting_timestamps.append(entry)
        elif isinstance(entry, dict) and "timestamp" in entry:
            interesting_timestamps.append(entry["timestamp"])
    
    # Extract timestamps from tests.json
    test_timestamps = []
    for _, timestamp in tests_data.items():
        test_timestamps.append(timestamp)
    
    # Parse timestamps to datetime objects
    interesting_datetimes = []
    for ts in interesting_timestamps:
        try:
            dt = datetime.datetime.fromisoformat(ts)
            interesting_datetimes.append(dt)
        except (ValueError, TypeError):
            # Skip invalid timestamps
            continue
    
    test_datetimes = []
    for ts in test_timestamps:
        try:
            dt = datetime.datetime.fromisoformat(ts)
            test_datetimes.append(dt)
        except (ValueError, TypeError):
            # Skip invalid timestamps
            continue
    
    # Sort timestamps
    interesting_datetimes.sort()
    test_datetimes.sort()
    
    # Create mapping of test count to interesting count
    test_count_to_interesting = []
    
    interesting_count = 0
    test_count = 0
    
    # Initialize with starting point
    test_count_to_interesting.append((0, 0))
    
    # Merge the two timestamp lists and process in chronological order
    all_events = []
    for dt in interesting_datetimes:
        all_events.append((dt, "interesting"))
    for dt in test_datetimes:
        all_events.append((dt, "test"))
    
    all_events.sort(key=lambda x: x[0])
    
    for dt, event_type in all_events:
        if event_type == "test":
            test_count += 1
        elif event_type == "interesting":
            interesting_count += 1
            # Record the current test count and interesting count
            test_count_to_interesting.append((test_count, interesting_count))
    
    # Extract data for plotting
    test_counts = [x[0] for x in test_count_to_interesting]
    interesting_counts = [x[1] for x in test_count_to_interesting]
    
    # Create the plot
    plt.figure(figsize=(10, 6))
    plt.plot(test_counts, interesting_counts, marker='o', linestyle='-', color='green')
    plt.title('Interesting Test Cases vs Number of Tests')
    plt.xlabel('Number of Tests Executed')
    plt.ylabel('Number of Interesting Test Cases')
    plt.grid(True)
    
    # Add final count annotation
    if interesting_counts:
        plt.annotate(f'Total: {interesting_counts[-1]}', 
                    xy=(test_counts[-1], interesting_counts[-1]),
                    xytext=(test_counts[-1] - test_counts[-1]*0.1, interesting_counts[-1] + 0.5),
                    fontsize=12)
    
    # Save the plot
    plot_path = os.path.join(session_folder, 'interesting_vs_tests.png')
    plt.savefig(plot_path)
    print(f"Plot saved to {plot_path}")
    
    # Show the plot
    plt.show()

def main():
    parser = argparse.ArgumentParser(description='Plot interesting test cases vs number of tests from fuzzing session data')
    parser.add_argument('session_folder', type=str, help='Path to the fuzzing session folder')
    args = parser.parse_args()
    
    session_folder = args.session_folder
    if not os.path.isdir(session_folder):
        print(f"Error: {session_folder} is not a valid directory")
        return
    
    plot_interesting_vs_tests(session_folder)

if __name__ == "__main__":
    main()
