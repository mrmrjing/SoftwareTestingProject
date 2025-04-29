# Plot number of unique crashes over wall clock time
import json
import os
import matplotlib.pyplot as plt
import datetime
import argparse

def plot_unique_crashes_over_time(session_folder):
    """
    Plot the number of unique crashes over time using failureQ.json
    which contains the actual bug IDs and timestamps.
    
    Args:
        session_folder: Path to the session folder containing the fuzzing data
    """
    # Load the failureQ data which contains bug IDs and timestamps
    failureq_path = os.path.join(session_folder, "failureQ.json")
    if not os.path.exists(failureq_path):
        print(f"Error: failureQ.json not found in {session_folder}")
        return
    
    with open(failureq_path, 'r') as f:
        failureq_data = json.load(f)
    
    # Extract bug IDs and timestamps from failureQ.json
    bug_timestamps = []
    
    for path in failureq_data:
        for method in failureq_data[path]:
            for status in failureq_data[path][method]:
                for failure in failureq_data[path][method][status]:
                    if "bug_id" in failure and "timestamp" in failure:
                        bug_timestamps.append((failure["bug_id"], failure["timestamp"]))
    
    # If we couldn't find bug IDs in failureQ.json, print an error
    if not bug_timestamps:
        print("No bug IDs found in failureQ.json. Cannot create plot.")
        return
    
    # Sort by timestamp
    bug_timestamps.sort(key=lambda x: x[1])
    
    # Track unique bugs over time
    seen_bugs = set()
    unique_bugs_by_time = {}
    
    for bug_id, timestamp in bug_timestamps:
        if bug_id not in seen_bugs:
            seen_bugs.add(bug_id)
            unique_bugs_by_time[timestamp] = len(seen_bugs)
    
    # Convert to lists for plotting
    timestamps = [datetime.datetime.fromisoformat(ts) for ts in unique_bugs_by_time.keys()]
    bug_counts = list(unique_bugs_by_time.values())
    
    # Calculate elapsed time in minutes from the first timestamp
    if timestamps:
        start_time = min(timestamps)
        elapsed_minutes = [(ts - start_time).total_seconds() / 60 for ts in timestamps]
        
        # Create the plot
        plt.figure(figsize=(10, 6))
        plt.plot(elapsed_minutes, bug_counts, marker='o', linestyle='-', color='red')
        plt.title('Unique Crashes Over Time')
        plt.xlabel('Elapsed Time (minutes)')
        plt.ylabel('Number of Unique Crashes')
        plt.grid(True)
        
        # Add final count annotation
        if bug_counts:
            plt.annotate(f'Total: {bug_counts[-1]}', 
                        xy=(elapsed_minutes[-1], bug_counts[-1]),
                        xytext=(elapsed_minutes[-1] - 0.5, bug_counts[-1] + 0.5),
                        fontsize=12)
        
        # Save the plot
        plot_path = os.path.join(session_folder, 'unique_crashes_over_time.png')
        plt.savefig(plot_path)
        print(f"Plot saved to {plot_path}")
        
        # Show the plot
        plt.show()
    else:
        print("No crash data found to plot")

def main():
    parser = argparse.ArgumentParser(description='Plot unique crashes over time from fuzzing session data')
    parser.add_argument('session_folder', type=str, help='Path to the fuzzing session folder')
    args = parser.parse_args()
    
    session_folder = args.session_folder
    if not os.path.isdir(session_folder):
        print(f"Error: {session_folder} is not a valid directory")
        return
    
    plot_unique_crashes_over_time(session_folder)

if __name__ == "__main__":
    main()
