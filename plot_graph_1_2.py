# Plot number of interesting test cases vs wall clock time 
import json
import os
import matplotlib.pyplot as plt
import datetime
import argparse

def plot_interesting_cases_over_time(session_folder):
    """
    Plot the number of interesting test cases (new coverage) over time
    using interesting.json which tracks when new coverage was discovered.
    
    Args:
        session_folder: Path to the session folder containing the fuzzing data
    """
    # Load the interesting.json data
    interesting_path = os.path.join(session_folder, "interesting.json")
    if not os.path.exists(interesting_path):
        print(f"Error: interesting.json not found in {session_folder}")
        return
    
    with open(interesting_path, 'r') as f:
        interesting_data = json.load(f)
    
    # Extract timestamps from interesting.json
    timestamps = []
    for _, entry in interesting_data.items():
        # Handle both formats: string timestamps and dictionary entries
        if isinstance(entry, str):
            timestamps.append(entry)
        elif isinstance(entry, dict) and "timestamp" in entry:
            timestamps.append(entry["timestamp"])
    
    # Parse timestamps to datetime objects
    datetime_objects = []
    for ts in timestamps:
        try:
            dt = datetime.datetime.fromisoformat(ts)
            datetime_objects.append(dt)
        except (ValueError, TypeError):
            # Skip invalid timestamps
            continue
    
    # Sort timestamps
    datetime_objects.sort()
    
    # Calculate elapsed time in minutes from the first timestamp
    if datetime_objects:
        start_time = min(datetime_objects)
        elapsed_minutes = [(ts - start_time).total_seconds() / 60 for ts in datetime_objects]
        
        # Create the data points - each timestamp represents a new interesting case
        case_counts = list(range(1, len(elapsed_minutes) + 1))
        
        # Create the plot
        plt.figure(figsize=(10, 6))
        plt.plot(elapsed_minutes, case_counts, marker='o', linestyle='-', color='blue')
        plt.title('Interesting Test Cases Over Time (New Coverage)')
        plt.xlabel('Elapsed Time (minutes)')
        plt.ylabel('Number of Interesting Test Cases')
        plt.grid(True)
        
        # Add final count annotation
        if case_counts:
            plt.annotate(f'Total: {case_counts[-1]}', 
                        xy=(elapsed_minutes[-1], case_counts[-1]),
                        xytext=(elapsed_minutes[-1] - 0.5, case_counts[-1] + 0.5),
                        fontsize=12)
        
        # Save the plot
        plot_path = os.path.join(session_folder, 'interesting_cases_over_time.png')
        plt.savefig(plot_path)
        print(f"Plot saved to {plot_path}")
        
        # Show the plot
        plt.show()
    else:
        print("No interesting test case data found to plot")

def main():
    parser = argparse.ArgumentParser(description='Plot interesting test cases over time from fuzzing session data')
    parser.add_argument('session_folder', type=str, help='Path to the fuzzing session folder')
    args = parser.parse_args()
    
    session_folder = args.session_folder
    if not os.path.isdir(session_folder):
        print(f"Error: {session_folder} is not a valid directory")
        return
    
    plot_interesting_cases_over_time(session_folder)

if __name__ == "__main__":
    main()
