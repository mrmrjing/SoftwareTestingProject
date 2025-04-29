# Plot number of interesting test cases and unique crashes as bar charts, the x-axis is the session number for 5 sessions  

import os
import json
import matplotlib.pyplot as plt
import argparse
import glob
import re

def count_interesting_cases(session_folder):
    """Count the number of interesting test cases in a session"""
    interesting_path = os.path.join(session_folder, "interesting.json")
    if not os.path.exists(interesting_path):
        return 0
    
    with open(interesting_path, 'r') as f:
        interesting_data = json.load(f)
    
    # Subtract 1 for the initial timestamp at index 0
    return max(0, len(interesting_data) - 1)

def count_unique_crashes(session_folder):
    """Count the number of unique crashes in a session"""
    # First try to get count from bug_summary.txt
    bug_summary_path = os.path.join(session_folder, "bug_summary.txt")
    if os.path.exists(bug_summary_path):
        with open(bug_summary_path, 'r') as f:
            content = f.read()
            bug_ids = re.findall(r'BUG-\d+', content)
            if bug_ids:
                return len(set(bug_ids))
    
    # If bug_summary.txt doesn't exist or doesn't contain bug IDs,
    # try to count from failureQ.json
    failureq_path = os.path.join(session_folder, "failureQ.json")
    if os.path.exists(failureq_path):
        with open(failureq_path, 'r') as f:
            failureq_data = json.load(f)
        
        unique_bugs = set()
        for path in failureq_data:
            for method in failureq_data[path]:
                for status in failureq_data[path][method]:
                    for failure in failureq_data[path][method][status]:
                        if "bug_id" in failure:
                            unique_bugs.add(failure["bug_id"])
        
        return len(unique_bugs)
    
    # If neither file exists, try failure.json as a last resort
    failure_path = os.path.join(session_folder, "failure.json")
    if os.path.exists(failure_path):
        with open(failure_path, 'r') as f:
            failure_data = json.load(f)
        
        # Each key in failure.json represents a unique failure type
        return len(failure_data)
    
    return 0

def plot_results(session_folders):
    """
    Generate bar charts for interesting test cases and unique crashes
    
    Args:
        session_folders: List of paths to session folders
    """
    if not session_folders:
        print("No session folders to analyze")
        return
    
    # Count interesting cases and unique crashes for each session
    interesting_counts = []
    crash_counts = []
    session_labels = []
    
    for i, folder in enumerate(session_folders):
        session_name = os.path.basename(folder)
        session_labels.append(f"Run {i+1}\n({session_name})")
        
        interesting_count = count_interesting_cases(folder)
        interesting_counts.append(interesting_count)
        
        crash_count = count_unique_crashes(folder)
        crash_counts.append(crash_count)
        
        print(f"Session {session_name}: {interesting_count} interesting cases, {crash_count} unique crashes")
    
    # Create the plots
    plt.figure(figsize=(12, 10))
    
    # Plot interesting test cases
    plt.subplot(2, 1, 1)
    bars = plt.bar(session_labels, interesting_counts, color='blue', alpha=0.7)
    plt.title('Number of Interesting Test Cases per Run', fontsize=14)
    plt.ylabel('Count', fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Add count labels on top of bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                f'{height}', ha='center', va='bottom')
    
    # Plot unique crashes
    plt.subplot(2, 1, 2)
    bars = plt.bar(session_labels, crash_counts, color='red', alpha=0.7)
    plt.title('Number of Unique Crashes per Run', fontsize=14)
    plt.ylabel('Count', fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Add count labels on top of bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                f'{height}', ha='center', va='bottom')
    
    plt.tight_layout()
    
    # Save the plot
    output_path = "fuzzer_performance_comparison.png"
    plt.savefig(output_path)
    print(f"Plot saved to {output_path}")
    
    # Show the plot
    plt.show()

def main():
    parser = argparse.ArgumentParser(description='Plot fuzzer results from existing session folders')
    parser.add_argument('--sessions', type=str, nargs='+', help='Specific session folders to analyze')
    parser.add_argument('--num-sessions', type=int, default=5, help='Number of recent sessions to analyze if specific sessions not provided')
    parser.add_argument('--sessions-dir', type=str, default=os.path.join("sessions"), help='Directory containing session folders')
    args = parser.parse_args()
    
    if args.sessions:
        # Use the specified session folders
        session_folders = args.sessions
    else:
        # Find the most recent session folders
        session_pattern = os.path.join(args.sessions_dir, "session*")
        all_sessions = glob.glob(session_pattern)
        
        if not all_sessions:
            print(f"No session folders found in {args.sessions_dir}")
            return
        
        # Sort by session number (assuming format "session N")
        def get_session_number(path):
            match = re.search(r'session\s*(\d+)', os.path.basename(path))
            return int(match.group(1)) if match else 0
        
        session_folders = sorted(all_sessions, key=get_session_number)
        
        # Take the specified number of sessions
        session_folders = session_folders[:args.num_sessions]
    
    print(f"Analyzing {len(session_folders)} session folders:")
    for folder in session_folders:
        print(f"  - {folder}")
    
    # Plot the results
    plot_results(session_folders)

if __name__ == "__main__":
    main()