# Plot a table of that tabulates these three timings (time to first crash, average time to generate a test)
# Usage: python plot_table_2_1.py sessions/"session 10" sessions/"session 11" 
import json
import os
import datetime
import argparse
import pandas as pd
from tabulate import tabulate

def parse_datetime(dt_str):
    """Parse ISO format datetime string to datetime object"""
    try:
        return datetime.datetime.fromisoformat(dt_str)
    except (ValueError, TypeError):
        return None

def calculate_efficiency_metrics(session_folder):
    """
    Calculate the key efficiency metrics:
    - Time to first crash/bug
    - Average time to generate a test
    
    Args:
        session_folder: Path to the session folder
    
    Returns:
        Dictionary with the calculated metrics
    """
    metrics = {}
    
    # Load the necessary files
    tests_path = os.path.join(session_folder, "tests.json")
    failure_path = os.path.join(session_folder, "failure.json")
    failureq_path = os.path.join(session_folder, "failureQ.json")
    
    if not os.path.exists(tests_path):
        print(f"Error: tests.json not found in {session_folder}")
        return metrics
    
    # Load test timestamps
    with open(tests_path, 'r') as f:
        tests_data = json.load(f)
    
    # Extract and parse test timestamps
    test_timestamps = []
    for test_id, timestamp in tests_data.items():
        if test_id != "0":  # Skip the initial timestamp
            dt = parse_datetime(timestamp)
            if dt:
                test_timestamps.append(dt)
    
    if not test_timestamps:
        print(f"Warning: No valid test timestamps in {session_folder}")
        return metrics
    
    # Sort timestamps
    test_timestamps.sort()
    
    # Get the session start time (from test ID 0 or the first test)
    if "0" in tests_data:
        session_start = parse_datetime(tests_data["0"])
    else:
        session_start = min(test_timestamps)
    
    session_end = max(test_timestamps)
    session_duration = (session_end - session_start).total_seconds()
    
    # Total number of tests
    total_tests = len(test_timestamps)
    
    # Average time to generate a test (total time / number of tests)
    if total_tests > 0 and session_duration > 0:
        avg_time_per_test = session_duration / total_tests
        metrics["avg_time_per_test"] = avg_time_per_test
    
    # Time to first crash - try failureQ.json first for more accurate data
    if os.path.exists(failureq_path):
        try:
            with open(failureq_path, 'r') as f:
                failureq_data = json.load(f)
            
            # Extract timestamps from all failures
            crash_timestamps = []
            for path in failureq_data:
                for method in failureq_data[path]:
                    for status in failureq_data[path][method]:
                        for failure in failureq_data[path][method][status]:
                            if "timestamp" in failure:
                                dt = parse_datetime(failure["timestamp"])
                                if dt:
                                    crash_timestamps.append(dt)
            
            if crash_timestamps:
                crash_timestamps.sort()
                first_crash = min(crash_timestamps)
                time_to_first_crash = (first_crash - session_start).total_seconds()
                if time_to_first_crash > 0:  # Ensure it's positive
                    metrics["time_to_first_crash"] = time_to_first_crash
        except Exception as e:
            print(f"Error processing failureQ.json: {e}")
    
    # If we couldn't get time to first crash from failureQ.json, try failure.json
    if "time_to_first_crash" not in metrics and os.path.exists(failure_path):
        try:
            with open(failure_path, 'r') as f:
                failure_data = json.load(f)
            
            failure_timestamps = []
            for _, entry in failure_data.items():
                if isinstance(entry, str):
                    dt = parse_datetime(entry)
                    if dt:
                        failure_timestamps.append(dt)
                elif isinstance(entry, dict) and "timestamp" in entry:
                    dt = parse_datetime(entry["timestamp"])
                    if dt:
                        failure_timestamps.append(dt)
            
            if failure_timestamps:
                failure_timestamps.sort()
                first_failure = min(failure_timestamps)
                time_to_first_crash = (first_failure - session_start).total_seconds()
                if time_to_first_crash > 0:  # Ensure it's positive
                    metrics["time_to_first_crash"] = time_to_first_crash
        except Exception as e:
            print(f"Error processing failure.json: {e}")
    
    return metrics

def main():
    parser = argparse.ArgumentParser(description='Calculate and tabulate fuzzer efficiency metrics')
    parser.add_argument('session_folders', type=str, nargs='+', help='Paths to session folders')
    parser.add_argument('--output', type=str, help='Output CSV file path (optional)')
    args = parser.parse_args()
    
    all_metrics = []
    
    for i, session_folder in enumerate(args.session_folders):
        print(f"Analyzing session {i+1}: {session_folder}")
        
        metrics = calculate_efficiency_metrics(session_folder)
        if metrics:
            metrics["run"] = i + 1
            metrics["session"] = os.path.basename(session_folder)
            all_metrics.append(metrics)
    
    if not all_metrics:
        print("No valid metrics could be calculated from the provided sessions.")
        return
    
    # Create DataFrame for easy manipulation
    df = pd.DataFrame(all_metrics)
    
    # Reorder columns
    columns = ["run", "session", "time_to_first_crash", "avg_time_per_test"]
    df = df.reindex(columns=[c for c in columns if c in df.columns])
    
    # Calculate averages
    avg_row = df.mean(numeric_only=True)
    avg_dict = avg_row.to_dict()
    avg_dict["run"] = "Average"
    avg_dict["session"] = "-"
    
    # Add average row to DataFrame
    df = pd.concat([df, pd.DataFrame([avg_dict])], ignore_index=True)
    
    # Format the table
    formatted_df = df.copy()
    
    # Format time values to be more readable
    for col in ["time_to_first_crash", "avg_time_per_test"]:
        if col in formatted_df.columns:
            # Convert to milliseconds for small values
            formatted_df[col] = formatted_df[col].apply(
                lambda x: f"{x*1000:.2f} ms" if isinstance(x, (int, float)) and x < 0.1 else
                          f"{x:.4f} s" if isinstance(x, (int, float)) else "N/A"
            )
    
    # Rename columns for display
    column_names = {
        "run": "Run",
        "session": "Session",
        "time_to_first_crash": "Time to First Crash",
        "avg_time_per_test": "Avg Time to Generate Test"
    }
    formatted_df = formatted_df.rename(columns=column_names)
    
    # Print the table
    print("\nTable 2.1: Fuzzer Efficiency Metrics\n")
    print(tabulate(formatted_df, headers="keys", tablefmt="grid", showindex=False))
    
    # Save to CSV if output path is provided
    if args.output:
        df.to_csv(args.output, index=False)
        print(f"\nMetrics saved to {args.output}")

if __name__ == "__main__":
    main()
