import json
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from datetime import datetime

def load_coverage_data(filename="coverage_data.json"):
    try:
        with open(filename, "r") as f:
            data = json.load(f)
        return data
    except Exception as e:
        print(f"Error loading {filename}: {e}")
        return {}

# Calculates the number of lines covered in a single request 
def compute_coverage_metric(coverage_entry):
    """Compute a simple metric such as the total number of covered lines."""
    file_coverage = coverage_entry.get("coverage", {})
    total_lines = sum(len(lines) for lines in file_coverage.values())
    return total_lines

def get_time_series(coverage_data):
    data_points = []
    for entry in coverage_data.values():
        timestamp = entry.get("timestamp")
        if timestamp:
            metric = compute_coverage_metric(entry)
            data_points.append((timestamp, metric))
    data_points.sort(key=lambda x: x[0])
    return data_points

# Create a figure for live plotting
fig, ax = plt.subplots(figsize=(10, 6))

def animate(frame):
    coverage_data = load_coverage_data("DjangoWebApplication/coverage_data.json")
    data_points = get_time_series(coverage_data)
    
    if data_points:
        times, coverage = zip(*data_points)
        times_dt = [datetime.fromtimestamp(t) for t in times]
    else:
        times_dt, coverage = [], []
    
    ax.clear()
    ax.plot(times_dt, coverage, marker='o')
    ax.set_xlabel("Time")
    ax.set_ylabel("Total Covered Lines")
    ax.set_title("Live Coverage Evolution Over Time")
    ax.grid(True)
    plt.tight_layout()

# Set up the animation to update every 5 seconds
ani = FuncAnimation(fig, animate, interval=5000)
plt.show()


