import time
import json
import subprocess
from datetime import datetime

'''
Running Experiments:
1. Setup as normal
2. In signal-cli run 'python script.py'
3. Run code in experiment_analysis.ipynb to get average duration

Code is appended into json_files/[insert experiment # here]/*.json
If one of your experiment runs fails or aborts: you may want to delete the extra entries in the .json file. 
I could not figure out a naming convention that got around this. 

Experiment Number:
1. client-side proof gen
2. server-side proof verification
3. server-side latency

'''

SCAN_COMMAND = ["cargo", "run", "--bin", "client", "scan"]
OUTPUT_FILE = "timing_log.json"
NUM_ITERATIONS = 100
GROUP_ID = "VON5o2iTrMfkbvxB/ynpTJjU8TvAQd0Dq6oGG6PzCXc="

def run_command(command):
    start = time.time()
    try:
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        return time.time() - start, False, e.stderr.decode()
    return time.time() - start, True, ""

def append_log(entry):
    try:
        with open(OUTPUT_FILE, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        data = []
    
    data.append(entry)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=2)

# client join

post_command = [
        "cargo", "run", "--bin", "client", "join"
    ]
post_duration, post_success, post_error = run_command(post_command)
for i in range(1, NUM_ITERATIONS + 1):
    message = f"Message: {i}"
    post_command = [
        "cargo", "run", "--bin", "client", "post", 
        "-m", message,
        "-g", GROUP_ID
    ]

    post_duration, post_success, post_error = run_command(post_command)
    log_entry = {
        "iteration": i,
        "timestamp": datetime.utcnow().isoformat(),
        "post": {
            "message": message,
            "duration_seconds": post_duration,
            "success": post_success,
            "error": post_error if not post_success else None
        }
    }

    # if i % 4 == 0:
    #     scan_duration, scan_success, scan_error = run_command(SCAN_COMMAND)
    #     log_entry["scan"] = {
    #         "duration_seconds": scan_duration,
    #         "success": scan_success,
    #         "error": scan_error if not scan_success else None
    #     }

    #     append_log(log_entry)
    #     print(f"Iteration {i} complete.")

print("All done. Timing info saved to timing_log.json.")
