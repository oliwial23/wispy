import time
import json
import subprocess
import os
import glob
from datetime import datetime
import nbformat
from nbconvert.preprocessors import ExecutePreprocessor
import shutil

OUTPUT_FILE = "timing_log.json"
NUM_ITERATIONS = 100
GROUP_ID = "VON5o2iTrMfkbvxB/ynpTJjU8TvAQd0Dq6oGG6PzCXc="

# Clear all existing experiment files
def clean_previous_results():
    folders = ['json_files/1', 'json_files/2', 'json_files/3']
    for folder in folders:
        if os.path.exists(folder):
            for file in os.listdir(folder):
                file_path = os.path.join(folder, file)
                try:
                    os.remove(file_path)
                except Exception as e:
                    print(f"❌ Failed to delete {file_path}: {e}")
        else:
            os.makedirs(folder, exist_ok=True)

    # Optional: clear overall experiment log
    if os.path.exists(OUTPUT_FILE):
        try:
            os.remove(OUTPUT_FILE)
        except Exception as e:
            print(f"❌ Failed to delete {OUTPUT_FILE}: {e}")

    print("🧹 Cleaned all previous timing files.")

# Run cleanup first
clean_previous_results()

for subdir in ['json_files/1', 'json_files/2', 'json_files/3']:
    os.makedirs(subdir, exist_ok=True)

with open("json_files/3/start_time.json", "w") as f:
    f.write('{}')

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

def get_timing_log(path):
    return os.path.exists(os.path.join(path, "timings.jsonl"))

def assert_all_timings_written():
    if not all([
        get_timing_log("json_files/1"),
        get_timing_log("json_files/2"),
        get_timing_log("json_files/3")
    ]):
        raise RuntimeError("❌ Missing one or more timing files!")
    print("✅ All timing files written correctly.")


def run_notebook(path):
    print("📊 Running analysis notebook...")
    with open(path) as f:
        nb = nbformat.read(f, as_version=4)
    ep = ExecutePreprocessor(timeout=600, kernel_name='python3')
    ep.preprocess(nb, {'metadata': {'path': './'}})
    print("✅ Notebook executed: experiment_analysis.ipynb")

# 1. Optional join first
join_command = ["cargo", "run", "--bin", "client", "join"]
print("🧪 Running join command...")
run_command(join_command)

# 2. Run post 100 times
for i in range(1, NUM_ITERATIONS + 1):
    message = f"Message: {i}"
    post_command = [
        "cargo", "run", "--bin", "client", "post",
        "-m", message,
        "-g", GROUP_ID
    ]

    print(f"📨 Iteration {i}: Sending post...")
    post_duration, post_success, post_error = run_command(post_command)

    try:
        assert_all_timings_written()
    except RuntimeError as e:
        print(f"⚠️ Iteration {i} error: {e}")

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

    append_log(log_entry)
    print(f"✅ Iteration {i} complete.")

# 3. Analyze results
run_notebook("experiment_analysis.ipynb")

