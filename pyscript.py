import os
import shutil
import subprocess

# Number of times to repeat execution (set as desired)
REPEAT_COUNT = 10

def get_next_run_number(data_root='data'):
    run = 1
    while os.path.exists(os.path.join(data_root, str(run))):
        run += 1
    return run

def move_run_results(run_number):
    """
    Move the result folders (data/normal, data/compromised) created by simulation.py
    into data/{run_number}/normal and data/{run_number}/compromised respectively.
    """
    labels = ['normal', 'compromised']
    for label in labels:
        src_dir = os.path.join("data", label)
        dest_dir = os.path.join("data", str(run_number), label)
        os.makedirs(os.path.dirname(dest_dir), exist_ok=True)
        if os.path.exists(src_dir):
            shutil.move(src_dir, dest_dir)
            print(f"📂 moved {src_dir} → {dest_dir}")
        else:
            print(f"⚠️ {src_dir} does not exist (skipped)")

def run_main_script():
    """
    Execute simulation.py.
    After execution, simulation.py should save results into data/normal and data/compromised.
    """
    try:
        subprocess.check_call(['python3', 'simulation.py'])
    except subprocess.CalledProcessError as e:
        print("❌ Error during simulation.py execution:", e)

def run_multiple_times(repeat_count):
    start_run = get_next_run_number()
    for i in range(repeat_count):
        current_run = start_run + i
        print(f"\n🔁 Run #{current_run} starting... (normal & compromised)")
        run_main_script()
        move_run_results(current_run)
        print(f"🏁 Run #{current_run} completed!")

if __name__ == '__main__':
    run_multiple_times(REPEAT_COUNT)

