import os
import re
import time
import psutil
from collections import defaultdict
from itertools import combinations
from scipy.stats import wasserstein_distance

def parse_cluster_indices(filepath):
    clusters = {}
    current_cluster = None
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            header_match = re.match(r"Cluster (\d+) Indices:", line)
            if header_match:
                current_cluster = int(header_match.group(1))
                clusters[current_cluster] = defaultdict(list)
                continue
            if current_cluster is not None:
                m = re.match(r"([A-Z]+)\s*:\s*([\d\.]+)", line)
                if m:
                    metric = m.group(1)
                    value = float(m.group(2))
                    clusters[current_cluster][metric].append(value)
    return clusters

def max_pairwise_distance_among_clusters(cluster_dict, key):
    distributions = [
        cluster_dict[cid].get(key, [])
        for cid in sorted(cluster_dict.keys())
        if cluster_dict[cid].get(key)
    ]
    if len(distributions) < 2:
        return 0.0
    pairwise = [
        wasserstein_distance(dist1, dist2)
        for dist1, dist2 in combinations(distributions, 2)
    ]
    return max(pairwise) if pairwise else 0.0

def compute_mpd_from_calcfile(calc_file):
    cluster_vals = parse_cluster_indices(calc_file)
    metrics = ["SPI", "PFSI", "TFSI", "PPR", "PPD"]
    for metric in metrics:
        _ = max_pairwise_distance_among_clusters(cluster_vals, metric)

def measure_resources(func, *args, **kwargs):
    process = psutil.Process(os.getpid())
    cpu_before = process.cpu_times()
    mem_before = process.memory_info().rss / (1024 * 1024)  # MB

    start_time = time.perf_counter()
    func(*args, **kwargs)
    end_time = time.perf_counter()

    cpu_after = process.cpu_times()
    mem_after = process.memory_info().rss / (1024 * 1024)

    elapsed = end_time - start_time
    cpu_used = (cpu_after.user + cpu_after.system) - (cpu_before.user + cpu_before.system)
    cpu_percent = (cpu_used / elapsed) * 100 if elapsed > 0 else 0.0

    return elapsed, cpu_percent, mem_after

def main():
    base_path = "4kdata"
    count = 0
    total_time = 0.0
    total_cpu = 0.0
    total_mem = 0.0

    for exp_id in sorted(os.listdir(base_path), key=lambda x: int(x) if x.isdigit() else float('inf')):
        for label in ["normal", "compromised"]:
            calc_file = os.path.join(base_path, exp_id, label, "calculate_index.txt")
            if not os.path.exists(calc_file):
                continue
            try:
                elapsed, cpu, mem = measure_resources(compute_mpd_from_calcfile, calc_file)
                print(f"{calc_file}: {elapsed:.4f}s, CPU {cpu:.2f}%, Memory {mem:.2f}MB")
                count += 1
                total_time += elapsed
                total_cpu += cpu
                total_mem += mem
            except Exception as e:
                print(f"Failed to process {calc_file}: {e}")

    if count > 0:
        print("\nAverage resource usage:")
        print(f"  Average runtime   : {total_time / count:.4f} sec")
        print(f"  Average CPU usage : {total_cpu / count:.2f}%")
        print(f"  Average memory    : {total_mem / count:.2f} MB")
    else:
        print("No valid files found.")

if __name__ == "__main__":
    main()

