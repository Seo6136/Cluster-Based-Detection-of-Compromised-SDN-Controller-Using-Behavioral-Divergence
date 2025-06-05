import psutil
import time
import os
import re
from collections import Counter

# -------------------- Data Parsing --------------------

def parse_flow_table(filename):
    flows_by_switch = {}
    current_switch = None
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith("Switch"):
                m = re.match(r"Switch:\s*s(\d+)", line)
                if m:
                    current_switch = int(m.group(1))
                    flows_by_switch[current_switch] = []
            elif line and current_switch is not None:
                if "actions=" in line:
                    kv_part, actions_part = line.split("actions=", 1)
                    actions = [actions_part.strip()]
                else:
                    kv_part = line
                    actions = []
                flow = {}
                tokens = kv_part.split(",")
                for token in tokens:
                    token = token.strip()
                    if "=" in token:
                        key, value = token.split("=", 1)
                        key = key.strip()
                        value = value.strip()
                        if value.isdigit():
                            value = int(value)
                        flow[key] = value
                    else:
                        flow[token] = token
                flow['actions'] = actions
                flows_by_switch[current_switch].append(flow)
    return flows_by_switch

def parse_packet_in_out(filename):
    stats = {}
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            m = re.match(r"s(\d+)\s+packet_in:\s*(\d+),\s*packet_out:\s*(\d+)", line, re.IGNORECASE)
            if m:
                switch = int(m.group(1))
                packet_in = int(m.group(2))
                packet_out = int(m.group(3))
                stats[switch] = {'packet_in': packet_in, 'packet_out': packet_out}
    return stats

def parse_switch_degrees(filename):
    switch_degrees = {}
    with open(filename, 'r') as f:
        for line in f:
            matches = re.findall(r"(s\d+)-eth\d+", line)
            for switch in matches:
                sid = int(switch[1:])
                switch_degrees[sid] = switch_degrees.get(sid, 0) + 1
    return switch_degrees

# -------------------- Metric Computation --------------------

def compute_SPI(flows_by_switch, switch_degrees):
    xs = {sw: len(flows) for sw, flows in flows_by_switch.items()}
    ds = switch_degrees.copy()
    common = set(xs) & set(ds)
    if not common:
        return 0.0

    total_x = sum(xs[sw] for sw in common)
    total_d = sum(ds[sw] for sw in common)
    if total_x == 0 or total_d == 0:
        return 0.0

    ratios = []
    for sw in common:
        normalized_x = xs[sw] / total_x
        normalized_d = ds[sw] / total_d
        if normalized_d > 0:
            ratios.append(normalized_x / normalized_d)

    if not ratios:
        return 0.0

    mu = sum(ratios) / len(ratios)
    return sum((r - mu) ** 2 for r in ratios) / len(ratios)

def compute_frequency_spike_index(flows_by_switch, key):
    counter = Counter()
    for flows in flows_by_switch.values():
        for flow in flows:
            counter[flow.get(key, 0)] += 1
    if not counter:
        return 0.0
    freqs = list(counter.values())
    mean = sum(freqs) / len(freqs)
    return max(max(freqs) - mean, mean - min(freqs))

def compute_PPR(packet_stats):
    total_in = sum(s['packet_in'] for s in packet_stats.values())
    total_out = sum(s['packet_out'] for s in packet_stats.values())
    return (total_out / total_in) if total_in > 0 else 0.0

def compute_PPD(packet_stats):
    total_in = sum(s['packet_in'] for s in packet_stats.values())
    total_out = sum(s['packet_out'] for s in packet_stats.values())
    if total_in > 0 and total_out > total_in:
        return (total_out - total_in) / total_in
    return 0.0

# -------------------- Measurement Function --------------------

def compute_overall_only(target_dir, switch_degrees):
    flows_by_switch = parse_flow_table(os.path.join(target_dir, "flow_table.txt"))
    packet_stats = parse_packet_in_out(os.path.join(target_dir, "packet_in_out.txt"))
    _ = compute_SPI(flows_by_switch, switch_degrees)
    _ = compute_frequency_spike_index(flows_by_switch, 'priority')
    _ = compute_frequency_spike_index(flows_by_switch, 'idle_timeout')
    _ = compute_PPR(packet_stats)
    _ = compute_PPD(packet_stats)

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

# -------------------- Main Loop --------------------

def main():
    base_path = "10kdata"
    links_path = "links.txt"

    if not os.path.exists(links_path):
        print("❗ links.txt file not found.")
        return

    switch_degrees = parse_switch_degrees(links_path)

    total_time = 0.0
    total_cpu = 0.0
    total_mem = 0.0
    count = 0

    for subdir in os.listdir(base_path):
        full_subdir = os.path.join(base_path, subdir)
        if not os.path.isdir(full_subdir):
            continue
        for mode in ["normal", "compromised"]:
            target_dir = os.path.join(full_subdir, mode)
            if not os.path.isdir(target_dir):
                continue
            required = ["flow_table.txt", "packet_in_out.txt"]
            if not all(os.path.exists(os.path.join(target_dir, f)) for f in required):
                print(f"❌ {target_dir}: missing required files")
                continue
            try:
                elapsed, cpu, mem = measure_resources(compute_overall_only, target_dir, switch_degrees)
                print(f"✅ {target_dir}: {elapsed:.4f}s, {cpu:.2f}%, {mem:.2f}MB")
                total_time += elapsed
                total_cpu += cpu
                total_mem += mem
                count += 1
            except Exception as e:
                print(f"⚠️ Measurement failed for {target_dir}: {e}")

    if count == 0:
        print("❗ No valid targets found for measurement.")
        return

    print("\n📊 Overall average resource usage:")
    print(f"  Average runtime   : {total_time / count:.4f} sec")
    print(f"  Average CPU usage : {total_cpu / count:.2f}%")
    print(f"  Average memory    : {total_mem / count:.2f} MB")

if __name__ == "__main__":
    main()

