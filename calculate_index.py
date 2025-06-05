import re
import os
import math
from collections import Counter

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

def parse_clustering(filename):
    clusters = {}
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            m = re.match(r"Cluster\s*(\d+):\s*(.*)", line)
            if m:
                cluster_num = int(m.group(1))
                switches_str = m.group(2)
                switches = [int(s.strip()[1:]) 
                            for s in switches_str.split(',') 
                            if s.strip().startswith('s')]
                clusters[cluster_num] = switches
    return clusters

def parse_switch_degrees(filename):
    switch_degrees = {}
    with open(filename, 'r') as f:
        for line in f:
            matches = re.findall(r"(s\d+)-eth\d+", line)
            for switch in matches:
                sid = int(switch[1:])
                switch_degrees[sid] = switch_degrees.get(sid, 0) + 1
    return switch_degrees

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
    return sum((r - mu)**2 for r in ratios) / len(ratios)

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

def compute_relative_cluster_spike_index(cluster_flows_by_switch, key):
    """
    Calculates spike index using only cluster-specific flows_by_switch and a given key.
    """
    counter = Counter()
    for flows in cluster_flows_by_switch.values():
        for flow in flows:
            counter[flow.get(key, 0)] += 1
    if not counter:
        return 0.0
    freqs = list(counter.values())
    mean = sum(freqs) / len(freqs)
    return max(max(freqs) - mean, mean - min(freqs))

def compute_PPR(packet_stats):
    total_in  = sum(s['packet_in']  for s in packet_stats.values())
    total_out = sum(s['packet_out'] for s in packet_stats.values())
    return (total_out / total_in) if total_in > 0 else 0.0

def compute_PPD(packet_stats):
    total_in  = sum(s['packet_in']  for s in packet_stats.values())
    total_out = sum(s['packet_out'] for s in packet_stats.values())
    if total_in > 0 and total_out > total_in:
        return (total_out - total_in) / total_in
    return 0.0

def process_directory(target_dir, switch_degrees):
    flows_by_switch = parse_flow_table(os.path.join(target_dir, "flow_table.txt"))
    packet_stats    = parse_packet_in_out(os.path.join(target_dir, "packet_in_out.txt"))
    clusters        = parse_clustering("final_clustering.txt")

    output = []
    # Overall indices
    output.append("Overall Indices:")
    output.append(f"  SPI : {compute_SPI(flows_by_switch, switch_degrees):.4f}")
    output.append(f"  PFSI: {compute_frequency_spike_index(flows_by_switch, 'priority'):.2f}")
    output.append(f"  TFSI: {compute_frequency_spike_index(flows_by_switch, 'idle_timeout'):.2f}")
    output.append(f"  PPR : {compute_PPR(packet_stats):.2f}")
    output.append(f"  PPD : {compute_PPD(packet_stats):.2f}\n")

    # Per-cluster indices
    for cid, sw_list in clusters.items():
        # Cluster-specific data
        cluster_flows        = {sw: flows_by_switch.get(sw, []) for sw in sw_list}
        cluster_packet_stats = {sw: packet_stats.get(sw, {'packet_in':0,'packet_out':0}) for sw in sw_list}

        spi   = compute_SPI(cluster_flows, switch_degrees)
        ps    = compute_relative_cluster_spike_index(cluster_flows, 'priority')
        ts    = compute_relative_cluster_spike_index(cluster_flows, 'idle_timeout')
        ppr   = compute_PPR(cluster_packet_stats)
        ppd   = compute_PPD(cluster_packet_stats)

        output.append(f"Cluster {cid} Indices:")
        output.append(f"  SPI : {spi:.4f}")
        output.append(f"  PFSI: {ps:.2f}")
        output.append(f"  TFSI: {ts:.2f}")
        output.append(f"  PPR : {ppr:.2f}")
        output.append(f"  PPD : {ppd:.2f}\n")

    # Save result
    out_file = os.path.join(target_dir, "calculate_index.txt")
    with open(out_file, "w") as f:
        f.write("\n".join(output))
    print(f"Calculated indices saved to {out_file}")

def main():
    base_path = "./data"
    if not os.path.isdir(base_path):
        print("No data directory found.")
        return
    if not os.path.exists("links.txt"):
        print("links.txt file does not exist.")
        return

    switch_degrees = parse_switch_degrees("links.txt")

    for entry in os.listdir(base_path):
        n_path = os.path.join(base_path, entry)
        if not os.path.isdir(n_path):
            continue
        for sub in ["normal", "compromised"]:
            sub_dir = os.path.join(n_path, sub)
            if os.path.isdir(sub_dir):
                req = ["flow_table.txt", "packet_in_out.txt"]
                if all(os.path.exists(os.path.join(sub_dir, fn)) for fn in req):
                    process_directory(sub_dir, switch_degrees)
                else:
                    print(f"Skipping {sub_dir}: missing required files.")

if __name__ == "__main__":
    main()

