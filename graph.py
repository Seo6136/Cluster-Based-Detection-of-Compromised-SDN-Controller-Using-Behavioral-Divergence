import os
import re
import matplotlib.pyplot as plt
from itertools import combinations
from scipy.stats import wasserstein_distance

# Base directory and output directories
base_path = "./8kdata"
overall_output_dir = "./overall"
clusters_output_dir = "./clusters"

os.makedirs(overall_output_dir, exist_ok=True)
os.makedirs(clusters_output_dir, exist_ok=True)

# Regular expressions for each index (file format example: "  SPI : 0.3080")
index_patterns = {
    "SPI": {
        "overall": r"SPI\s*:\s*([0-9.]+)",
        "cluster": r"SPI\s*:\s*([0-9.]+)"
    },
    "PFSI": {
        "overall": r"PFSI\s*:\s*([0-9.]+)",
        "cluster": r"PFSI\s*:\s*([0-9.]+)"
    },
    "TFSI": {
        "overall": r"TFSI\s*:\s*([0-9.]+)",
        "cluster": r"TFSI\s*:\s*([0-9.]+)"
    },
    "PPR": {
        "overall": r"PPR\s*:\s*([0-9.]+)",
        "cluster": r"PPR\s*:\s*([0-9.]+)"
    },
    "PPD": {
        "overall": r"PPD\s*:\s*([0-9.]+)",
        "cluster": r"PPD\s*:\s*([0-9.]+)"
    }
}

# Data storage dictionaries
overall_data = {key: {"normal": [], "compromised": []} for key in index_patterns}
cluster_maxwd_data = {key: {"normal": [], "compromised": []} for key in index_patterns}

def extract_overall_indices(file_path):
    with open(file_path, "r") as f:
        content = f.read()
    # Split off cluster sections; take only the part before the first "Cluster N Indices:"
    overall_section = re.split(r"Cluster \d+ Indices:", content)[0]
    extracted = {}
    for key in index_patterns:
        match = re.search(index_patterns[key]["overall"], overall_section)
        extracted[key] = float(match.group(1)) if match else None
    return extracted

def extract_all_cluster_indices(file_path):
    with open(file_path, "r") as f:
        content = f.read()
    # Split into parts where cluster sections start
    parts = re.split(r"(Cluster \d+ Indices:)", content)
    clusters = {}
    for i in range(1, len(parts), 2):
        header = parts[i]
        match = re.search(r"Cluster (\d+)", header)
        if not match:
            continue
        cluster_id = int(match.group(1))
        section = parts[i + 1]
        extracted = {}
        for key in index_patterns:
            m = re.search(index_patterns[key]["cluster"], section)
            extracted[key] = float(m.group(1)) if m else None
        clusters[cluster_id] = extracted
    return clusters

def max_wasserstein_distance_among_clusters(cluster_dict, key):
    values = [v[key] for v in cluster_dict.values() if v[key] is not None]
    # Compute pairwise Wasserstein distances between single-value distributions
    pairwise_distances = [
        wasserstein_distance([a], [b])
        for a, b in combinations(values, 2)
    ]
    return max(pairwise_distances) if pairwise_distances else 0

# Iterate through experiment directories
i = 1
while True:
    normal_path = os.path.join(base_path, str(i), "normal", "calculate_index.txt")
    compromised_path = os.path.join(base_path, str(i), "compromised", "calculate_index.txt")
    if not os.path.exists(normal_path) or not os.path.exists(compromised_path):
        break

    normal_overall = extract_overall_indices(normal_path)
    compromised_overall = extract_overall_indices(compromised_path)
    for key in index_patterns:
        overall_data[key]["normal"].append(normal_overall[key])
        overall_data[key]["compromised"].append(compromised_overall[key])

    normal_clusters = extract_all_cluster_indices(normal_path)
    compromised_clusters = extract_all_cluster_indices(compromised_path)
    for key in index_patterns:
        maxwd_normal = max_wasserstein_distance_among_clusters(normal_clusters, key)
        maxwd_compromised = max_wasserstein_distance_among_clusters(compromised_clusters, key)
        cluster_maxwd_data[key]["normal"].append(maxwd_normal)
        cluster_maxwd_data[key]["compromised"].append(maxwd_compromised)
    i += 1

exp_ids = list(range(1, i))

def setup_plot(title, xlabel, ylabel):
    plt.title(title, fontsize=14, fontweight='bold')
    plt.xlabel(xlabel, fontsize=12)
    plt.ylabel(ylabel, fontsize=12)
    plt.xticks(fontsize=10)
    plt.yticks(fontsize=10)
    plt.grid(True, linestyle='--', linewidth=0.5, alpha=0.7)
    plt.legend(loc='upper left', fontsize=10, frameon=False)
    plt.tight_layout()

# Plot Overall indices for each metric
for key in index_patterns:
    plt.figure(figsize=(6, 4))
    plt.scatter(
        exp_ids,
        overall_data[key]["normal"],
        marker='o',
        facecolors='none',
        edgecolors='blue',
        s=50,
        label="Normal"
    )
    plt.scatter(
        exp_ids,
        overall_data[key]["compromised"],
        marker='s',
        facecolors='none',
        edgecolors='red',
        s=50,
        label="Compromised"
    )
    setup_plot(
        f"Overall {key} across Experiments",
        "Experiment Number",
        f"{key} Value"
    )
    plt.savefig(
        os.path.join(overall_output_dir, f"{key}_overall.png"),
        dpi=300,
        bbox_inches='tight'
    )
    plt.close()

# Plot maximum pairwise distance among clusters for each metric
for key in index_patterns:
    plt.figure(figsize=(6, 4))
    plt.scatter(
        exp_ids,
        cluster_maxwd_data[key]["normal"],
        marker='o',
        facecolors='none',
        edgecolors='blue',
        s=50,
        label="Normal Clusters"
    )
    plt.scatter(
        exp_ids,
        cluster_maxwd_data[key]["compromised"],
        marker='s',
        facecolors='none',
        edgecolors='red',
        s=50,
        label="Compromised Clusters"
    )
    setup_plot(
        f"Max Pairwise Distance of {key} across Experiments",
        "Experiment Number",
        "Max Pairwise Distance"
    )
    plt.savefig(
        os.path.join(clusters_output_dir, f"{key}_cluster_maxpairwise.png"),
        dpi=300,
        bbox_inches='tight'
    )
    plt.close()

print(f"✅ Overall plots saved in '{overall_output_dir}/', cluster pairwise-distance plots saved in '{clusters_output_dir}/'")

