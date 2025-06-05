#!/usr/bin/env python3
import os
import re
import csv
from collections import defaultdict
from itertools import combinations
from scipy.stats import wasserstein_distance

def parse_overall_indices(filepath):
    """
    Extract SPI, PFSI, TFSI, PPR, and PPD values from the Overall Indices section
    of calculate_index.txt. Stops reading when the 'Cluster' section appears.
    """
    overall = {}
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("Cluster"):
                break
            m = re.match(r"([A-Z]+)\s*:\s*([\d\.]+)", line)
            if m:
                overall[m.group(1)] = float(m.group(2))
    return overall

def parse_cluster_indices(filepath):
    """
    Collect SPI, PFSI, TFSI, PPR, and PPD values for each cluster from the
    Cluster N Indices sections of calculate_index.txt.

    If a cluster has multiple measurements (for example, multiple switches),
    all values are stored in a list. If only one value exists, the list length is 1.
    """
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
    """
    Compute the maximum Earth Mover's Distance (Wasserstein distance) between all
    pairs of distributions for a given metric across clusters.
    """
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

def main():
    data_dir = "10kdata"
    csv_dir = "csv"
    os.makedirs(csv_dir, exist_ok=True)

    overall_rows = []
    clusters_rows = []

    # Iterate through experiment folders (numeric names) in sorted order
    for exp_id in sorted(os.listdir(data_dir), key=lambda x: int(x) if x.isdigit() else x):
        exp_path = os.path.join(data_dir, exp_id)
        if not os.path.isdir(exp_path):
            continue

        for label in ("normal", "compromised"):
            calc_file = os.path.join(exp_path, label, "calculate_index.txt")
            if not os.path.exists(calc_file):
                print(f"❌ {calc_file} does not exist.")
                continue

            # Parse overall indices
            overall = parse_overall_indices(calc_file)
            row_overall = {"experiment": exp_id, "label": label}
            for metric in ("SPI", "PFSI", "TFSI", "PPR", "PPD"):
                row_overall[metric] = overall.get(metric)
            overall_rows.append(row_overall)

            # Parse cluster indices and compute maximum pairwise distance per metric
            cluster_vals = parse_cluster_indices(calc_file)
            row_cluster = {"experiment": exp_id, "label": label}
            for metric in ("SPI", "PFSI", "TFSI", "PPR", "PPD"):
                dist = max_pairwise_distance_among_clusters(cluster_vals, metric)
                row_cluster[f"{metric}_max_pairwise_distance"] = dist
            clusters_rows.append(row_cluster)

    # Create overall.csv
    overall_csv = os.path.join(csv_dir, "overall.csv")
    with open(overall_csv, "w", newline="") as f:
        fieldnames = ["experiment", "label", "SPI", "PFSI", "TFSI", "PPR", "PPD"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(overall_rows)
    print(f"✅ Saved overall.csv → {overall_csv}")

    # Create clusters.csv
    clusters_csv = os.path.join(csv_dir, "clusters.csv")
    with open(clusters_csv, "w", newline="") as f:
        fieldnames = [
            "experiment", "label",
            "SPI_max_pairwise_distance",
            "PFSI_max_pairwise_distance",
            "TFSI_max_pairwise_distance",
            "PPR_max_pairwise_distance",
            "PPD_max_pairwise_distance"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(clusters_rows)
    print(f"✅ Saved clusters.csv → {clusters_csv}")

if __name__ == "__main__":
    main()

