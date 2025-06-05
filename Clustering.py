#!/usr/bin/env python3
import networkx as nx
import os
import math

# Functions for saving clustering logs
clustering_log = []
def log(message):
    print(message)
    clustering_log.append(message)

def write_clustering_sequence(output_file="clustering_sequence.txt"):
    with open(output_file, "w") as f:
        for message in clustering_log:
            f.write(message + "\n")
    print(f"Clustering sequence has been saved to {output_file}.")

def write_final_clustering(clusters, output_file="final_clustering.txt"):
    with open(output_file, "w") as f:
        for i, cluster in enumerate(clusters, start=1):
            nodes_str = ", ".join(sorted(cluster))
            f.write(f"Cluster{i}: {nodes_str}\n")
    print(f"Final clustering results have been saved to {output_file}.")

def build_switch_graph_from_nodes_links(nodes_file="nodes.txt", links_file="links.txt"):
    """
    Reads all nodes from nodes.txt and extracts only switch (s*) nodes.
    Parses connections between switches from links.txt and builds a NetworkX graph.
    """
    G = nx.Graph()
    # Read all nodes and select only switches
    with open(nodes_file, "r") as f:
        all_nodes = [line.strip() for line in f.readlines()]
    switches = [node for node in all_nodes if node.startswith("s")]
    G.add_nodes_from(switches)
    log(f"Added {len(switches)} switch nodes from nodes.txt.")

    # Read link info and add edges only if both nodes are switches
    with open(links_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or "<->" not in line:
                continue
            left, right = line.split("<->")
            node1 = left.split("-")[0]
            node2 = right.split("-")[0]
            if node1.startswith("s") and node2.startswith("s"):
                G.add_edge(node1, node2)
    log(f"Graph constructed: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G

def identify_core_switches(G, core_ratio=0.2):
    """
    Dynamically identifies top core_ratio (e.g., 20%) switches using closeness centrality.
    """
    centrality = nx.closeness_centrality(G)
    total_nodes = len(G.nodes())
    core_count = max(1, int(round(total_nodes * core_ratio)))
    sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
    core_nodes = [node for node, c in sorted_nodes[:core_count]]
    log(f"Automatically selected Core switches: {core_nodes} (top {core_count} of {total_nodes})")
    return set(core_nodes)

def extract_pod_clusters(G, core_nodes):
    """
    Removes Core switches and extracts connected components of the remaining switches as Pod clusters.
    """
    G_filtered = G.copy()
    G_filtered.remove_nodes_from(core_nodes)
    pods = list(nx.connected_components(G_filtered))
    log(f"Found {len(pods)} Pod clusters after removing Core switches")
    return pods

def split_clusters_with_core(G, pod_clusters, core_nodes):
    """
    Combines Pod clusters and Core switches into final clustering results.
    """
    final_clusters = list(pod_clusters)
    if core_nodes:
        final_clusters.append(core_nodes)
        log(f"Core switch cluster added: {sorted(core_nodes)}")
    else:
        log("No separate Core switches identified.")
    return final_clusters

if __name__ == "__main__":
    # 1. Build switch graph from nodes.txt and links.txt
    G = build_switch_graph_from_nodes_links("nodes.txt", "links.txt")
    
    # 2. Dynamically identify Core switches using top 20% closeness centrality
    core_nodes = identify_core_switches(G, core_ratio=0.2)
    
    # 3. Extract Pod clusters after removing Core switches
    pod_clusters = extract_pod_clusters(G, core_nodes)
    
    # 4. Combine Pod clusters and Core switches into final clustering result
    final_clusters = split_clusters_with_core(G, pod_clusters, core_nodes)
    
    # 5. Save final clustering results and log
    write_final_clustering(final_clusters)
    write_clustering_sequence("clustering_sequence.txt")

