#!/usr/bin/env python3
"""
Integrated version:
- Build network topology with Mininet (MyTopo)
- Save node/link, MAC, and IP information to files
- Perform clustering (pod identification) based on switch connectivity
  - Dynamically identify core switches
  - Remove core switches, find connected components as pods
  - Map hosts connected to switches in each pod
- Generate traffic flows: 70% chance intra-pod, 30% inter-pod with random sources/destinations
- Save generated CSV as traffic_plan.json
- Run ryu-manager with controller, perform traffic simulation
- Run flow_table.py, copy results into data/{label}/
"""

#############################
# OVSSwitch and sorted override
#############################
from mininet.node import OVSSwitch

def my_default_dpid(self, dpid=None):
    if dpid is None:
        dpid = self.name[1:]
        dpid = ('0' * (16 - len(dpid))) + dpid
    return dpid.replace(":", "")

OVSSwitch.defaultDpid = my_default_dpid

import builtins

old_sorted = builtins.sorted

def custom_sorted(iterable, key=None, reverse=False):
    if key == type:
        return old_sorted(iterable, key=lambda s: s.name if hasattr(s, 'name') else str(s), reverse=reverse)
    else:
        return old_sorted(iterable, key=key, reverse=reverse)

builtins.sorted = custom_sorted

#############################
# Standard imports
#############################
import os
import time
import random
import subprocess
import threading
import shutil
import json
import csv
import numpy as np
import networkx as nx

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import setLogLevel
from mininet.link import TCLink

from dctopo import MyTopo  # Custom topology

######################################
# File-saving functions
######################################
def save_nodes_links(net):
    with open("nodes.txt", "w") as f_nodes:
        for node in net.values():
            f_nodes.write(f"{node.name}\n")
    print("nodes.txt saved")

    with open("links.txt", "w") as f_links:
        for link in net.links:
            intf1_name = link.intf1.name
            intf2_name = link.intf2.name
            f_links.write(f"{intf1_name}<->{intf2_name}\n")
    print("links.txt saved")

def save_mac_addresses(net):
    with open("mac.txt", "w") as f_mac:
        for host in net.hosts:
            f_mac.write(f"{host.name} {host.MAC()}\n")
    print("mac.txt saved")

def save_ip_addresses(net):
    with open("ip.txt", "w") as f_ip:
        for host in net.hosts:
            f_ip.write(f"{host.name}: {host.IP()}\n")
    print("ip.txt saved")

def save_results(label):
    """
    Copy flow_table.txt and packet_in_out.txt into data/{label}/
    """
    data_dir = os.path.join("data", label)
    os.makedirs(data_dir, exist_ok=True)

    result_files = ["flow_table.txt", "packet_in_out.txt"]

    for filename in result_files:
        if os.path.exists(filename):
            shutil.copy(filename, os.path.join(data_dir, filename))
            print(f"{filename} → {data_dir}/ copied")
        else:
            print(f"{filename} not found (skipped)")

    return data_dir

######################################
# Clustering functions
######################################
clustering_log = []

def log(message):
    print(message)
    clustering_log.append(message)

def write_clustering_sequence(output_file="clustering_sequence.txt"):
    with open(output_file, "w") as f:
        for message in clustering_log:
            f.write(message + "\n")
    print(f"Clustering sequence saved to {output_file}")

def write_final_clustering(clusters, output_file="final_clustering.txt"):
    with open(output_file, "w") as f:
        for i, cluster in enumerate(clusters, start=1):
            nodes_str = ", ".join(sorted(cluster))
            f.write(f"Cluster{i}: {nodes_str}\n")
    print(f"Final clustering saved to {output_file}")

def build_switch_graph_from_nodes_links(nodes_file="nodes.txt", links_file="links.txt"):
    """
    Read nodes.txt, extract switch names (s*), then read links.txt to build a NetworkX graph of switch-to-switch edges.
    """
    G = nx.Graph()
    with open(nodes_file, "r") as f:
        all_nodes = [line.strip() for line in f.readlines()]
    switches = [node for node in all_nodes if node.startswith("s")]
    G.add_nodes_from(switches)
    log(f"Added {len(switches)} switch nodes from nodes.txt")

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
    log(f"Graph built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G

def identify_core_switches(G, core_ratio=0.2):
    """
    Identify top core_ratio fraction of switches (by closeness centrality) as core switches.
    """
    centrality = nx.closeness_centrality(G)
    total_nodes = len(G.nodes())
    core_count = max(1, int(round(total_nodes * core_ratio)))
    sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
    core_nodes = [node for node, _ in sorted_nodes[:core_count]]
    log(f"Identified core switches: {core_nodes} (out of {total_nodes}, count {core_count})")
    return set(core_nodes)

def extract_pod_clusters(G, core_nodes):
    """
    Remove core switches, then find connected components of remaining switches as pods.
    """
    G_filtered = G.copy()
    G_filtered.remove_nodes_from(core_nodes)
    pods = list(nx.connected_components(G_filtered))
    log(f"Found {len(pods)} pod clusters after removing core switches")
    return pods

def split_clusters_with_core(pod_clusters, core_nodes):
    """
    Append the core switches as a separate cluster to the pods list.
    """
    final_clusters = list(pod_clusters)
    if core_nodes:
        final_clusters.append(core_nodes)
        log(f"Added core cluster: {sorted(core_nodes)}")
    else:
        log("No core switches to add as separate cluster")
    return final_clusters

def map_clusters_to_hosts(net, pod_clusters):
    """
    For each switch-based pod cluster, find all hosts connected to switches in that cluster.
    Returns a list of host lists (one list per pod).
    """
    pod_hosts = []
    switch_name_to_obj = {s.name: s for s in net.switches}

    for pod in pod_clusters:
        hosts_in_pod = set()
        for switch_name in pod:
            switch = switch_name_to_obj.get(switch_name)
            if not switch:
                continue
            for intf in switch.intfList():
                if intf.link:
                    node = intf.link.intf1.node if intf.link.intf1.node != switch else intf.link.intf2.node
                    if node in net.hosts:
                        hosts_in_pod.add(node)
        if hosts_in_pod:
            pod_hosts.append(list(hosts_in_pod))
    log(f"Mapped hosts into {len(pod_hosts)} pods")
    return pod_hosts

######################################
# Traffic generation functions
######################################
def generate_dct2gen_csv_with_pods(net, pods, csv_filename="dct2gen_output.csv"):
    """
    Generate DCT^2Gen-style traffic CSV based on pods:
    - 70% chance of intra-pod traffic, 30% inter-pod
    - For each pair, generate 1–3 flows:
      * Flow start time: exponential distribution
      * Flow size: log-normal distribution
    """
    all_hosts = net.hosts
    num_hosts = len(all_hosts)
    num_pairs = int(num_hosts * random.uniform(1.5, 1.8))
    flows = []
    used_pairs = set()

    for _ in range(num_pairs):
        if pods and random.random() < 0.7:
            valid_pods = [pod for pod in pods if len(pod) >= 2]
            if valid_pods:
                pod = random.choice(valid_pods)
                src, dst = random.sample(pod, 2)
            else:
                src = random.choice(all_hosts)
                dst = random.choice([h for h in all_hosts if h != src])
        else:
            src = random.choice(all_hosts)
            dst = random.choice([h for h in all_hosts if h != src])
            while (src.name, dst.name) in used_pairs:
                src = random.choice(all_hosts)
                dst = random.choice([h for h in all_hosts if h != src])
        used_pairs.add((src.name, dst.name))

        num_flows_pair = random.randint(1, 3)
        for _ in range(num_flows_pair):
            start_time = round(np.random.exponential(scale=1.0), 2)
            flow_size = int(np.random.lognormal(mean=10, sigma=2.0))
            flows.append({
                "start_time": start_time,
                "src": src.name,
                "dst": dst.name,
                "bytes": flow_size
            })

    flows = sorted(flows, key=lambda f: f["start_time"])
    with open(csv_filename, "w", newline='') as csvfile:
        fieldnames = ["start_time", "src", "dst", "bytes"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flows)
    print(f"DCT²Gen-style traffic CSV generated ({len(flows)} flows, {len(used_pairs)} pairs)")

def convert_csv_to_plan(csv_file="dct2gen_output.csv", plan_file="traffic_plan.json"):
    """
    Convert DCT²Gen CSV to traffic_plan.json:
    - For each flow: 60% chance TCP (port 80, parallel=1, time=10)
                    40% chance UDP (port 8080, bandwidth="10M", time=10)
    - Additionally, generate 3 ping tests between random hosts from the CSV
    """
    plan = {"tcp": [], "udp": [], "ping": []}
    rows = []
    with open(csv_file, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    random.shuffle(rows)

    for row in rows:
        if random.random() < 0.6:
            entry = {
                "server": row["dst"],
                "client": row["src"],
                "port": 80,
                "parallel": 1,
                "time": 10
            }
            plan["tcp"].append(entry)
        else:
            entry = {
                "server": row["dst"],
                "client": row["src"],
                "port": 8080,
                "bandwidth": "10M",
                "time": 10
            }
            plan["udp"].append(entry)

    hosts = set()
    for row in rows:
        hosts.add(row["src"])
        hosts.add(row["dst"])
    hosts = list(hosts)
    num_ping = min(3, len(hosts) - 1)
    for _ in range(num_ping):
        server = random.choice(hosts)
        client = random.choice([h for h in hosts if h != server])
        plan["ping"].append({"server": server, "client": client})

    with open(plan_file, "w") as f:
        json.dump(plan, f, indent=2)
    print(f"traffic_plan.json saved: {plan_file}")

######################################
# Traffic simulation function
######################################
def simulate_from_plan(net, filename="traffic_plan.json"):
    with open(filename, "r") as f:
        plan = json.load(f)

    name_to_host = {h.name: h for h in net.hosts}
    threads = []

    # TCP tests
    for test in plan["tcp"]:
        server = name_to_host.get(test["server"])
        client = name_to_host.get(test["client"])
        if not server or not client:
            continue
        port = test["port"]
        parallel = test["parallel"]
        t_time = test["time"]

        def run_tcp(server=server, client=client, port=port, parallel=parallel, t_time=t_time):
            try:
                server.cmd("pkill -f 'iperf -s'")
                server.cmd(f"iperf -s -p {port} &")
                time.sleep(2)
                client.cmd(f"iperf -c {server.IP()} -p {port} -P {parallel} -t {t_time}")
                server.cmd("pkill -f 'iperf -s'")
            except Exception as e:
                print(f"TCP test error ({server.name} ↔ {client.name}): {e}")

        t = threading.Thread(target=run_tcp)
        threads.append(t)

    # UDP tests
    for test in plan["udp"]:
        server = name_to_host.get(test["server"])
        client = name_to_host.get(test["client"])
        if not server or not client:
            continue
        port = test["port"]
        bandwidth = test["bandwidth"]
        t_time = test["time"]

        def run_udp(server=server, client=client, port=port, bandwidth=bandwidth, t_time=t_time):
            try:
                server.cmd("pkill -f 'iperf -s -u'")
                server.cmd(f"iperf -s -u -p {port} &")
                time.sleep(2)
                client.cmd(f"iperf -c {server.IP()} -u -p {port} -b {bandwidth} -t {t_time}")
                server.cmd("pkill -f 'iperf -s -u'")
            except Exception as e:
                print(f"UDP test error ({server.name} ↔ {client.name}): {e}")

        t = threading.Thread(target=run_udp)
        threads.append(t)

    # Ping tests
    for test in plan["ping"]:
        server = name_to_host.get(test["server"])
        client = name_to_host.get(test["client"])
        if not server or not client:
            continue

        def run_ping(server=server, client=client):
            try:
                server.cmd(f"ping -c 10 {client.IP()}")
            except Exception as e:
                print(f"Ping test error ({server.name} → {client.name}): {e}")

        t = threading.Thread(target=run_ping)
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    os.system("pkill -f iperf")
    print("All traffic tests completed")

######################################
# Main simulation function
######################################
def run_simulation(controller_file, label, plan_file="traffic_plan.json", force_generate=False):
    # Clean up
    os.system("mn -c")
    os.system("pkill -f iperf")
    os.system("pkill -f ryu-manager")
    time.sleep(1)

    # Build topology and start network
    topo = MyTopo()
    net = Mininet(topo=topo, controller=None, autoSetMacs=False, link=TCLink)
    remote_controller = RemoteController('c0', ip='127.0.0.1', port=6633)
    net.addController(remote_controller)
    net.start()
    print("Network topology configured")

    # Save node, link, MAC, IP information
    save_nodes_links(net)
    save_mac_addresses(net)
    save_ip_addresses(net)

    # Clustering: build switch graph and find pods
    G = build_switch_graph_from_nodes_links("nodes.txt", "links.txt")
    core_nodes = identify_core_switches(G, core_ratio=0.2)
    pod_clusters = extract_pod_clusters(G, core_nodes)
    final_clusters = split_clusters_with_core(pod_clusters, core_nodes)
    write_final_clustering(final_clusters)
    write_clustering_sequence("clustering_sequence.txt")

    # Map hosts into pods
    pods = map_clusters_to_hosts(net, pod_clusters)

    # Run clustering analysis script if exists
    print("Running Clustering.py")
    try:
        subprocess.check_call(["python3", "Clustering.py"])
        print("Clustering.py completed")
    except subprocess.CalledProcessError as e:
        print(f"Error running Clustering.py: {e}")

    # Generate or reuse traffic plan
    if force_generate or not os.path.exists(plan_file):
        generate_dct2gen_csv_with_pods(net, pods, "dct2gen_output.csv")
        convert_csv_to_plan("dct2gen_output.csv", plan_file)
    else:
        print(f"Using existing traffic plan: {plan_file}")

    # Start controller
    print(f"Starting controller: ryu-manager {controller_file}")
    controller_proc = subprocess.Popen(["ryu-manager", controller_file])
    time.sleep(10)

    # Run traffic simulation
    simulate_from_plan(net, plan_file)

    # Generate flow table
    print("Running flow_table.py")
    try:
        subprocess.check_call(["python3", "flow_table.py"])
        print("flow_table.txt generated")
    except subprocess.CalledProcessError as e:
        print(f"Error running flow_table.py: {e}")

    # Save result files
    save_results(label)

    print("All tests complete, stopping network")
    net.stop()
    controller_proc.terminate()
    controller_proc.wait()
    os.system("mn -c")
    print("Controller terminated")

######################################
# Entry point
######################################
if __name__ == '__main__':
    setLogLevel('info')
    # First simulation: use normal_controller.py, force new plan generation
    run_simulation("normal_controller.py", "normal", force_generate=True)
    # Second simulation: use compromised_controller.py, reuse existing plan
    run_simulation("compromised_controller.py", "compromised", force_generate=False)

