## Cluster-Based Detection of Compromised SDN Controller Using Behavioral Divergence

This repository accompanies the paper **"Cluster-Based Detection of Compromised SDN Controller Using Behavioral Divergence"**, which proposes a scalable framework for detecting malicious SDN controller behavior in large-scale data centers.

### 📝 Overview

Software-Defined Networking (SDN) centralizes network control, which improves flexibility and manageability—but also creates a single point of failure. A compromised SDN controller can manipulate network flows while remaining protocol-compliant, making detection difficult, especially at scale.

This project introduces a **cluster-based anomaly detection framework** that leverages **behavioral divergence** among localized switch groups (or "clusters") in hierarchical topologies such as FatTree and Clos. The key idea is to detect inconsistencies in behavioral patterns across pods rather than relying on full-network monitoring.

### 🔍 Key Contributions

- **Pod-Level Monitoring**: Switches are grouped into clusters based on traffic locality (e.g., pods), and behavioral metrics are computed per cluster.
- **Max Pairwise Distance (MPD)**: Anomaly detection is based on the maximum behavioral divergence between clusters using MPD, capturing deviations without full network visibility.
- **Behavioral Indexes**: Five core metrics are introduced to quantify behavior:
  - Switch Participation Index (SPI)
  - Priority Frequency Spike Index (PFSI)
  - Timeout Frequency Spike Index (TFSI)
  - Packet Processing Ratio (PPR)
  - Packet Processing Divergence (PPD)
- **Threat Model**: Evaluates multiple stealthy attack vectors such as silent drops, flow rule abuse, and covert mirroring—while the controller remains OpenFlow-compliant.
- **Traffic Simulation**: Uses a custom DCT2Gen-inspired traffic generator to emulate realistic east-west data center traffic patterns.
- **Experimental Results**: Shows that the cluster-based method maintains high detection accuracy with lower overhead and better scalability compared to centralized approaches.

### 🏗️ Experimental Environment

- **SDN Emulator**: Mininet v2.3.1b4
- **Controller**: Ryu v4.34
- **Topology**: k-ary Fat-Tree (k = 4, 6, 8, 10)
- **Classifier Models**: Random Forest, Adaboost, Decision Tree, MLP, Naïve Bayes
- **Metrics**: Detection accuracy, CPU/memory usage, latency

### 📌 Conclusion

The proposed method offers an efficient, accurate, and scalable solution for detecting compromised SDN controllers in hierarchical data center networks. By exploiting spatial traffic locality and reducing monitoring overhead, this approach is well-suited for deployment in hyperscale cloud environments.

****
