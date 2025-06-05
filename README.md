## Cluster-Based Detection of Compromised SDN Controller Using Behavioral Divergence

This repository supports the paper **"Cluster-Based Detection of Compromised SDN Controller Using Behavioral Divergence"**, which introduces a scalable, localized anomaly detection framework for SDN environments.

---

### Overview

Software-Defined Networking (SDN) offers centralized programmability, but this centralization makes the controller a critical point of failure. If compromised, a controller may issue malicious flow rules while staying OpenFlow-compliant, making traditional detection methods ineffective—especially in large-scale networks.

We propose a **cluster-based anomaly detection method** that leverages the hierarchical and localized traffic nature of data centers.

---

### Architecture

The detection process is carried out in four steps:

1. **Local Monitoring** at each pod using the Cluster Index Monitoring System (CIMS)  
2. **Behavioral Index Extraction** from flow table and packet activity  
3. **Transfer of index vectors** to the central monitoring server  
4. **Anomaly Classification** based on inter-cluster divergence  

![Framework Overview](./framework-001.png)

---

### Behavioral Indexes

To characterize cluster behavior, five statistical indexes are used:

- **SPI**: Switch Participation Index  
- **PFSI**: Priority Frequency Spike Index  
- **TFSI**: Timeout Frequency Spike Index  
- **PPR**: Packet Processing Ratio  
- **PPD**: Packet Processing Divergence  

These indexes are computed per cluster and compared using **Max Pairwise Distance (MPD)** to capture abnormal divergence.

---

### Classification Accuracy

Extensive evaluation shows that the cluster-based method provides more **stable and scalable accuracy** compared to centralized detection, especially as topology size increases.

![Classification Accuracy](./accuracy.png)

---

### Scalability and Resource Efficiency

Compared to centralized approaches, the proposed method achieves:

- Lower latency
- Lower CPU usage at scale
- Consistently low memory footprint

![Scalability and Efficiency](./efficiency.png)

---

### Conclusion

The proposed cluster-based detection framework achieves **high accuracy with significantly improved scalability** and resource efficiency. This makes it well-suited for large-scale SDN deployments in modern data center environments.

Future directions include support for multi-controller systems and adaptation to evolving attack strategies.

---

> 📎 For detailed implementation, refer to the code and usage instructions below.

## How to Use the Code

This section walks you through the full experimental pipeline — from setup to anomaly detection evaluation — based on our SDN controller compromise detection framework.

---

### 1. Install Requirements

Before running the code, ensure the following are installed:

#### System Dependencies:
- Mininet (v2.3.1b4 or higher)
- Ryu Controller (v4.34 or higher)
- Ubuntu 20.04+ (recommended)
- Optional: VMware/VirtualBox for virtualization

#### Python Packages:
```bash
pip install -r requirements.txt
```

### 2. Run the Experiment Script
```bash
sudo python3 pyscript.py
```
- Runs the experiment for the configured number of iterations.
- Raw output is saved in the data/ directory.

- ### 3. Calculate Behavioral Indexes
Extract behavioral indexes (e.g., SPI, PFSI, TFSI, PPR, PPD):
```bash
sudo python3 calculate_index.py
```
- Each experiment run will have its own index results stored in a subfolder within data/.

- ### 4. (Optional) Visualize Indexes
If you want to visualize the index values:
```bash
sudo python3 graph.py
```
- Generates plots for easier inspection and debugging.
- This step is optional.

- ### 5. Convert to CSV Format
```bash
sudo python3 data_process.py
```

- ### 6. Run Detection and Evaluate
Run classification models and measure detection performance.
- For Cluster-Based Detection:
```bash
sudo python3 ML.py       # Accuracy
sudo python3 util.py     # Resource efficiency
```
- For Centralized Detection:
```bash
sudo python3 overall_ML.py     # Accuracy
sudo python3 overall_util.py   # Resource efficiency
```


