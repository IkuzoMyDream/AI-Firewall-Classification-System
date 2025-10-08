# AI Firewall Classification System

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3%2B-orange)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)](https://www.linux.org/)

![AI Firewall Classification System Topology](docs/images/image.png)


## Overview

The **AI Firewall Classification System** is a machine learning-based tool that automatically detects and classifies network firewall types based on their behavioral characteristics. The system analyzes network behavior patterns including ICMP responses, TCP port states, scan timing, SYN/ACK ratios, and HTTP header modifications to accurately identify firewall implementations.

## Project Objectives

This project aims to develop a lightweight machine learning classifier capable of:
- Automated firewall type detection from network behavior patterns
- Non-intrusive firewall fingerprinting without exploiting vulnerabilities
- Network security assessment through behavioral analysis
- Support for real-time classification of unknown network perimeters

## Firewall Classification

The system classifies networks into **4 distinct categories**:

| Label | Firewall Type | Key Characteristics |
|-------|--------------|---------------------|
| **0** | No Firewall | Responds to all packets, minimal filtering |
| **1** | Stateless | Port-based filtering, stateless packet inspection |
| **2** | Stateful | Connection tracking, session-aware filtering |
| **3** | Proxy | Application-layer filtering, HTTP header modification |

## Technology Stack

**Infrastructure:**
- Host OS: Kali Linux 2024+
- Virtualization: Oracle VirtualBox 7.0+
- Guest OS: Ubuntu Server 22.04 LTS

**Firewall Technologies:**
- iptables (Stateless filtering)
- ufw (Stateful filtering)
- Squid 6.x (HTTP proxy)

**Network Analysis Tools:**
- ping (ICMP testing)
- nmap (Port scanning)
- hping3 (TCP/IP packet crafting)
- curl (HTTP header analysis)

**Machine Learning:**
- Python 3.8+
- scikit-learn (Classification algorithms)
- pandas (Data manipulation)
- numpy (Numerical computations)
- matplotlib/seaborn (Visualization)

## Architecture

### Network Topology

```
                      [ Kali Host ]
                      192.168.56.1
                            |
                   vboxnet0 (Host-only)
    ________________________________________________
    |              |              |              |
192.168.56.10  192.168.56.11  192.168.56.12  192.168.56.13
    VM1             VM2            VM3            VM4
 No Firewall     Stateless      Stateful        Proxy
  (Baseline)     (iptables)       (ufw)        (Squid)
```

### Virtual Machine Configuration

| VM | Firewall Type | OS | vCPU | RAM | Storage | Network Mode | IP Address | OSI Layer | Implementation |
|----|--------------|-----|------|-----|---------|-------------|------------|-----------|----------------|
| **VM1** | No Firewall | Ubuntu 22.04 | 1 | 512 MB | 6 GB | Host-only | `192.168.56.10/24` | N/A | Baseline |
| **VM2** | Stateless | Ubuntu 22.04 | 1 | 512 MB | 6 GB | Host-only | `192.168.56.11/24` | Layer 3 | iptables |
| **VM3** | Stateful | Ubuntu 22.04 | 1 | 512 MB | 6 GB | Host-only | `192.168.56.12/24` | Layer 3-4 | ufw |
| **VM4** | Proxy | Ubuntu 22.04 | 1 | 768 MB | 8 GB | Host-only | `192.168.56.13/24` | Layer 7 | Squid |

## Firewall Configuration

### VM1: No Firewall (Baseline)

```bash
# No firewall configuration
# System accepts all incoming and outgoing traffic
# Used as baseline for comparison
```

**Purpose:** Establish baseline network behavior without filtering

### VM2: Stateless Firewall (iptables)

```bash
sudo apt update && sudo apt install -y iptables iptables-persistent

# Drop incoming SSH connections (port 22)
sudo iptables -A INPUT -p tcp --dport 22 -j DROP

# Save rules persistently
sudo netfilter-persistent save
```

**Purpose:** Demonstrate stateless packet filtering based on port numbers without connection tracking

### VM3: Stateful Firewall (ufw)

```bash
sudo apt update && sudo apt install -y ufw

# Enable firewall with default deny policy
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw enable
```

**Purpose:** Implement stateful inspection that tracks connection states and only allows established connections

### VM4: Proxy Firewall (Squid)

```bash
sudo apt update && sudo apt install -y squid

# Configure Squid to allow all connections
sudo sed -i '/http_access deny all/i http_access allow all' /etc/squid/squid.conf

# Enable and start Squid service
sudo systemctl enable squid
sudo systemctl restart squid
```

**Purpose:** Demonstrate application-layer proxy that inspects and modifies HTTP traffic

## Feature Engineering

The machine learning model uses 11 stable behavioral features for classification:

### Layer 3 (Network Layer) Features
- **avg_latency**: Average round-trip time in milliseconds
- **packet_loss**: Percentage of lost ICMP packets
- **ttl_return**: Time-to-live value from ICMP responses
- **icmp_reachable**: Binary indicator of ICMP echo reply reception

### Layer 4 (Transport Layer) Features
- **filtered_ports_count**: Number of filtered TCP ports (1-1024 range)
- **scan_time**: Duration of port scan operation in seconds
- **syn_ack_ratio**: Ratio of SYN/ACK responses to SYN probes (port 80)
- **tcp_reset_ratio**: Ratio of RST responses to SYN probes (port 22)

### Layer 7 (Application Layer) Features
- **response_time**: HTTP response time in milliseconds
- **header_modified**: Binary indicator of proxy/cache header presence

### Target Variable
- **firewall_label**: Firewall classification (0-3)

## Project Structure

```
AI-Firewall-Classification-System/
├── data/
│   ├── raw/              # Raw collected data
│   └── processed/        # Processed datasets (dataset.csv)
├── docs/
│   ├── images/           # Documentation images
│   ├── feature.txt       # Feature descriptions and importance
│   └── payload.txt       # Network payload specifications
├── models/
│   └── firewall_classifier.pkl   # Trained Random Forest model
├── results/
│   ├── confusion_matrices/       # Confusion matrix plots
│   └── metrics/                  # Performance metrics and plots
├── src/
│   ├── data_collector.py         # Feature collection script
│   ├── train_model.py            # Model training script
│   ├── classify.py               # Real-time classification
│   └── validate_model.py         # Model validation
├── vm_configs/
│   ├── VM1.txt           # No Firewall configuration
│   ├── VM2.txt           # Stateless Firewall (iptables)
│   ├── VM3.txt           # Stateful Firewall (ufw)
│   └── VM4.txt           # Proxy Firewall (Squid)
├── examples/
│   └── validation_example.md     # Validation examples
├── requirements.txt      # Python dependencies
├── LICENSE              # MIT License
└── README.md            # This file
```

## Getting Started

### Prerequisites

**Software Requirements:**
- Kali Linux or any Linux distribution with networking tools
- Oracle VirtualBox 7.0 or higher
- Ubuntu Server 22.04 LTS ISO image
- Python 3.8 or higher

**Hardware Requirements:**
- Minimum 8 GB RAM (for host and 4 VMs)
- 30 GB free disk space
- Multi-core processor with virtualization support (VT-x/AMD-V)

### Installation and Setup

#### Step 1: Create VirtualBox Host-Only Network

```bash
# Create host-only network adapter
VBoxManage hostonlyif create

# Configure network with IP 192.168.56.1/24
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0
```

#### Step 2: Deploy Virtual Machines

Create 4 Ubuntu Server VMs with specifications from the configuration table:
- Follow the network topology diagram
- Attach each VM to the host-only network (vboxnet0)
- Assign static IP addresses as specified
- Apply respective firewall configurations from the sections above

#### Step 3: Install Dependencies on Host

```bash
# Update package repository
sudo apt update

# Install network analysis tools
sudo apt install -y nmap hping3 curl

# Install Python and ML libraries
sudo apt install -y python3 python3-pip
pip3 install scikit-learn pandas numpy matplotlib seaborn
```

#### Step 4: Clone Repository

```bash
# Clone the project
git clone https://github.com/IkuzoMyDream/AI-Firewall-Classification-System.git
cd AI-Firewall-Classification-System

# Install Python dependencies
pip install -r requirements.txt

# Give hping3 raw socket capability (to run without sudo)
sudo setcap cap_net_raw+ep $(which hping3)
```

#### Step 5: Collect Training Data

```bash
# Collect data from all VMs (recommended: 250+ samples per VM)
python src/data_collector.py \
  --targets 192.168.56.10 192.168.56.11 192.168.56.12 192.168.56.13 \
  --label-map 192.168.56.10:0 192.168.56.11:1 192.168.56.12:2 192.168.56.13:3 \
  --repeat 250 \
  --output data/processed/dataset.csv
```

#### Step 6: Train Machine Learning Model

```bash
# Train Random Forest classifier
python src/train_model.py

# Outputs:
# - models/firewall_classifier.pkl
# - results/metrics/metrics.json
# - results/confusion_matrices/confusion_matrix.png
# - results/metrics/feature_importance.png
# - results/metrics/learning_curve.png
```

#### Step 7: Classify Unknown Firewalls

```bash
# Classify a single target
python src/classify.py 192.168.56.10

# Classify multiple targets
python src/classify.py 192.168.56.10 192.168.56.11 192.168.56.12 192.168.56.13

# With debug output
python src/classify.py 192.168.56.13 --debug
```

#### Step 8: Validate Model on New Data

```bash
# Collect fresh validation data
python src/data_collector.py \
  --targets 192.168.56.10 192.168.56.11 192.168.56.12 192.168.56.13 \
  --repeat 20 \
  --output validation_data.csv

# Validate model
python src/validate_model.py validation_data.csv
```

## Expected Performance

The trained classification model should achieve the following metrics:

| Metric | Target Value | Description |
|--------|-------------|-------------|
| **Accuracy** | > 90% | Overall classification accuracy on test set |
| **Precision** | > 85% | Correctly identified positives per class |
| **Recall** | > 85% | Coverage of actual positives per class |
| **F1-Score** | > 85% | Harmonic mean of precision and recall |
| **Inference Time** | < 2 seconds | Time to classify a single target |
| **Training Time** | < 5 minutes | Model training duration (100+ samples) |

## Limitations and Considerations

**Ethical Use:**
- Only test on networks you own or have explicit authorization to scan
- Comply with local laws and regulations regarding network scanning
- Respect privacy and security policies of target networks

**Technical Limitations:**
- Requires sudo/root privileges for nmap and hping3
- Results may vary based on network conditions and latency
- Proxy detection requires accessible proxy ports (3128, 8080, 8888)
- Classification accuracy depends on training data quality and quantity

## Contributing

Contributions are welcome! Please follow these guidelines:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Create a Pull Request

## License

This project is for educational and research purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

## Author

**winnietheSUii**

GitHub: [https://github.com/winnietheSUii](https://github.com/winnietheSUii)

## Acknowledgments

This project was developed as part of network security research to understand firewall behavior classification through machine learning techniques.
