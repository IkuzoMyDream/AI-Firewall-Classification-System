# VM Configuration Files

This directory contains VM configuration files used for testing the AI Firewall Classification System.

## VM Setup Summary

| VM | IP Address | Firewall Type | Layer | Tool | Label |
|----|------------|---------------|-------|------|-------|
| **VM1** | 192.168.56.10 | No Firewall | — | — | 0 |
| **VM2** | 192.168.56.11 | Stateless | L3 | iptables | 1 |
| **VM3** | 192.168.56.12 | Stateful | L3/L4 | ufw | 2 |
| **VM4** | 192.168.56.13 | Proxy | L7 | Squid | 3 |

## Configuration Files

- `VM1.txt` - No Firewall (Baseline)
- `VM2.txt` - Stateless Firewall (iptables)
- `VM3.txt` - Stateful Firewall (ufw)
- `VM4.txt` - Proxy Firewall (Squid)

Each file contains:
1. Network configuration (`/etc/netplan/01-netcfg.yaml`)
2. Firewall setup commands
3. Verification steps

## Network Setup

All VMs use dual network interfaces:
- **enp0s3**: Host-only adapter (192.168.56.0/24) - for Kali Linux testing
- **enp0s8**: NAT Network - for internet access (apt install packages)

## Quick Start

1. Create 4 Ubuntu Server VMs in VirtualBox
2. Configure network adapters (Host-only + NAT)
3. Follow instructions in each VM*.txt file
4. Apply netplan configuration: `sudo netplan apply`
5. Set up firewall as specified
6. Verify connectivity from Kali Linux
