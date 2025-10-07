                +----------------------+
                |      Kali (Host)     |
                | 10.0.0.1 (Host-only) |
                | Scanner / AI Model   |
                +----------+-----------+
                           |
                 [VirtualBox Host-only Adapter]
                           |
    ------------------------------------------------
    |          |           |           |           |
  VM1        VM2         VM3         VM4         VM5
(no FW)   (Stateless)  (Stateful)   (Proxy)     (NAT)
10.0.0.10  10.0.0.11    10.0.0.12    10.0.0.13   NAT subnet (10.0.2.x)



My goal is to build a lightweight AI classifier that detects firewall type from network behavior (ping, TTL diff, open ports, latency, HTTP response, etc.).