# Scapy Port Scanner

A command-line tool for scanning ports.  
Python package Scapy is requried.

## Features
- TCP and UDP protocols supported
- ICMP ping to check live hosts
- ICMP ping detects host operating system (Windows or *nix)
- Scan lists and/or ranges of ports
- Scan ranges of IP or subnet
- Specify timeout

## Use
`
BYOPS.py [-h] [--icmp] host port protocol
`  

Scan ports for a specified host 

positional arguments:  
    host        IP address of host to scan   
    port        Port number to scan  
    protocol    TCP or UDP  

optional arguments:  
    -h, --help  show this help message and exit  
    --icmp      Use ICMP ping to determine if host is up before scanning ports  
    --timeout TIMEOUT  Timeout waiting for response  

Scapy requires sudo access for some functions.

Sample functions:
```bash
sudo python BYOPS.py 192.168.185.40 22-40,55-60 tcp
sudo python BYOPS.py 192.168.185.0/24 80 tcp --icmp
sudo python BYOPS.py 192.168.185.40 22,80,121-122 udp
sudo python BYOPS.py 192.168.185.40-192.168.185.45 80 tcp

```
