# -*- coding: utf-8 -*-
"""
Test commands to show ip range, ip subnet mast, port range, port list, tcp/udp, icmp ping:
sudo python BYOPS.py 192.168.185.40 22-40 tcp --timeout .1
sudo python BYOPS.py 192.168.185.0/24 80 tcp --icmp
sudo python BYOPS.py 192.168.185.40 22,80,121-122 udp 
sudo python BYOPS.py 192.168.185.40-192.168.185.45 80 tcp

"""
#%% Import packages
from scapy.all import *
import argparse
import os

#%% Command-line switches
parser = argparse.ArgumentParser(description='Scan ports for a specified host \n(BYOPS [host] [port] [protocol])')
parser.add_argument('host', help='IP address of host to scan')
parser.add_argument('port', help='Port number to scan')
parser.add_argument('protocol', default='tcp', help='TCP UDP')
parser.add_argument('--icmp', action='store_true', help='Use ICMP ping to determine if host is up before scanning ports')
parser.add_argument('--timeout', default=1, type=float, help='Timeout waiting for response')
args = vars(parser.parse_args())

##host
arg_destinations = args['host']
#single ip
if arg_destinations.find('-') == -1 & arg_destinations.find('/') == -1:
    destinations = [arg_destinations]
#ip range
elif arg_destinations.find('-') != -1: 
    [d1,d2] = arg_destinations.split('-')
    start = list(map(int, d1.split(".")))
    end = list(map(int, d2.split(".")))
    temp = start
    destinations = []
    destinations.append(d1)
    while temp != end:
        start[3] += 1
        for i in (3, 2, 1):
            if temp[i] == 256:
                temp[i] = 0
                temp[i-1] += 1
        destinations.append(".".join(map(str, temp)))       
#subnet mask  
elif arg_destinations.find('/'): 
    import ipaddress
    ipn = ipaddress.IPv4Network(unicode(arg_destinations))
    destinations = []
    for h in ipn.hosts():
        destinations.append(h.exploded)

##port
ports = []
arg_ports = args['port']
#single port
if arg_ports.find('-') == -1 & arg_ports.find(',') == -1:
    ports = [int(arg_ports)]
#list ports
elif arg_ports.find(','):               
    arg_ports = arg_ports.split(',')
    for p in arg_ports:
        if p.find('-') == -1:
            ports.append(int(p))
        else:
            #lists and ranges
            p_r = p.split('-')
            ports = ports+range(int(p_r[0]),int(p_r[1]))
#port range
elif arg_ports.find('-'):               
    p_r = arg_ports.split('-')
    ports = ports+range(int(p_r[0]),int(p_r[1]))

##protocol
#TCP, UDP
protocol = args['protocol'].lower()
if protocol not in ['tcp','udp']:
    print "Please select TCP or UDP  protocols"
    exit()

##extra parameters
to = args['timeout'] #timeout time

#%%Port Scan
open_ports = {} #store results in a dictionary
for destination in destinations:
    open_ports[destination] = []
    print 'Trying IP: ' + destination
    #optional -- icmp to detect if host is up
    if args['icmp']:
        reply = sr1(IP(dst=destination)/ICMP(), timeout=to)
        if not (reply is None):
            if reply.ttl<65:
                print destination, " is Linux" #linux ttl starts at 64
                open_ports[destination].append('Linux')
            else:   
                print destination, " is Windows" #windows ttl starts at 128 -- unlikely to get below 65
                open_ports[destination].append('Windows')
        else:
            print destination, ' unreachable'
            open_ports[destination].append('down')
            continue #didn't get response, skip port scan for this host
        
    for port_check in ports:
        #tcp scan - SYN ACK RST
        if protocol == 'tcp':
            # Send SYN
            packet = IP(dst=destination,ttl=10)/TCP(sport=80,dport=port_check,flags="S")
            reply = sr1(packet,timeout=to)
            
            #no response
            if(str(type(reply))=="<type 'NoneType'>"):
                print port_check, " Closed"
            #got response
            elif(reply.haslayer(TCP)):
                # if SYN ACK
                if(reply.getlayer(TCP).flags == 0x12):
                    # send ACK RST
                    send_rst = sr(IP(dst=destination)/TCP(sport=80,dport=port_check,flags="AR"),timeout=to)
                    print port_check, " Open"
                    open_ports[destination].append(port_check)
                # if RST
                elif (reply.getlayer(TCP).flags == 0x14):
                    print port_check, " Closed"
        
        elif protocol == 'udp':
            # send packet to port
            reply = sr1(IP(dst=destination)/UDP(dport=port_check),timeout=to)
            # no response
            if (str(type(reply))=="<type 'NoneType'>"):
                retrans = []
                #try again to make sure
                for count in range(0,3):
                    retrans.append(sr1(IP(dst=destination)/UDP(dport=port_check),timeout=to))
                    for item in retrans:
                        if (str(type(item))!="<type 'NoneType'>"):
                            udp_scan(destination,port_check,1)
                            print "Open|Filtered"
            # got UDP response
            elif (reply.haslayer(UDP)):
                print "Open"
                open_ports[destination].append(port_check)
            #ICMP closed response
            elif(reply.haslayer(ICMP)):
                if(int(reply.getlayer(ICMP).type)==3 and int(reply.getlayer(ICMP).code)==3):
                    print "Closed"
            #ICMP filtered response
            elif(int(reply.getlayer(ICMP).type)==3 and int(reply.getlayer(ICMP).code) in [1,2,9,10,13]):
                print "Filtered"

#%% Print Results
print "Summary of open ports: \n"
for destination in destinations:
    #show host OS from icmp ttl
    if args['icmp']:
        if len(open_ports[destination]) < 2: #host down
            print destination, open_ports[destination][0]
        else:
            print destination, '(', open_ports[destination][0], '): ', open_ports[destination][1:]
    else:
        print destination, ': ', open_ports[destination]

