#!/usr/bin/env python

import scapy.all as scapy
import argparse

#python3 network_scanner.py -t 10.0.2.1/24
#scan entire nw/ and display Mac IP mapping except own IP of m.c it is running ie 10.0.2.20
# root@kali:~# python3 /root/PycharmProjects/network_scanner/network_scanner.py -t 10.0.2.1/24
# IP			MAC Address
# --------------------------------------------------
# 10.0.2.1		52:54:00:12:35:00
# 10.0.2.2		52:54:00:12:35:00
# 10.0.2.3		08:00:27:b6:98:b3
# 10.0.2.15		08:00:27:e6:e5:59
# root@kali:~#
#this algo is compatible with both py 2 n 3

def get_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument('-t', '--target', dest="target",
                      help=' Target Range of IP address ex: 10.0.2.1/24 ')
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please Specify an IP range, use --help")
    # For improvement add auto input of IP address range
    return options

def scapy_scan(ip):
    scapy.arping(ip)

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    #arp_request.show()
    #above will show all request param

    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # 34. Combining Frames Review
    #ff:ff... is broadcast address
    #broadcast.show()
    # above will show all request param

    arp_request_broadcast = broadcast/arp_request
    # / means merging two ARP request
    #arp_request_broadcast.show()
    # above will show all request param
    # print(arp_request_broadcast.summary())
    # above will show what will be the request output "Ether / ARP Who has Net (10.0.2.1/24) says 10.0.2.8 (ie ur local m/c ip)

    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] # this returns two list; answered and unanswered by keeping [0] it will only return answered
    #srp is to send packet and return list
    #answered will display mac who has that ip and unanswered will return all ips that are not used by any clients on the n/w
    #print(answered_list.summary())
    client_list = []
    for e in answered_list:
        #print(e[1].show())
        #above will show everything
        #in below first elemenet ie 0 is always the request sent which is same for all element except requesting for diff IP
        #in below 1 signifies the second value in the element which is answer that is replying to mac address

        client_dict = {
            "ip" : e[1].psrc,
            'mac' : e[1].hwsrc
        }
        client_list.append(client_dict)
    #print(client_list)
    #above will print list of all items added in dict
    return client_list

def print_result(result_list):
    print("IP\t\t\tMAC Address")
    print("-"*50)
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()
scan_result = scan(options.target)
#scan_result = scan("10.0.2.1/24")
print_result(scan_result)
