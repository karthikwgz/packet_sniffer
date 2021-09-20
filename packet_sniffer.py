#!/usr/bin/python3
print("Use Sudo")

from rich import print
from datetime import datetime
from rich.panel import Panel
from rich.table import Table
from rich.style import Style
import sys
import subprocess 
from scapy.all import *


grid = Table.grid(expand=True)
grid.add_column(justify="center", ratio=1)
grid.add_column(justify="right")
grid.add_row(
    "Database Monitoring Tool",
    datetime.now().ctime().replace(":", "[blink]:[/]"),
)
print(Panel(grid, style="white on red"))

net_iface = input("Enter interface name: ")

subprocess.call(["ifconfig",net_iface,"promisc"])

num_of_pkt = int(input("Enter the packet count you want to capture"))

time_sec =int(input("Enter the time how long(in sec) run to capture"))

proto = input("Enter the protocol(arp | icmp |all)")

def logs(packet):
	print("______________________")
	#print(packet.show())
	print(f"SRC_MAC: {str(packet[0].src)} DEST_MAC: {str(packet[0].dst)} TYPE: {str(packet[0].type)}")
	print(f"psrc: {str(packet[1].psrc)} hwsrc: {str(packet[1].hwsrc)} pdst: {str(packet[1].pdst)}")
	
if proto == "all":
	sniff(iface = net_iface ,count = num_of_pkt, timeout = time_sec, prn=logs )
elif proto == "arp" or proto == "icmp":
	sniff(iface = net_iface, count = num_of_pkt,timeout = time_sec , prn = logs , filter = proto)
