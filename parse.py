"""
    Read traffic.pcap and analyze RTT for each ip address
    Read ttfb.txt (redirected by run.js)  and analyze ttfb for each hosts and uris.
"""
from scapy.all import *
import sys
import os
from ipaddress import ip_address
import subprocess
from subprocess import Popen
from math import ceil
from urllib.parse import urlparse
from random import sample

reached_ip = sys.argv[1].split(",")

pkts = rdpcap('test.pcap')

ip_map = {} # ip: [S, SA]
host_map = {} # host: {url: delay}
ping_map = {}

def sec_to_datetime(sec):
    _, sec = divmod(sec, 24 * 3600)
    hour, sec = divmod(sec, 3600)
    minute, sec = divmod(sec, 60)
    second, sec = divmod(sec, 60)
    return '{}:{}:{}'.format(hour-4, minute, second)

def parse_pkt(pkt):
    ip = pkt.getlayer(IP)
    src, dst = ip.src, ip.dst
    time = pkt.time
    flags =str(pkt['TCP'].flags)
    return (flags, time, src, dst)

def is_private(address):
    return address == '10.0.2.15'
    # return address.split('.')[0] == '10' and address.split('.')[1] == '0'


def main():
    for pkt in pkts:
        if pkt is None:
            continue
        if "TCP"  not in pkt:
            continue
        flag, time, src, dst = parse_pkt(pkt)
        if is_private(src) and dst not in ip_map:  # SYN msg
            ip_map[dst] = [time]
        elif is_private(dst) and src in ip_map and len(ip_map[src]) == 1:  # SA msg
            ip_map[src].append(time)
    f2 = open('traffic.txt', 'w')
    f3 = open('prolonged_traffic.txt', 'w')

    count = -1
    for ip, times in ip_map.items():
        if ip not in reached_ip:
            continue
        count += 1
        if len(times) < 2:
            continue
        #rtt = max(0.0, float(rtt_sample[count]) * 2 -0.029)
        rtt = times[1]-times[0]
        f2.write('{}\t{}\n'.format(ip, rtt))
        f3.write('{}\t{}\n'.format(ip, 0))
    f3.write('factor\t50\n')
    f2.close()
    f3.close()

if __name__ == '__main__':
    main()
