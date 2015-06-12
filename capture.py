"""
    a packet capture tool based on python2.7
    capture on one network adapter
"""

# !/usr/bin/env python2.7
# -*- coding: utf-8 -*-

__author__ = 'lau'

import pcap
import socket
import struct
import string
import time
import sys
import finddev
import os


def decode_ip_packet(s):
    d = {}
    d['version'] = (ord(s[0]) & 0xf0) >> 4
    d['header_len'] = ord(s[0]) & 0x0f
    d['ToS'] = ord(s[1])
    d['total_len'] = socket.ntohs(struct.unpack('H', s[2:4])[0])
    d['id'] = socket.ntohs(struct.unpack('H', s[4:6])[0])
    d['flags'] = (ord(s[6]) & 0xe0) >> 5
    d['fragment_offset'] = socket.htons(struct.unpack('H', s[6：8])[0] & 0x1f)
    d['ttl'] = ord(s[8])
    d['protocol'] = ord(s[9])
    d['checksum'] = socket.htons(struct.unpack('H', s[10:12])[0])
    d['src_addr'] = pcap.ntoa(struct.unpack('i', s[12:16])[0])
    d['dst_addr'] = pcap.ntoa(struct.unpack('i', s[16:20])[0])
    if d['header_len'] > 5:
        d['options'] = s[20: 4 * (d['header_len'] - 5)]
    else:
        d['options'] = None
    d['data'] = s[4 * d['header_len']:]
    return d


def hex_dump(s):
    byte = map(lambda x: '%.2x' % x, map(ord, s))
    for i in xrange(0, len(byte) / 16):
        print('     %s' % string.join(byte[i * 16: (i + 1) * 16]), ' ')
    print('     %s' % string.join(byte[(i + 1) * 16:]), ' ')


def show_packet(pktlen, data, timestamp):
    if not data:
        return

    protocol = {socket.IPPROTO_TCP: 'TCP',
                socket.IPPROTO_UDP: 'UDP',
                socket.IPPROTO_ICMP: 'ICMP'}
    if data[12:14] == '\x08\x00':
        decoded = decode_ip_packet(data[14:])
        print '\n[+] %s.%f %s > %s' % (time.strftime('%H:%M', time.localtime(timestamp)),
                                    timestamp % 60,
                                    decoded['src_addr'],
                                    decoded['dst_addr'])
        for key in ['version', 'header_len', 'Tos', 'total_len', 'id', 'flags', 'fragment_offset',
                    'ttl']:
            print '[+] %s: %d' % (key, decoded[key])
        print '[+] protocol: %s' % protocol[decoded['protocol']]
        print '[+] Header Checksum: %d' % decoded['checksum']
        print '[+] data:'
        hex_dump(decoded['data'])


def print_help():
    print '[+] usage: python2.7 capture.py [OPTION]... [FILTER]...'
    print '         -h, --help'
    print '             Output help information'
    print '         -d, --dev'
    print '             List all the devices'
    print '         -c|--capture [DEV] "[FILTER]"'
    print '             Capture on DEV with FILTER.'
    print '             as: sudo python2.7 capture.py eth0 "port 80"'


def capture():
    p = pcap.pcapObject()

    if len(sys.argv) == 2:
        if sys.argv[1] == '-d' or sys.argv[1] == '--dev':
            finddev.print_all_devs()
        elif sys.argv[1] == '-h' or sys.argv[1] == '--help':
            finddev.print_help()
        else:
            print '[-] Wrong order " %s' % sys.argv[1:], '"'
            print_help()
    elif len(sys.argv) == 4:
        if sys.argv[1] == '-c':
            dev = sys.argv[2]
            net, mask = pcap.lookupnet(dev)
            p.open_live(dev, 1600, 0, 100)
            p.setfilter(string.join(sys.argv[3:], ' '), 0, 0)
            try:
                while True:
                    p.dispatch(1, show_packet)
            except KeyboardInterrupt:
                print '[-] %s' % sys.exc_type
                print '[-] shutting down'
                print '[+] %d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()
    else:
        print '[-] Wrong order " %s' % sys.argv[1:], '"'
        print_help()

if __name__ == '__main__':
    capture()
