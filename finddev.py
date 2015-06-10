"""
    a packet capture tool based on python2.7
    find all devices
"""

# !/usr/bin/env python2.7
# -*- coding: utf-8 -*-

__author__ = 'lau'


import pcap


def print_all_devs():
    i = 0
    for name, descr, addrs, flags in pcap.findalldevs():
        print '[+] if %02d: %s' % (i + 1, name)
        i += 1
        # print '   Description: %s ' % descr
        # if addrs:
        #     i = 1
        #     for (addr, netmask, broadaddr, dstaddr) in addrs:
        #         # print '    Address %d: %s ' % (i, addr)
        #         # print '       Netmask: %s' % netmask
        #         # print '     Broadcast: %s' % broadaddr
        #         # print 'Peer dest addr: %s' % dstaddr
        #         i += 1
        # else:
        #     print '  No addresses!'
        # print ' flags: %s ' % flags

if __name__ == '__main__':
    print_all_devs()
