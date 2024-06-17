#!/usr/bin/env python3
'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *


class ARPtable():

    def __init__(self):
        self.table = {}

    def add(self, ip, mac):
        if mac != SpecialEthAddr.ETHER_BROADCAST.value:
            self.table[ip.exploded] = mac.toStr()
            self.print_table()

    def print_table(self):
        log_info('ARP table')
        for k, v in self.table.items():
            log_info(f'{k}:{v}')

    def query(self, ip):
        return self.table.get(ip.exploded)


class Router(object):

    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.table = ARPtable()
        # other initialization stuff here

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        arp = packet.get_header(Arp)
        if arp:
            # debugger()
            self.table.add(arp.senderprotoaddr, arp.senderhwaddr)
            if arp.operation == ArpOperation.Request:
                ip = arp.targetprotoaddr
                try:
                    port = self.net.port_by_ipaddr(ip)
                    pkt = create_ip_arp_reply(port.ethaddr, arp.senderhwaddr,
                                              port.ipaddr, arp.senderprotoaddr)
                    self.net.send_packet(ifaceName, pkt)
                except KeyError as e:
                    log_info(e)

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
