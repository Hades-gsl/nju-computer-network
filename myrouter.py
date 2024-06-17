#!/usr/bin/env python3
"""
Basic IPv4 router (static routing) in Python.
"""

from time import *
import switchyard
from switchyard.lib.userlib import *


class ARPtable:
    def __init__(self):
        self.table = {}

    def add(self, ip, mac):
        self.table[ip.exploded] = mac.toStr()
        self.print_table()

    def print_table(self):
        log_info("ARP table")
        for k, v in self.table.items():
            log_info(f"IP:{k} MAC:{v}")

    def query(self, ip):
        return self.table.get(ip)


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.arp_table = ARPtable()

        self.forwarding_table = []
        self.init_forwarding_table()

        self.queue = {}

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv

        if packet.has_header(Arp):
            arp = packet.get_header(Arp)
            eth = packet.get_header(Ethernet)
            port = self.net.port_by_name(ifaceName)

            if (
                port.ethaddr == eth.dst
                or eth.dst == SpecialEthAddr.ETHER_BROADCAST.value
            ) and eth.ethertype != EtherType.Vlan:
                self.handle_arp(ifaceName, packet.get_header(Arp))

        if packet.has_header(IPv4):
            ip = packet.get_header(IPv4).dst
            try:
                port = self.net.port_by_ipaddr(ip)
            except KeyError:
                next_hop, portName = self.look_up(packet, ifaceName)

                if next_hop != None:
                    self.add_queue(next_hop, packet, portName)

        self.forward()

    def look_up(self, packet, ifaceName):
        macaddr = packet.get_header(Ethernet).dst
        port = self.net.port_by_name(ifaceName)

        if macaddr == SpecialEthAddr.ETHER_BROADCAST.value or macaddr == port.ethaddr:
            ip_dst = packet.get_header(IPv4).dst
            for d in self.forwarding_table:
                ip = IPv4Address(d["ip"])
                mask = IPv4Address(d["mask"])

                if int(ip) == int(mask) & int(ip_dst):
                    next_hop = d["next_hop"]
                    if next_hop == "0.0.0.0":
                        next_hop = ip_dst.exploded
                    return next_hop, d["port"]

        return None, None

    def add_queue(self, next_hop, packet, portName):
        if self.queue.get(next_hop) == None:
            self.queue[next_hop] = []

        if len(self.queue[next_hop]) == 0:
            self.queue[next_hop].append(portName)
            self.queue[next_hop].append(0)
            self.queue[next_hop].append(time())

        self.queue[next_hop].append(packet)

    def forward(self):
        for ip, q in self.queue.items():
            if len(q) > 0:
                macaddr = self.arp_table.query(ip)
                port = self.net.port_by_name(q[0])

                if self.arp_table.query(ip):
                    for i in range(3, len(q)):
                        packet = q[i]
                        packet[Ethernet].dst = macaddr
                        packet[Ethernet].src = port.ethaddr
                        packet[IPv4].ttl -= 1
                        self.net.send_packet(q[0], packet)

                    self.queue[ip].clear()
                else:
                    t = time()
                    if q[1] == 5 and t - q[2] > 1:
                        self.queue[ip].clear()
                    elif q[1] == 0 or t - q[2] > 1:
                        arp = create_ip_arp_request(port.ethaddr, port.ipaddr, ip)
                        self.net.send_packet(q[0], arp)
                        q[1] += 1
                        q[2] = t

    def handle_arp(self, ifaceName, arp):
        try:
            port = self.net.port_by_ipaddr(arp.targetprotoaddr)
            if arp.operation == ArpOperation.Request:
                self.arp_table.add(arp.senderprotoaddr, arp.senderhwaddr)

                pkt = create_ip_arp_reply(
                    port.ethaddr, arp.senderhwaddr, port.ipaddr, arp.senderprotoaddr
                )
                self.net.send_packet(ifaceName, pkt)
            else:
                if (
                    arp.senderhwaddr != SpecialEthAddr.ETHER_BROADCAST.value
                    and arp.targethwaddr == port.ethaddr
                    and port.name == ifaceName
                ):
                    self.arp_table.add(arp.senderprotoaddr, arp.senderhwaddr)
        except KeyError as e:
            log_failure(e)

    def init_forwarding_table(self):
        for p in self.net.ports():
            ip = ""
            mask = p.netmask.exploded
            for x, y in zip(p.ipaddr.exploded.split("."), mask.split(".")):
                m = int(x) & int(y)
                ip += str(m) + "."
            ip = ip[:-1]

            next_hop = "0.0.0.0"
            port = p.name
            self.forwarding_table.append(
                {"ip": ip, "mask": mask, "next_hop": next_hop, "port": port}
            )

        with open("forwarding_table.txt", "r") as f:
            t = f.readline()
            while t:
                ip, mask, next_hop, port = t[:-1].split(" ")
                self.forwarding_table.append(
                    {"ip": ip, "mask": mask, "next_hop": next_hop, "port": port}
                )
                t = f.readline()

        self.forwarding_table.sort(key=lambda d: d["mask"], reverse=True)

        for d in self.forwarding_table:
            log_debug(d)

    def start(self):
        """A running daemon of the router.
        Receive packets until the end of time.
        """
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                self.forward()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    """
    Main entry point for router.  Just create Router
    object and get it going.
    """
    router = Router(net)
    router.start()
