#!/usr/bin/env python3

import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blastee:
    def __init__(self, net: switchyard.llnetbase.LLNetBase, blasterIp, num):
        self.net = net
        # TODO: store the parameters
        self.blasterIp = blasterIp
        self.num = num
        self.count = 0

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug(f"I got a packet from {fromIface}")
        log_debug(f"Pkt: {packet}")

        # extract seq
        self.count += 1
        num = packet[3].to_bytes()[:4]
        payload = packet[3].to_bytes()[6:14]
        if len(payload) < 8:
            payload.append(b"\00" * (8 - len(payload)))

        log_debug(
            f"\33[32mrecv seq {int.from_bytes(num, 'big')}, total {self.count}\33[0m"
        )

        # reply
        ack = (
            Ethernet(
                dst="40:00:00:00:00:02",
                src="20:00:00:00:00:01",
                ethertype=EtherType.IPv4,
            )
            + IPv4(
                dst=self.blasterIp,
                src=self.net.port_by_name(fromIface).ipaddr,
                ttl=64,
                protocol=IPProtocol.UDP,
            )
            + UDP(dst=22222, src=33333)
            + RawPacketContents(num)
            + RawPacketContents(payload)
        )
        self.net.send_packet(fromIface, ack)

    def start(self):
        """A running daemon of the blastee.
        Receive packets until the end of time.
        """
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()
