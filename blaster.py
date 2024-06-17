#!/usr/bin/env python3

import time
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blaster:
    def __init__(
        self,
        net: switchyard.llnetbase.LLNetBase,
        blasteeIp,
        num,
        length="100",
        senderWindow="5",
        timeout="300",
        recvTimeout="100",
    ):
        self.net = net
        # TODO: store the parameters
        self.balsteeIp = blasteeIp
        self.num = int(num)
        self.length = int(length)
        self.SW = int(senderWindow)
        self.timeout = float(timeout) / 1000
        self.recvTimeout = float(recvTimeout) / 1000

        self.cur_num = 0
        self.cur_time = 0
        self.window = []
        self.queue = []

        self.start_time = -1
        self.packet_count = 0
        self.timeout_count = 0

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug("I got a packet")

        num = int.from_bytes(packet[3].to_bytes()[:4], "big")
        log_debug(f"recv packet seq {num}")

        for i in range(len(self.window)):
            # update
            if self.window[i]["seq"] == num:
                self.window[i]["status"] = 1
                break

        self.handle_no_packet()

        # complete transmission
        if self.cur_num == self.num and not self.window:
            total_time = time.time() - self.start_time
            log_info(f"Total TX time: {total_time} s")
            log_info(f"Number of reTX: {self.packet_count - self.num}")
            log_info(f"Number of coarse TOs: {self.timeout_count}")
            log_info(
                f"Throughput: {(6 + self.length) * self.packet_count / total_time} Bps"
            )
            log_info(f"Goodput: {(6 + self.length) * self.num / total_time} Bps")
            self.shutdown()

    def handle_no_packet(self):
        log_debug("Didn't receive anything")

        port = self.net.ports()[0]
        t = time.time()

        while self.window:
            # LHS move, update time
            if self.window[0]["status"] == 1:
                del self.window[0]
                self.cur_time = t
            else:
                break

        # Creating the headers for the packet
        pkt = (
            Ethernet(
                dst="40:00:00:00:00:01",
                src="10:00:00:00:00:01",
                ethertype=EtherType.IPv4,
            )
            + IPv4(dst=self.balsteeIp, src=port.ipaddr, protocol=IPProtocol.UDP, ttl=64)
            + UDP(dst=33333, src=22222)
        )

        # first time
        if self.cur_num == 0:
            self.start_time = t
            self.cur_time = t

        # no retransmission
        if not self.queue:
            # timeout
            if t - self.cur_time > self.timeout:
                self.timeout_count += 1
                for i in range(len(self.window)):
                    info = self.window[i]
                    if info["status"] == 0:
                        seq = RawPacketContents(info["seq"].to_bytes(4, "big"))
                        length = RawPacketContents(self.length.to_bytes(2, "big"))
                        payload = RawPacketContents(b"\x00" * self.length)

                        self.queue.append(pkt + seq + length + payload)

                        self.packet_count += 1
            # move RHS
            if len(self.window) < self.SW and self.cur_num < self.num:
                seq = RawPacketContents(self.cur_num.to_bytes(4, "big"))
                length = RawPacketContents(self.length.to_bytes(2, "big"))
                payload = RawPacketContents(b"\x00" * self.length)

                self.net.send_packet(port.name, pkt + seq + length + payload)

                self.window.append(
                    {
                        "seq": self.cur_num,
                        "status": 0,  # 0 : not recv ack, 1 : recv ack
                    }
                )

                self.cur_num += 1
                self.packet_count += 1

        # need retransmission
        else:
            self.net.send_packet(port.name, self.queue[0])
            del self.queue[0]
            if not self.queue:
                self.cur_time = t

        # print window with status, green for ack, red for unack
        s = ""
        for d in self.window:
            if d["status"] == 0:
                s += f'| \33[31m{d["seq"]}\33[0m'
            else:
                s += f'| \33[32m{d["seq"]}\33[0m'
        if self.window:
            s += " |"
            log_debug(s)

    def start(self):
        """A running daemon of the blaster.
        Receive packets until the end of time.
        """
        while True:
            try:
                recv = self.net.recv_packet(timeout=self.recvTimeout)
            except NoPackets:
                self.handle_no_packet()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
