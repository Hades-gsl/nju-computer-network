'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)

remove forwarding table entries after some time(10s)
'''
import switchyard
from switchyard.lib.userlib import *
import time

T = 10.0

def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    table =  {}

    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        src = eth.src
        dst = eth.dst
        t = time.time()
        table[src] = (fromIface, t)
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if dst == 'ff:ff:ff:ff:ff:ff' or table.get(dst) == None or t - table[dst][1] > T:
                if table.get(dst) != None:
                    table.pop(dst)
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
            else:
                log_info (f"Forwarding packet {packet} to {table[dst][0]}")
                net.send_packet(table[dst][0], packet)

    net.shutdown()
