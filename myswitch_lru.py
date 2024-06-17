'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)

evict the least recently used rule
'''
import switchyard
from switchyard.lib.userlib import *

N = 5

def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    table = {}

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
        if table.get(src) != None:
            table[src][0] = fromIface
        else:
            table[src] = [fromIface, 1]
        for k in table.keys():
            table[k][1] += 1
        if len(table) > N:
            ks, vs = list(table.keys()), list(table.values())
            k = ks[vs.index(max(vs, key=lambda v : v[1]))]
            table.pop(k)
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if dst == 'ff:ff:ff:ff:ff:ff' or table.get(dst) == None:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
            else:
                log_info(f'Forwarding packet {packet} to {table[dst][0]}')
                net.send_packet(table[dst][0], packet)
                table[dst][1] = 1

    net.shutdown()
