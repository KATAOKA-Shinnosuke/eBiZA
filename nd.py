from bcc import BPF
import socket
import os
from time import sleep
#from pyroute2 import IPRoute

import sys
import time

b = BPF(src_file="nd.bpf.c")
nic = sys.argv[1]
f = b.load_func("xdp_nd", BPF.XDP)

b.attach_xdp(nic, f, 0)

prev_access = b.get_table("prev_access_hash")
new_access = b.get_table("new_access_queue")
scan_count = b.get_table("count_hash")
#test_queue = b.get_table("test_queue")
#test_hash = b.get_table("test_hash")
while True:
    try:
        time.sleep(5)
        #os.system('clear')
        for src_dst, count in prev_access.items():
            print("({}, {}): {}".format(socket.inet_ntoa(src_dst.src_addr.to_bytes(4, byteorder='little')),
                                        socket.inet_ntoa(src_dst.dst_addr.to_bytes(4, byteorder='little')), count.value))
        #print(test_queue.values())
        #print(test_hash.values())
        #for src_ts in new_access.values():
        #    print("{} at {}".format(socket.inet_ntoa(src_ts.src_addr.to_bytes(4, byteorder='little')),
        #                            src_ts.timestamp))
        #for src, scan in scan_count.items():
        #    print("{}: {} scans".format(socket.inet_ntoa(int(src).to_bytes(4, byteorder='little')),
        #                                scan))
        #print(prev_access.values())
        print(scan_count.values())
    except KeyboardInterrupt:
        break

b.remove_xdp(nic)
