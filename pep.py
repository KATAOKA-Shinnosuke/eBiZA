from bcc import BPF
import socket
import os
from time import sleep
#from pyroute2 import IPRoute

import sys
import time

b = BPF(src_file="pep.bpf.c")
nic = sys.argv[1]
f = b.load_func("xdp_pep", BPF.XDP)

b.attach_xdp(nic, f, 0)

allowed_src = b.get_table("allowed_src_hash")

while True:
    try:
        time.sleep(5)
        os.system('clear')
        for src, ts in allowed_src.items():
            print("({}): {}".format(socket.inet_ntoa(src),
                                    ts.value))
        #print(test_queue.values())
        #print(test_hash.values())
        #for src_ts in new_access.values():
        #    print("{} at {}".format(socket.inet_ntoa(src_ts.src_addr.to_bytes(4, byteorder='little')),
        #                            src_ts.timestamp))
        #for src, scan in scan_count.items():
        #    print("{}: {} scans".format(socket.inet_ntoa(int(src).to_bytes(4, byteorder='little')),
        #                                scan))
        #print(prev_access.values())
    except KeyboardInterrupt:
        break

b.remove_xdp(nic)