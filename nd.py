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
while True:
    try:
        time.sleep(1)
        os.system('clear')
        for src, dst, count in prev_access.items():
            print("({}, {}): {}".format(src.value, dst.value, count.value))
        print("")
        #for src, ts in new_access.get():
        #    print("{} at {}".format(src.value, ts.value))
    except KeyboardInterrupt:
        break

b.remove_xdp(nic)
