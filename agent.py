from bcc import BPF
import socket
import os
from time import sleep
from pyroute2 import IPRoute

import sys
import time

ipr = IPRoute()

nic = sys.argv[1]

INGRESS="ffff:ffff2"
EGRESS="ffff:ffff3"

try:
    b = BPF(src_file="agent.bpf.c")
    fn = b.load_func("xdp_agent", BPF.SCHED_CLS)
    idx = ipr.link_lookup(ifname=nic)[0]

    ipr.tc("add", "clsact", idx)
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent=EGRESS, classid=1,direct_action=True)

    dst_ts = b.get_table("dst_ts_hash")
    while True:
        try:
            time.sleep(3)
            for dst, ts in dst_ts.items():
                print("({}): {}".format(socket.inet_ntoa(dst),
                                        ts.value))
        except KeyboardInterrupt:
            break
finally:
    if "idx" in locals():
        ipr.tc("del", "clsact", idx)

# BPFプログラムのロード
#b = BPF(src_file="agent.bpf.c")
#prog_array = b.get_table("prog_array")
#prog_array[0] = b.get_prog("bpf_ingress_redirect")

# Traffic Controlのingressにアタッチ
#b.attach_tc("ingress", "bpf_ingress_redirect")