from bcc import BPF
import socket
import os
from time import sleep
#from pyroute2 import IPRoute

import sys
import time

b = BPF(src_file="nd.bpf.c")
interface = "hogehoge"

fx = b.load_func("xdp", BPF.XDP)
BPF.attach_xdp(interface, fx, 0)

b.trace_print()
