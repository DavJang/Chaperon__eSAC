#!/usr/bin/env python3
# Chaperon Request P -- TEST-ONLY: a process that joins the tenant cgroup WITHOUT exec (so it works with or without
# the legacy exec block), drops to the tenant uid/gid, and then touches the tenant's RDMA device. It models "a process
# that merely belongs to the same cgroup" (never registered by the Manager).
#   cg_probe.py <cgroup.procs> <uid> <uverbs dev> open|preopen_ioctl|preopen_mmap [gofile]
#     open            open(2) the uverbs node inside the cgroup
#     preopen_ioctl   open the node BEFORE joining (outside the protected cgroup), then RDMA_VERBS_IOCTL inside it
#     preopen_mmap    same, then mmap(2) of the fd inside it
#   gofile: after joining, wait until this file exists (the Manager plants a stale registry entry meanwhile)
import fcntl, mmap, os, pwd, sys, time

procs, uid, dev, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
gof = sys.argv[5] if len(sys.argv) > 5 else None
P = lambda s: print("CGP " + s, flush=True)
fd = None
if mode.startswith("preopen"):
    fd = os.open(dev, os.O_RDWR)
    P(f"preopen fd={fd} pid={os.getpid()} (outside the protected cgroup)")
with open(procs, "w") as f:
    f.write(str(os.getpid()))
gid = pwd.getpwuid(uid).pw_gid
os.setgroups([]); os.setgid(gid); os.setuid(uid)
P(f"joined pid={os.getpid()} uid={os.getuid()} cgroup={open('/proc/self/cgroup').read().strip()}")
if gof:
    P("waiting")
    while not os.path.exists(gof):
        time.sleep(0.05)
if mode == "open":
    P("open begin")
    try:
        r = os.open(dev, os.O_RDWR); P(f"open ret fd={r}")
    except OSError as e:
        P(f"open ret errno={e.errno}")
elif mode == "preopen_ioctl":
    P("ioctl begin")
    try:
        fcntl.ioctl(fd, 0xC0181B01, bytes(24)); P("ioctl ret ok")      # RDMA_VERBS_IOCTL = _IOWR(0x1b, 1, 24 bytes)
    except OSError as e:
        P(f"ioctl ret errno={e.errno}")
elif mode == "preopen_mmap":
    P("mmap begin")
    try:
        m = mmap.mmap(fd, 4096, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=0); P("mmap ret ok")
    except OSError as e:
        P(f"mmap ret errno={e.errno}")
P("end (process survived)")
