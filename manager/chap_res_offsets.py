#!/usr/bin/env python3
# Chaperon Request I: "prog:symbol[:ret],..." -> "prog:fileoffset[:ret],..." for the Table tab:apis attach
# points (bpftime override for the Agent, kernel uprobes for the Sentinel). Symbol virtual addresses are
# converted to file offsets with the ELF program headers. Any missing symbol => exit 1 (launch is refused).
import subprocess, sys

exe, spec = sys.argv[1], sys.argv[2]
syms = {}
for line in subprocess.run(["nm", exe], capture_output=True, text=True).stdout.splitlines():
    p = line.split()
    if len(p) == 3 and p[1] in ("T", "t"):
        syms.setdefault(p[2], int(p[0], 16))
segs = []
for line in subprocess.run(["readelf", "-lW", exe], capture_output=True, text=True).stdout.splitlines():
    p = line.split()
    if p and p[0] == "LOAD":
        segs.append((int(p[1], 16), int(p[2], 16), int(p[4], 16)))   # file offset, vaddr, file size
out, bad = [], []
for ent in [e for e in spec.split(",") if e]:
    f = ent.split(":")
    prog, sym, rest = f[0], f[1], f[2:]
    v = syms.get(sym)
    off = None
    if v is not None:
        for o, va, fs in segs:
            if va <= v < va + fs:
                off = v - va + o
    if off is None:
        bad.append(sym)
        continue
    out.append(":".join([prog, hex(off)] + rest))
if bad:
    print("MISSING " + " ".join(bad), file=sys.stderr)
    sys.exit(1)
print(",".join(out))
