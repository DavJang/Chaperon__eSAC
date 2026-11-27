#!/usr/bin/env python3
"""Split bpftrace events into per-mlx5_flow_create windows; the last (crossing) call must show the entry
probe but no RETURN and no command-submission activity (rdma-core submit calls / ioctl) before the kill."""
import re, sys
ev = []
for ln in open(sys.argv[1], errors="replace"):
    m = re.match(r"(\d+) (ENTRY|RETURN|SUBMIT|IOCTL)\b(.*)", ln.strip())
    if m: ev.append((int(m.group(1)), m.group(2), m.group(3).strip()))
ev.sort(); hard = int(sys.argv[2])
wins = []
for t, k, d in ev:
    if k == "ENTRY": wins.append({"t": t, "ret": None, "sub": [], "ioc": 0})
    elif wins:
        w = wins[-1]
        if k == "RETURN": w["ret"] = d
        elif k == "SUBMIT": w["sub"].append(d)
        elif k == "IOCTL": w["ioc"] += 1
for i, w in enumerate(wins, 1):
    print(f"CALL {i}: returned={'yes ' + w['ret'] if w['ret'] else 'NO'} submit_calls={len(w['sub'])} {sorted(set(w['sub']))} ioctls={w['ioc']}")
ok = len(wins) == hard + 1 and all(w["ret"] and (w["sub"] or w["ioc"]) for w in wins[:hard]) \
     and wins[-1]["ret"] is None and not wins[-1]["sub"] and wins[-1]["ioc"] == 0
print(f"HL_RESULT {'PASS' if ok else 'FAIL'}: calls={len(wins)} admitted_with_submission={sum(1 for w in wins[:hard] if w['ret'] and (w['sub'] or w['ioc']))}/{hard} "
      f"crossing_call: entry=yes return={'yes' if wins and wins[-1]['ret'] else 'no'} submit={len(wins[-1]['sub']) if wins else '?'} ioctl={wins[-1]['ioc'] if wins else '?'}")
sys.exit(0 if ok else 1)
