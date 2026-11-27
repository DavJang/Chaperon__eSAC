#!/usr/bin/env python3
"""Chaperon Request-E Manager-side tools (run by the root harness; 'alias' is run AS THE TENANT UID).
  rangecheck <pid> <ranges>        every registered range must be mapped and NON-writable in the live tenant
  aliasops   <seal_targets.txt>    compute SHM-file offsets of enforcement routing (for the backing-object test)
  alias      <shm_path> off:hex..  write through the SHM backing object (a second, writable alias)
  order      <testpmd.log>         ordered launch evidence (BOOT_START < BARRIER_OK < GO < app init < EAL)
"""
import os, re, sys

def maps(pid):
    out = []
    for ln in open(f"/proc/{pid}/maps"):
        a, perm = ln.split()[:2]
        s, e = (int(x, 16) for x in a.split("-"))
        out.append((s, e, perm, ln.strip()))
    return out

def rangecheck(pid, rf):
    mp = maps(pid); n = wr = miss = 0
    for ln in open(rf):
        p = ln.split()
        if len(p) < 2: continue
        s, e = int(p[0], 16), int(p[1], 16); n += 1
        cov = [m for m in mp if m[0] < e and m[1] > s]
        if not cov: miss += 1; print(f"  MISSING {s:#x}-{e:#x}")
        for m in cov:
            if m[2][1] == "w": wr += 1; print(f"  WRITABLE {s:#x}-{e:#x} :: {m[3]}")
    print(f"RANGECHECK n={n} writable={wr} unmapped={miss}")
    return 0 if (n > 0 and wr == 0 and miss == 0) else 1

def aliasops(tf):
    shm = None; mp = {}
    for ln in open(tf):
        if ln.startswith("SHM "):
            shm = int(ln.split()[1].split("-")[0], 16)
        m = re.match(r"MAP fd=\d+ type=(\d+) name=(\S+) handler=(0x[0-9a-f]+) value0=(\S+)(?: type_off=(\d+))?", ln)
        if m:
            toff = int(m.group(5)) if m.group(5) else int(os.environ.get("CHAP_TYPE_OFF", "-1"))
            mp[m.group(2)] = dict(type=int(m.group(1)), h=int(m.group(3), 16),
                                  v=(int(m.group(4), 16) if m.group(4).startswith("0x") else 0), toff=toff)
    ops = []; desc = []
    r = mp.get("c_filter.rodata")
    if shm and r and r["v"]:
        ops.append(f"{r['v'] - shm + 24:#x}:00000000"); desc.append("RCFG.enabled=0 (SHM .rodata storage)")
    for nm in ("comm_policy", "rxburst_drv_pen"):
        x = mp.get(nm)
        if shm and x and x["toff"] >= 0: ops.append(f"{x['h'] - shm + x['toff']:#x}:ffff0000"); desc.append(f"{nm} handler.type=0xffff")
    print("OPS " + " ".join(ops)); print("DESC " + " ; ".join(desc))
    return 0 if len(ops) == 3 else 1

def alias(path, ops):
    fd = os.open(path, os.O_RDWR)
    for op in ops:
        off, hx = op.split(":"); off = int(off, 0); b = bytes.fromhex(hx)
        before = os.pread(fd, len(b), off); os.pwrite(fd, b, off); after = os.pread(fd, len(b), off)
        print(f"ALIAS_WRITE uid={os.getuid()} off={off:#x} before={before.hex()} after={after.hex()} landed={after == b}")
    os.close(fd); return 0

def order(logf):
    L = open(logf, errors="replace").read().splitlines()
    def first(pat):
        for i, l in enumerate(L):
            if re.search(pat, l): return i + 1
        return None
    k = dict(BOOT_START=first(r"\[chap-boot.*BOOT_START"), BARRIER_OK=first(r"\[chap-boot.*BARRIER_OK"),
             GO_RECEIVED=first(r"\[chap-boot.*GO_RECEIVED"), initialize_program=first(r"initialize program:"),
             transferring_control=first(r"transferring control:"), first_EAL=first(r"EAL:"))
    pre = [re.sub(r"^\s*\d+:\s*", "", l) for l in L[: (k["BOOT_START"] or 1) - 1] if "calling init:" in l]
    print("ORDER " + " ".join(f"{a}=L{b}" for a, b in k.items()))
    print(f"PRE_BOOTSTRAP_SHARED_LIB_INITS n={len(pre)}")
    for l in pre: print("  " + l)
    seq = [k[x] for x in ("BOOT_START", "BARRIER_OK", "GO_RECEIVED", "initialize_program", "transferring_control", "first_EAL")]
    ok = all(v is not None for v in seq) and seq == sorted(seq)
    print("ORDER_RESULT " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1

def libtrust(tuser, exe, preload):
    """Request F: classify every object ld.so loads (and initializes BEFORE the barrier) for the tenant."""
    import pwd, stat, subprocess
    pw = pwd.getpwnam(tuser); tuid = pw.pw_uid; tg = set(os.getgrouplist(tuser, pw.pw_gid))
    env = dict(os.environ); env["LD_PRELOAD"] = preload
    out = subprocess.run(["/lib64/ld-linux-x86-64.so.2", "--list", exe], env=env, capture_output=True, text=True).stdout
    pre = [os.path.realpath(p) for p in preload.split(":") if p]
    objs = []
    for ln in out.splitlines():
        ln = ln.strip()
        m = re.match(r"\S+ => (/\S+) \(0x", ln) or re.match(r"(/\S+) \(0x", ln)
        if m: objs.append(os.path.realpath(m.group(1)))
    objs = list(dict.fromkeys(objs + pre))
    def tw(st):   # writable by the tenant principal
        m = st.st_mode
        return (st.st_uid == tuid and m & stat.S_IWUSR) or (st.st_gid in tg and m & stat.S_IWGRP) or (m & stat.S_IWOTH)
    def ow(st):   # writable by some other NON-ROOT principal
        m = st.st_mode
        return (st.st_uid not in (0, tuid) and m & stat.S_IWUSR) or (st.st_gid not in (0,) and st.st_gid not in tg and m & stat.S_IWGRP)
    bad = 0; warn = 0
    print(f"LIBTRUST tenant={tuser} uid={tuid} objects={len(objs)} (all are initialized by ld.so before __libc_start_main)")
    for p in objs:
        st = os.stat(p)
        cat = "bootstrap" if p in pre else ("application" if p == os.path.realpath(exe) else "host-lib")
        why = []
        if tw(st): why.append("file tenant-writable")
        d = os.path.dirname(p)
        while True:
            ds = os.stat(d)
            if tw(ds) and not (ds.st_mode & stat.S_ISVTX and st.st_uid != tuid): why.append(f"dir {d} tenant-writable")
            if d == "/": break
            d = os.path.dirname(d)
        other = ow(st)
        if cat == "application": verdict = "APP(runs after barrier)"
        elif why: verdict = "UNTRUSTED"; bad += 1
        elif other: verdict = "WARN(non-root host principal can write)"; warn += 1
        else: verdict = "TRUSTED"
        print(f"  {verdict:34s} {cat:11s} {p}  owner={st.st_uid}:{st.st_gid} mode={oct(st.st_mode & 0o7777)} {';'.join(why)}")
    print(f"LIBTRUST_RESULT untrusted_pre_barrier={bad} warn={warn}")
    return 1 if bad else 0

def mergeranges(inf, outf, cs, ce):
    rs = []
    for ln in open(inf):
        p = ln.split()
        if len(p) >= 2: rs.append((int(p[0], 16), int(p[1], 16)))
    rs.append((int(cs, 16), int(ce, 16)))
    rs.sort(); m = []
    for s, e in rs:
        if m and s <= m[-1][1]: m[-1] = (m[-1][0], max(m[-1][1], e))
        else: m.append((s, e))
    open(outf, "w").write("".join(f"0x{s:x} 0x{e:x}\n" for s, e in m))
    print(f"MERGED in={len(rs)} out={len(m)}"); return 0

def timeline(mgr, boot, tlog):
    ev = []
    for ln in open(mgr):
        m = re.match(r"t=(\d+) (.*)", ln.strip())
        if m: ev.append((int(m.group(1)), "MANAGER", m.group(2)))
    for ln in open(boot, errors="replace"):
        m = re.search(r"\[chap-boot pid=\d+ t=(\d+)\] (\S+)", ln)
        if m: ev.append((int(m.group(1)), "TRUSTED-BOOTSTRAP", m.group(2)))
    ev.sort(); t0 = ev[0][0] if ev else 0
    for t, who, what in ev: print(f"  +{(t - t0) / 1e6:10.3f} ms  {who:18s} {what}")
    L = open(tlog, errors="replace").read().splitlines()
    def first(p):
        for i, l in enumerate(L):
            if re.search(p, l): return i + 1
        return None
    seqp = ["BOOT_START", "STEP2a MAPS_RO_INIT_OK", "STEP2b FD_REMOVED", "STEP3a DISPATCH_SEALED", "STEP3b VIEW_SEALED",
            "STEP3c CODE_SEALED", "BARRIER_OK", "GO_RECEIVED", "initialize program:", "transferring control:", "EAL:"]
    if first(re.escape("STEP3a DISPATCH_SEALED")) is None: seqp.remove("STEP3a DISPATCH_SEALED")   # listener-mode control
    pos = [first(re.escape(x)) for x in seqp]
    print("STREAM_ORDER " + " ".join(f"{x.split()[0]}=L{p}" for x, p in zip(seqp, pos)))
    def mt(name):
        for t, who, what in ev:
            if what.startswith(name): return t
        return None
    need = [mt("SENTINELS_READY"), mt("TENANT_EXEC_RELEASED"), mt("BOOT_START"), mt("BARRIER_OK"), mt("RANGES_REGISTERED"), mt("GO_WRITE_BEGIN"), mt("GO_RECEIVED")]
    ok_stream = all(p is not None for p in pos) and pos == sorted(pos)
    ok_time = all(x is not None for x in need) and need == sorted(need)
    r_api = mt("RESOURCE_API_FIRST_CALL"); ok_api = r_api is not None and need[-1] is not None and r_api > need[-1]
    print(f"TIMELINE_RESULT stream_order={'PASS' if ok_stream else 'FAIL'} manager_vs_bootstrap={'PASS' if ok_time else 'FAIL'} first_resource_api_after_go={'PASS' if ok_api else 'FAIL'}")
    return 0 if (ok_stream and ok_time and ok_api) else 1

def _tenant_writable(p, tuid, tg):
    """reasons why the tenant principal can modify path p (file or any directory on its path)"""
    import stat
    def tw(st):
        m = st.st_mode
        return (st.st_uid == tuid and m & stat.S_IWUSR) or (st.st_gid in tg and m & stat.S_IWGRP) or (m & stat.S_IWOTH)
    why = []; st = os.stat(p)
    if tw(st): why.append("file tenant-writable")
    d = os.path.dirname(p)
    while True:
        ds = os.stat(d)
        if tw(ds) and not (ds.st_mode & stat.S_ISVTX and st.st_uid != tuid): why.append(f"dir {d} tenant-writable")
        if d == "/": break
        d = os.path.dirname(d)
    return why

def maptrust(tuser, pid):
    """Request G: at the barrier every file mapped into the tenant (= everything ld.so loaded and initialized
    before __libc_start_main) must not be modifiable by the tenant. Checked on the LIVE process, not predicted."""
    import pwd
    pw = pwd.getpwnam(tuser); tuid = pw.pw_uid; tg = set(os.getgrouplist(tuser, pw.pw_gid))
    exe = os.path.realpath(f"/proc/{pid}/exe"); seen = []
    for ln in open(f"/proc/{pid}/maps"):
        f = ln.split()
        if len(f) < 6: continue
        p = " ".join(f[5:])
        if not p.startswith("/") or p.endswith("(deleted)") or p.startswith(("/dev/", "/proc/", "/sys/", "/memfd:")): continue
        if "hugepage" in p or "rtemap" in p or "/dev/shm/" in p: continue
        rp = os.path.realpath(p)
        if rp not in seen: seen.append(rp)
    bad = 0
    print(f"MAPTRUST pid={pid} tenant={tuser} mapped_files={len(seen)}")
    for p in seen:
        why = _tenant_writable(p, tuid, tg)
        if p == exe: v = "APP(code runs after the barrier; see exetrust)"
        elif why: v = "UNTRUSTED"; bad += 1
        else: v = "TRUSTED"
        print(f"  {v:46s} {p} {';'.join(why)}")
    print(f"MAPTRUST_RESULT untrusted_mapped={bad}")
    return 1 if bad else 0

def exetrust(exe):
    """Request G: no code of the application executable may run inside ld.so before the barrier:
    no DT_PREINIT_ARRAY and no IRELATIVE relocations (ifunc resolvers). DT_INIT / DT_INIT_ARRAY run from
    __libc_start_main, i.e. after the barrier hook."""
    import subprocess
    dyn = subprocess.run(["readelf", "-dW", exe], capture_output=True, text=True).stdout
    rel = subprocess.run(["readelf", "-rW", exe], capture_output=True, text=True).stdout
    pre = len(re.findall(r"\(PREINIT_ARRAY", dyn)); irel = len(re.findall(r"IRELATIV", rel))
    init = len(re.findall(r"\((INIT|INIT_ARRAY)\)", dyn))
    print(f"EXETRUST {exe} preinit_array={pre} irelative_relocs={irel} init_entries={init} (run by __libc_start_main after the barrier)")
    ok = pre == 0 and irel == 0
    print(f"EXETRUST_RESULT {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1

def _sentinel_ranges(pind):
    import json, subprocess, struct
    def dump(name):
        j = subprocess.run(["bpftool", "-j", "map", "dump", "pinned", f"{pind}/{name}"], capture_output=True, text=True).stdout
        return json.loads(j or "[]")
    def vbytes(e):
        v = e.get("value")
        if isinstance(v, list): return bytes(int(x, 16) for x in v)
        return None
    n = None
    for e in dump("integ_ctl"):
        f = e.get("formatted")
        if f and isinstance(f.get("value"), dict): n = int(f["value"].get("n_ranges", 0))
        else:
            b = vbytes(e)
            if b: n = struct.unpack_from("<I", b, 0)[0]
        break
    rs = []
    for e in dump("protected_ranges"):
        f = e.get("formatted")
        if f and isinstance(f.get("value"), dict):
            k = int(f["key"]); s, en = int(f["value"]["start"]), int(f["value"]["end"])
        else:
            kb = bytes(int(x, 16) for x in e["key"]); k = struct.unpack_from("<I", kb, 0)[0]
            s, en = struct.unpack_from("<QQ", vbytes(e), 0)
        rs.append((k, s, en))
    rs.sort()
    return n, [(s, e) for k, s, e in rs if n is not None and k < n and e > s]

def coverage(pid, odir, pind, cs, ce, seal_log, need_dispatch="1"):
    """Request G: every protection TARGET named by the trusted components must lie inside the ranges the
    kernel Tamper Sentinel actually holds (read back from its pinned map), not just a matching count."""
    tg = []
    d = open(os.path.join(odir, "dispatch.txt"), errors="replace").read() if os.path.exists(os.path.join(odir, "dispatch.txt")) else ""
    m = re.search(r"DISPATCH_SEALED .*table=\[(0x[0-9a-f]+),\+(\d+)\) selector=(0x[0-9a-f]+)", d)
    if m:
        t0, tl, sl = int(m.group(1), 16), int(m.group(2)), int(m.group(3), 16)
        tg += [("dispatch_table", t0, t0 + tl), ("dispatch_selector", sl, sl + 4096)]
    for mm in re.finditer(r"^CODE_RANGE (0x[0-9a-f]+)-(0x[0-9a-f]+) (\S+) (\S+)", d, re.M):
        tg.append((f"code:{os.path.basename(mm.group(4))}:{mm.group(3)}", int(mm.group(1), 16), int(mm.group(2), 16)))
    for mm in re.finditer(r"^TARGET (\S+) (0x[0-9a-f]+) (0x[0-9a-f]+)", d, re.M):
        tg.append((mm.group(1), int(mm.group(2), 16), int(mm.group(3), 16)))
    v = open(os.path.join(odir, "imm_view.txt"), errors="replace").read() if os.path.exists(os.path.join(odir, "imm_view.txt")) else ""
    m = re.search(r"VIEW_SEALED .*selector=(0x[0-9a-f]+) view=\[(0x[0-9a-f]+),\+(\d+)\)", v)
    if m:
        s0 = int(m.group(1), 16); v0 = int(m.group(2), 16)
        tg += [("view_selector", s0, s0 + 4096), ("view", v0, v0 + int(m.group(3)))]
    for mm in re.finditer(r"^RODATA_COPY fd=\d+ copy=\[(0x[0-9a-f]+),\+(\d+)\)", v, re.M):
        a = int(mm.group(1), 16); tg.append(("rodata_copy", a, a + int(mm.group(2))))
    for mm in re.finditer(r"^KARRAY_RO fd=\d+ name=(\S+) map=\[(0x[0-9a-f]+),(0x[0-9a-f]+)\)", v, re.M):
        tg.append((f"kmap_ro:{mm.group(1)}", int(mm.group(2), 16), int(mm.group(3), 16)))
    s = open(seal_log, errors="replace").read() if os.path.exists(seal_log) else ""
    for mm in re.finditer(r"SEAL rwx->r-x (0x[0-9a-f]+)-(0x[0-9a-f]+)", s):
        tg.append(("wx_hook_page", int(mm.group(1), 16), int(mm.group(2), 16)))
    for mm in re.finditer(r"ENFSEAL ufunc_ctx RO (0x[0-9a-f]+)-(0x[0-9a-f]+)", s):
        tg.append(("ufunc_table", int(mm.group(1), 16), int(mm.group(2), 16)))
    tg.append(("hook_code_seg", int(cs, 16), int(ce, 16)))
    n, rs = _sentinel_ranges(pind)
    def covered(a, b):
        x = a
        for s0, e0 in sorted(rs):
            if s0 <= x < e0: x = e0
            if x >= b: return True
        return x >= b
    miss = 0
    print(f"COVERAGE sentinel_n_ranges={n} readback={len(rs)} targets={len(tg)}")
    for name, a, b in tg:
        ok = covered(a, b); miss += 0 if ok else 1
        print(f"  {'COVERED' if ok else 'MISSING'} {name} [{a:#x},{b:#x})")
    cats = {"rodata_copy": 1, "view": 1, "view_selector": 1, "ufunc_table": 1, "wx_hook_page": 1, "jit": 1, "hook_code_seg": 1}
    if need_dispatch == "1": cats.update({"dispatch_table": 1, "dispatch_selector": 1})
    absent = [c for c in cats if not any(t[0] == c for t in tg)]
    if sum(1 for t in tg if t[0].startswith("kmap_ro:")) < 3: absent.append("kmap_ro(x3)")
    if not any(t[0].startswith("code:") and "agent" in t[0] and t[0].endswith("r-xp") for t in tg): absent.append("code:agent r-xp")
    for c in absent: print(f"  MISSING_TARGET_CATEGORY {c} (not reported by the trusted components)")
    ok = miss == 0 and not absent and n is not None and n == len(rs) and n > 0
    print(f"COVERAGE_RESULT {'PASS' if ok else 'FAIL'} targets={len(tg)} covered={len(tg) - miss} missing={miss} absent_categories={len(absent)} sentinel_ranges={n}")
    return 0 if ok else 1

def tele(sock, *cmds):
    """DPDK telemetry v2 query (the tenant's stdout is block-buffered, so counters are read here)."""
    import socket, json
    s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET); s.connect(sock); s.recv(16384)
    out = {}
    for c in cmds:
        s.send(c.encode()); out.update(json.loads(s.recv(1 << 22).decode()))
    print(json.dumps(out)); return 0

def txmem(logf):
    """mbuf pool state from the k-th 'dump_mempool' (buffered testpmd output, flushed at quit)."""
    L = open(logf, errors="replace").read().splitlines(); k = -1; cur = None
    for ln in L:
        m = re.search(r"mempool <(mb_pool_\d+)>@", ln)
        if m: k += 1; cur = {"size": None, "common": None, "cache": None}; continue
        if cur is None: continue
        for key, pat in (("size", r"^\s*size=(\d+)"), ("common", r"common_pool_count=(\d+)"), ("cache", r"total_cache_count=(\d+)")):
            mm = re.search(pat, ln)
            if mm: cur[key] = int(mm.group(1))
        if cur["size"] is not None and cur["common"] is not None and cur["cache"] is not None:
            print(f"TXMEM idx={k} size={cur['size']} avail={cur['common'] + cur['cache']} in_use={cur['size'] - cur['common'] - cur['cache']}")
            cur = None
    return 0

def txjudge(f):
    """Request G TX burst-exclusion verdict from the five txonly phases (+ mbuf pool states)."""
    P = {}; M = []
    for ln in open(f):
        m = re.match(r"TXPHASE (\S+) (.*)", ln.strip())
        if m: P[m.group(1)] = {k: v for k, v in (x.split("=", 1) for x in m.group(2).split())}
        m = re.match(r"TXMEM idx=(\d+) size=(\d+) avail=(\d+) in_use=(-?\d+)", ln.strip())
        if m: M.append(tuple(int(x) for x in m.groups()))
    def g(p, k):
        try: return int(P[p][k])
        except Exception: return -1
    bad = []
    def chk(c, msg):
        if not c: bad.append(msg)
    for p in P:
        chk(g(p, "err_cqe_dumps") == 0 and g(p, "err_cqe_dumps_tracewin") == 0, f"{p}: mlx5 error-CQE dumps")
        chk(g(p, "strace_ok") >= 1, f"{p}: syscall tracer not attached")
        chk(g(p, "process_vm_writev") == 0 and g(p, "bpf") == 0 and g(p, "lcore_syscalls") == 0, f"{p}: syscalls on the TX lcore ({P[p].get('lcore_syscalls')})")
        if p == "P7_PARTIAL_RETURN": chk(g(p, "app_short_ret") > 0, f"{p}: no partial PMD return was provoked")
        else: chk(g(p, "app_short_ret") == 0, f"{p}: app saw a short tx_burst return ({P[p].get('app_short_ret')})")
    for p in ("P1_ALL_DROP", "P4_ALL_DROP_AGAIN"):
        if p in P:
            chk(g(p, "peer_rx") <= 10 and g(p, "pmd_tx") == 0 and g(p, "filt_allow") == 0 and g(p, "filt_drop") > 100000, f"{p}: all-drop")
    for p in ("P2_ALL_ALLOW", "P5_ALLOW_AFTER_DROP"):
        if p in P:
            chk(g(p, "filt_drop") == 0 and g(p, "filt_allow") > 100000 and g(p, "peer_rx") >= 0.99 * g(p, "pmd_tx") and g(p, "pmd_tx") >= 0.99 * g(p, "filt_allow")
                and g(p, "peer_v0") > 0 and g(p, "peer_v1") > 0, f"{p}: all-allow delivery")
    for p in [x for x in ("P3_MIXED", "P6_MIXED_BURST64") if x in P]:
        a, d = g(p, "filt_allow"), g(p, "filt_drop")
        chk(a > 100000 and abs(a - d) <= max(64, a // 100), f"{p}: verdict split {a}/{d}")
        chk(g(p, "pmd_tx") >= 0.99 * a and g(p, "pmd_tx") <= a + 64 and g(p, "peer_rx") >= 0.99 * g(p, "pmd_tx"), f"{p}: only allowed packets reach PMD/peer")
        chk(g(p, "peer_v0") > 0 and g(p, "peer_v1") == 0, f"{p}: per-source peer counters v0={P[p].get('peer_v0')} v1={P[p].get('peer_v1')}")
    p = "P7_PARTIAL_RETURN"
    if p in P:   # PMD takes fewer than offered: caller keeps (and frees) the unsent allowed packets
        a, d = g(p, "filt_allow"), g(p, "filt_drop")
        chk(a > 10000 and abs(a - d) <= max(64, a // 100), f"{p}: verdict split {a}/{d}")
        chk(g(p, "pmd_tx") <= a + 64, f"{p}: PMD took more than the allowed packets")
        chk(g(p, "peer_v1") == 0, f"{p}: dropped source reached the peer")
    chk(len(M) >= len(P) + 1, f"mbuf pool dumps found={len(M)} expected>={len(P) + 1}")
    chk(all(0 <= iu <= size // 2 and av <= size for _, size, av, iu in M), f"mbuf pool in_use per dump {[x[3] for x in M]}")
    for b_ in bad: print("FAIL " + b_)
    s = " ; ".join(f"{p}: peer={P[p].get('peer_rx')} pmd={P[p].get('pmd_tx')} app_ret={P[p].get('app_ret')} short={P[p].get('app_short_ret')} allow/drop={P[p].get('filt_allow')}/{P[p].get('filt_drop')} v0/v1={P[p].get('peer_v0')}/{P[p].get('peer_v1')} cqe={P[p].get('err_cqe_dumps')} sys={P[p].get('lcore_syscalls')}" for p in P)
    print(f"TXJUDGE {'PASS' if not bad else 'FAIL'} :: {s} ; mbuf_in_use={[x[3] for x in M]}/{M[0][1] if M else '?'}")
    return 0 if not bad else 1

def rxapp(logf):
    """Request H: per RX phase, the app-visible result (sum of rx_burst returns, burst-size stats) from the first
    'Forward statistics' block after the k-th dump_mempool, and the pool state at each dump."""
    L = open(logf, errors="replace").read().splitlines()
    dumps = []; i = 0
    while i < len(L):
        if re.search(r"mempool <mb_pool_\d+>@", L[i]):
            d = {"line": i, "size": None, "common": None, "cache": None}
            j = i + 1
            while j < len(L) and j < i + 600 and None in (d["size"], d["common"], d["cache"]):
                for key, pat in (("size", r"^\s*size=(\d+)"), ("common", r"common_pool_count=(\d+)"), ("cache", r"total_cache_count=(\d+)")):
                    mm = re.search(pat, L[j])
                    if mm and d[key] is None: d[key] = int(mm.group(1))
                j += 1
            dumps.append(d); i = j; continue
        i += 1
    for k, d in enumerate(dumps):
        app = bursts = None
        end = dumps[k + 1]["line"] if k + 1 < len(dumps) else len(L)
        for j in range(d["line"], end):
            if app is None and "Forward statistics for port 0" in L[j]:
                for jj in range(j, min(j + 6, len(L))):
                    m = re.search(r"RX-packets:\s*(\d+)", L[jj])
                    if m and app is None: app = int(m.group(1))
                    m = re.search(r"RX-bursts\s*:\s*(\d+)\s*\[(.*)\]", L[jj])
                    if m and bursts is None: bursts = m.group(2).replace(" ", "_")
                break
        iu = d["size"] - d["common"] - d["cache"] if None not in (d["size"], d["common"], d["cache"]) else -1
        print(f"RXAPP idx={k} app_rx={app if app is not None else -1} bursts={bursts or 'NA'} size={d['size']} avail={(d['common'] or 0) + (d['cache'] or 0)} in_use={iu}")
    return 0

def rxjudge(f):
    """Request H RX window-exclusion verdict."""
    P = []; A = {}
    for ln in open(f):
        m = re.match(r"RXPHASE (\S+) (.*)", ln.strip())
        if m: P.append((m.group(1), {k: v for k, v in (x.split("=", 1) for x in m.group(2).split())}))
        m = re.match(r"RXAPP idx=(\d+) (.*)", ln.strip())
        if m: A[int(m.group(1))] = {k: v for k, v in (x.split("=", 1) for x in m.group(2).split())}
    def gi(d, k):
        try: return int(d[k])
        except Exception: return -1
    bad = []
    def chk(c, msg):
        if not c: bad.append(msg)
    out = []
    for k, (nm, d) in enumerate(P):
        a = A.get(k, {}); app = gi(d, "app_rx")      # dispatcher return values (bpftrace), not the ethdev counter
        rx, al, dr, pmd = gi(d, "filt_rx"), gi(d, "filt_allow"), gi(d, "filt_drop"), gi(d, "pmd_rx")
        chk(gi(d, "strace_ok") >= 1, f"{nm}: syscall tracer not attached")
        chk(gi(d, "lcore_syscalls") == 0 and gi(d, "process_vm_writev") == 0 and gi(d, "bpf") == 0, f"{nm}: syscalls on the RX lcore ({d.get('lcore_syscalls')}, pvw={d.get('process_vm_writev')})")
        chk(gi(d, "rx_nombuf") == 0, f"{nm}: rx_nombuf={d.get('rx_nombuf')} (mbuf exhaustion)")
        chk(abs(rx - pmd) <= 16, f"{nm}: inspected {rx} != received by the PMD {pmd}")
        chk(abs(al + dr - rx) <= 16, f"{nm}: allow+drop {al}+{dr} != inspected {rx}")
        chk(app == al, f"{nm}: app received {app} != allowed {al}")
        if "ALL_DROP" in nm: chk(al == 0 and pmd > 100000 and app == 0, f"{nm}: all-drop")
        if "ALL_ALLOW" in nm: chk(dr == 0 and pmd > 100000 and app == pmd, f"{nm}: all-allow")
        if "MIXED" in nm: chk(al > 100000 and abs(al - dr) <= max(64, al // 100), f"{nm}: verdict split {al}/{dr}")
        b = gi(d, "burst")
        if b > 32: chk(gi(d, "max_windows_per_call") >= 2, f"{nm}: no call with more than one 32-packet window (max={d.get('max_windows_per_call')})")
        out.append(f"{nm}(b{b}): pmd={pmd} inspected={rx} allow/drop={al}/{dr} app={app} max_windows/call={d.get('max_windows_per_call')} app_bursts={a.get('bursts')} sys={d.get('lcore_syscalls')} nombuf={d.get('rx_nombuf')}")
    iu = [(gi(a, "in_use"), gi(a, "size"), gi(a, "avail")) for _, a in sorted(A.items())]
    chk(len(A) >= len(P) + 1 and all(0 <= x <= s // 2 and av <= s for x, s, av in iu), f"mbuf pool in_use per dump {[x[0] for x in iu]}")
    for x in bad: print("FAIL " + x)
    print(f"RXJUDGE {'PASS' if not bad else 'FAIL'} :: " + " ; ".join(out) + f" ; mbuf_in_use={[x[0] for x in iu]}")
    return 0 if not bad else 1

def droprange(f, addr):
    a = int(addr, 16); out = []; dropped = None
    for ln in open(f):
        p = ln.split()
        if len(p) >= 2 and int(p[0], 16) <= a < int(p[1], 16) and dropped is None: dropped = ln.strip(); continue
        out.append(ln)
    open(f, "w").write("".join(out)); print(f"FAIL_INJECT range_drop removed: {dropped}"); return 0 if dropped else 1

if __name__ == "__main__":
    c = sys.argv[1]
    if c == "libtrust": sys.exit(libtrust(sys.argv[2], sys.argv[3], sys.argv[4]))
    if c == "mergeranges": sys.exit(mergeranges(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]))
    if c == "timeline": sys.exit(timeline(sys.argv[2], sys.argv[3], sys.argv[4]))
    if c == "rangecheck": sys.exit(rangecheck(sys.argv[2], sys.argv[3]))
    if c == "aliasops": sys.exit(aliasops(sys.argv[2]))
    if c == "alias": sys.exit(alias(sys.argv[2], sys.argv[3:]))
    if c == "order": sys.exit(order(sys.argv[2]))
    if c == "maptrust": sys.exit(maptrust(sys.argv[2], sys.argv[3]))
    if c == "exetrust": sys.exit(exetrust(sys.argv[2]))
    if c == "coverage": sys.exit(coverage(*sys.argv[2:9]))
    if c == "droprange": sys.exit(droprange(sys.argv[2], sys.argv[3]))
    if c == "txjudge": sys.exit(txjudge(sys.argv[2]))
    if c == "tele": sys.exit(tele(sys.argv[2], *sys.argv[3:]))
    if c == "txmem": sys.exit(txmem(sys.argv[2]))
    if c == "rxapp": sys.exit(rxapp(sys.argv[2]))
    if c == "rxjudge": sys.exit(rxjudge(sys.argv[2]))
    sys.exit(2)
