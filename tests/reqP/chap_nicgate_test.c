// Chaperon Request P -- TEST-ONLY tenant-side driver (never part of a normal launch). Preloaded into the tenant only
// when the harness runs NICJ tests (CHAP_NICJ_TEST=1); otherwise inert. A thread "chap-nicj" waits for command lines in
// /tmp/chap_nicj_cmd_<pid> (written by the Manager after GO) and acts INSIDE the sealed tenant process:
//   thread_open                 new pthread: ibv_open_device + alloc_pd + create_cq + query_port on the tenant's RDMA dev
//   fork_open HOLD_S            fork; the child does the same, holds HOLD_S s (Manager inspects it), releases, exits
//   execfail_open               fork; the child's exec of a missing file fails; the child then does the open sequence
//   fork_exec PATH ARGS...      fork; the child execs PATH with a CLEAN environment (no LD_PRELOAD/agent variables)
//   fdopen_exec PATH ARGS...    open the uverbs node WITHOUT O_CLOEXEC as fd 50 (sealed: allowed), then fork_exec
//   scm_exec PATH ARGS...       socketpair 60/61 + uverbs fd 50 (O_CLOEXEC) sent over 60, then fork_exec (child reads 61)
//   madv ADDR LEN ADVICE        madvise(ADDR, LEN, ADVICE) on a protected range (DONTFORK=10/WIPEONFORK=18: tenant killed)
// Request Q: vfork_exec / vfork_exit / clonevm_open HOLD / thread_exec_child PATH.. / leader_exit_child HOLD /
//   execfail_eacces / ioctl32_self / opendev IBDEV / passfd_out SOCKPATH / evfd_exec PATH.. / rawqp_tx DSTMAC N /
//   fork_storm N  (see run(); every exec'd image gets the tenant's XDG_RUNTIME_DIR and a clean environment)
// Results (one write per line): $CHAP_NICJ_DIR/nicj_out.txt
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <infiniband/verbs.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <sys/io.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static char g_out[512], g_cmd[128], g_dev[64];
static void out(const char *fmt, ...)
{ char b[768]; va_list a; va_start(a, fmt); int n = vsnprintf(b, sizeof b, fmt, a); va_end(a);
  int fd = open(g_out, O_WRONLY | O_CREAT | O_APPEND, 0644); if (fd >= 0) { if (write(fd, b, n) < 0) {} close(fd); } }

static int open_seq(const char *who)
{
    int num = 0; struct ibv_device **l = ibv_get_device_list(&num), *d = NULL;
    for (int i = 0; l && i < num; i++) if (!strcmp(ibv_get_device_name(l[i]), g_dev)) d = l[i];
    if (!d) { out("%s pid=%d OPEN FAIL no device %s\n", who, getpid(), g_dev); return 1; }
    struct ibv_context *c = ibv_open_device(d);
    if (!c) { out("%s pid=%d OPEN FAIL open_device errno=%d\n", who, getpid(), errno); return 1; }
    struct ibv_pd *pd = ibv_alloc_pd(c); struct ibv_cq *cq = pd ? ibv_create_cq(c, 16, NULL, NULL, 0) : NULL;
    struct ibv_port_attr pa; int qp = ibv_query_port(c, 1, &pa);
    out("%s pid=%d OPEN %s open_device=ok cmd_fd=%d pd=%s cq=%s query_port=%s\n", who, getpid(), (pd && cq && !qp) ? "ok" : "FAIL",
        c->cmd_fd, pd ? "ok" : "fail", cq ? "ok" : "fail", qp ? "fail" : "ok");
    if (cq) ibv_destroy_cq(cq); if (pd) ibv_dealloc_pd(pd); ibv_close_device(c); ibv_free_device_list(l);
    return (pd && cq && !qp) ? 0 : 1;
}
static void *thr(void *a) { (void)a; open_seq("THREAD"); return NULL; }

static void uverbs_path(char *o, size_t n)
{ char p[256]; snprintf(p, sizeof p, "/sys/class/infiniband/%s/device/infiniband_verbs", g_dev);
  DIR *d = opendir(p); struct dirent *e; char nm[64] = "";
  while (d && (e = readdir(d))) if (!strncmp(e->d_name, "uverbs", 6)) { snprintf(nm, sizeof nm, "%.60s", e->d_name); break; }
  if (d) closedir(d); snprintf(o, n, "/dev/infiniband/%s", nm); }

static char g_dir[400];
static void child_exec(char **argv)
{   /* a newly executed program starts WITHOUT the agent: clean environment, stdin /dev/null (never the tenant's
       command FIFO), stdout/stderr -> $CHAP_NICJ_DIR/nicj_child_<pid>.log */
    static char xdg[300]; const char *x = getenv("XDG_RUNTIME_DIR"); snprintf(xdg, sizeof xdg, "XDG_RUNTIME_DIR=%s", x ? x : "/var/tmp/chap_dpdkrun");
    char *env[] = {"PATH=/usr/local/bin:/usr/bin:/bin", xdg, NULL};
    char lp[512]; snprintf(lp, sizeof lp, "%s/nicj_child_%d.log", g_dir, getpid());
    int n = open("/dev/null", O_RDONLY), l = open(lp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (n >= 0) { dup2(n, 0); close(n); } if (l >= 0) { dup2(l, 1); dup2(l, 2); close(l); }
    execve(argv[0], argv, env);
    out("EXECFAIL %s errno=%d\n", argv[0], errno); _exit(127);
}
static void report(const char *what, pid_t c)
{ int st = 0; waitpid(c, &st, 0);
  if (WIFEXITED(st)) out("%s child=%d EXIT %d\n", what, c, WEXITSTATUS(st));
  else if (WIFSIGNALED(st)) out("%s child=%d SIGNAL %d\n", what, c, WTERMSIG(st)); }

/* ---- Request Q helpers ---- */
static char g_uvp[300];                                 /* uverbs node of the tenant device (resolved before clone) */
static int g_cv_hold;
static char g_cv_stack[256 * 1024] __attribute__((aligned(16)));
static int cv_child(void *a)
{   /* CLONE_VM child: shares the sealed address space; raw syscalls only */
    (void)a; int fd = open(g_uvp, O_RDWR), e = fd < 0 ? errno : 0;
    out("CLONEVM child pid=%ld open_fd=%d errno=%d\n", (long)syscall(SYS_getpid), fd, e);
    if (fd >= 0) close(fd);
    sleep(g_cv_hold); syscall(SYS_exit_group, fd >= 0 ? 0 : 1); return 0;
}
static char **g_texec_argv;
static void *texec(void *a) { (void)a; child_exec(g_texec_argv); return NULL; }   /* exec from a NON-leader thread */
static int g_lt_hold;
static void *lthr(void *a)
{   /* the leader has already called pthread_exit(); this thread keeps the process alive and uses the NIC */
    (void)a; sleep(1); out("LTHREAD pid=%d tid=%ld leader_gone\n", getpid(), (long)syscall(SYS_gettid));
    int r = open_seq("LTHREAD"); sleep(g_lt_hold); _exit(r);
}
static long ia32_ioctl(int fd, unsigned long cmd)
{ long r; __asm__ volatile("int $0x80" : "=a"(r) : "a"(54L), "b"((long)fd), "c"((long)cmd), "d"(0L) : "memory", "r8", "r9", "r10", "r11"); return r; }
static int parse_mac(const char *s, unsigned char *m) { return sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", m, m+1, m+2, m+3, m+4, m+5) == 6 ? 0 : -1; }
static void netpaths(const char *cmac)
{   /* IN the sealed process: which interfaces exist, and can it reach the NIC through the kernel network stack? */
    struct if_nameindex *ni = if_nameindex(); char lst[512] = "";
    for (struct if_nameindex *p = ni; p && p->if_index; p++) { strncat(lst, p->if_name, sizeof lst - strlen(lst) - 2); strcat(lst, " "); }
    out("NETPATHS pid=%d visible_ifs=[%s] netns=%s\n", getpid(), lst, ({ static char l[64]; ssize_t n = readlink("/proc/self/ns/net", l, 63); l[n > 0 ? n : 0] = 0; l; }));
    unsigned char fr[64] = {0}; parse_mac(cmac, fr); fr[12] = 0x88; fr[13] = 0xb5; snprintf((char *)fr + 14, 40, "CHAPQ-SAFP-%d", getpid());
    for (struct if_nameindex *p = ni; p && p->if_index; p++) {
        if (!strcmp(p->if_name, "lo")) continue;
        int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)), es = s < 0 ? errno : 0, ok = 0, e = 0;
        struct sockaddr_ll a = { .sll_family = AF_PACKET, .sll_ifindex = (int)p->if_index, .sll_halen = 6 }; memcpy(a.sll_addr, fr, 6);
        for (int i = 0; s >= 0 && i < 10; i++) { if (sendto(s, fr, 60, 0, (struct sockaddr *)&a, sizeof a) > 0) ok++; else e = errno; }
        int u = socket(AF_INET, SOCK_DGRAM, 0), on = 1, uok = 0, ue = 0; setsockopt(u, SOL_SOCKET, SO_BROADCAST, &on, sizeof on);
        struct sockaddr_in d = { .sin_family = AF_INET, .sin_port = htons(47999) }; d.sin_addr.s_addr = htonl(INADDR_BROADCAST); char pl[40]; snprintf(pl, sizeof pl, "CHAPQ-SUDP-%d", getpid());
        for (int i = 0; i < 10; i++) { char cb[CMSG_SPACE(sizeof(struct in_pktinfo))] = {0}; struct iovec io = { pl, strlen(pl) };
            struct msghdr m = { .msg_name = &d, .msg_namelen = sizeof d, .msg_iov = &io, .msg_iovlen = 1, .msg_control = cb, .msg_controllen = sizeof cb };
            struct cmsghdr *c = CMSG_FIRSTHDR(&m); c->cmsg_level = IPPROTO_IP; c->cmsg_type = IP_PKTINFO; c->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo)); ((struct in_pktinfo *)CMSG_DATA(c))->ipi_ifindex = (int)p->if_index;
            if (sendmsg(u, &m, 0) > 0) uok++; else ue = errno; }
        struct ifreq q = {0}; snprintf(q.ifr_name, IFNAMSIZ, "%s", p->if_name); ioctl(u, SIOCGIFFLAGS, &q); short f0 = q.ifr_flags; q.ifr_flags |= IFF_UP;
        int ru = ioctl(u, SIOCSIFFLAGS, &q), eu = ru ? errno : 0;
        out("NETPATHS if=%s afpacket socket=%d errno=%d sent=%d/10 last_errno=%d | udp_pktinfo sent=%d/10 last_errno=%d | flags=0x%x set_up=%d errno=%d\n", p->if_name, s, es, ok, e, uok, ue, f0, ru, eu);
        if (s >= 0) close(s); close(u);
    }
    const char *host[] = {"eth0", "eth1", "enp59s0f1np1", "enp59s0f1v1", "eno1"}; char hl[256] = "";
    for (unsigned i = 0; i < sizeof host / sizeof host[0]; i++) { char t[48]; snprintf(t, sizeof t, "%s:%u ", host[i], if_nametoindex(host[i])); strcat(hl, t); }
    int rp = ioperm(0xcf8, 8, 1), ep = rp ? errno : 0; if (!rp) ioperm(0xcf8, 8, 0);   /* permission checks only, no port access */
    int ri = iopl(3), ei = ri ? errno : 0; if (!ri) iopl(0);
    int pf = open("/proc/bus/pci/3b/01.3", O_RDONLY), epf = pf < 0 ? errno : 0; if (pf >= 0) close(pf);
    int r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)), peer = 0, any = 0; time_t end = time(0) + 4;
    while (r >= 0 && time(0) < end) { struct pollfd pp = { r, POLLIN, 0 }; if (poll(&pp, 1, 200) <= 0) continue; unsigned char b[2048]; ssize_t n = recv(r, b, sizeof b, 0); if (n <= 0) continue; any++; if (memmem(b, n, "CHAPQ-PEER", 10)) peer++; }
    out("NETPATHS host_ifindex(0=absent)=[%s] ioperm=%d errno=%d iopl=%d errno=%d /proc/bus/pci/3b/01.3 open=%d errno=%d | afpacket_rx_4s any=%d from_peer=%d\n", hl, rp, ep, ri, ei, pf, epf, any, peer);
    if (r >= 0) close(r); if (ni) if_freenameindex(ni);
}
static struct ibv_context *open_ctx(const char *dev)
{ int num = 0; struct ibv_device **l = ibv_get_device_list(&num), *d = NULL; struct ibv_context *c = NULL;
  for (int i = 0; l && i < num; i++) if (!strcmp(ibv_get_device_name(l[i]), dev)) d = l[i];
  if (d) c = ibv_open_device(d); if (l) ibv_free_device_list(l); return c; }
static void rawqp_tx(const char *dmac, int n)
{   /* application code of the SEALED process programs its own NIC queue directly through verbs (no PMD burst call) */
    struct ibv_context *c = open_ctx(g_dev); struct ibv_pd *pd = c ? ibv_alloc_pd(c) : NULL; struct ibv_cq *cq = pd ? ibv_create_cq(c, 64, NULL, NULL, 0) : NULL;
    struct ibv_qp_init_attr qa = { .send_cq = cq, .recv_cq = cq, .qp_type = IBV_QPT_RAW_PACKET, .cap = { .max_send_wr = 64, .max_recv_wr = 1, .max_send_sge = 1, .max_recv_sge = 1 } };
    struct ibv_qp *qp = cq ? ibv_create_qp(pd, &qa) : NULL; int e_qp = qp ? 0 : errno, m1 = -1, m2 = -1, m3 = -1;
    if (qp) { struct ibv_qp_attr at = { .qp_state = IBV_QPS_INIT, .port_num = 1 }; m1 = ibv_modify_qp(qp, &at, IBV_QP_STATE | IBV_QP_PORT);
              at.qp_state = IBV_QPS_RTR; m2 = ibv_modify_qp(qp, &at, IBV_QP_STATE); at.qp_state = IBV_QPS_RTS; m3 = ibv_modify_qp(qp, &at, IBV_QP_STATE); }
    static unsigned char buf[128] __attribute__((aligned(64))); memset(buf, 0, sizeof buf); parse_mac(dmac, buf);
    unsigned char sm[6] = {0x02, 0x51, 0, 0, 0, 0x01}; memcpy(buf + 6, sm, 6); buf[12] = 0x88; buf[13] = 0xb5; snprintf((char *)buf + 14, 64, "CHAPQ-RAWQP-%d", getpid());
    struct ibv_mr *mr = qp ? ibv_reg_mr(pd, buf, sizeof buf, IBV_ACCESS_LOCAL_WRITE) : NULL; int posted = 0, done = 0;
    for (int i = 0; mr && !m1 && !m2 && !m3 && i < n; i++) {
        struct ibv_sge sg = { .addr = (uintptr_t)buf, .length = 64, .lkey = mr->lkey }; struct ibv_send_wr wr = { .wr_id = i, .sg_list = &sg, .num_sge = 1, .opcode = IBV_WR_SEND, .send_flags = IBV_SEND_SIGNALED }, *bad;
        if (ibv_post_send(qp, &wr, &bad)) break; posted++;
        struct ibv_wc wc; for (int k = 0; k < 1000000; k++) { int r = ibv_poll_cq(cq, 1, &wc); if (r > 0) { if (wc.status == IBV_WC_SUCCESS) done++; break; } }
        usleep(1000);
    }
    out("RAWQP pid=%d ctx=%s qp=%s errno=%d modify=%d/%d/%d mr=%s posted=%d completed_ok=%d\n", getpid(), c ? "ok" : "FAIL", qp ? "ok" : "FAIL", e_qp, m1, m2, m3, mr ? "ok" : "FAIL", posted, done);
}

static void run(char *line)
{
    char *argv[32], *sv_; int argc = 0;
    for (char *t = strtok_r(line, " ", &sv_); t && argc < 31; t = strtok_r(NULL, " ", &sv_)) argv[argc++] = t;
    argv[argc] = NULL; if (!argc) return;
    out("CMD %s\n", argv[0]);
    if (!strcmp(argv[0], "thread_open")) { pthread_t t; pthread_create(&t, NULL, thr, NULL); pthread_join(t, NULL); }
    else if (!strcmp(argv[0], "fork_open") && argc > 1) {
        int hold = atoi(argv[1]); pid_t c = fork();
        if (c == 0) { out("CHILD pid=%d ppid=%d\n", getpid(), getppid()); int r = open_seq("CHILD"); sleep(hold); _exit(r); }
        report("FORK_OPEN", c);
    }
    else if (!strcmp(argv[0], "execfail_open")) {
        pid_t c = fork();
        if (c == 0) { char *a[] = {"/nonexistent/chap_reqP", NULL}; execv(a[0], a);
                      out("EXECFAIL_CHILD pid=%d errno=%d continues\n", getpid(), errno); _exit(open_seq("EXECFAIL_CHILD")); }
        report("EXECFAIL_OPEN", c);
    }
    else if (!strcmp(argv[0], "fork_exec") && argc > 1) { pid_t c = fork(); if (c == 0) child_exec(&argv[1]); out("FORK_EXEC child=%d path=%s\n", c, argv[1]); report("FORK_EXEC", c); }
    else if (!strcmp(argv[0], "fdopen_exec") && argc > 1) {
        char p[300]; uverbs_path(p, sizeof p); int fd = open(p, O_RDWR);
        if (fd >= 0 && fd != 50) { dup2(fd, 50); close(fd); fd = 50; }
        out("FDOPEN path=%s fd=%d errno=%d cloexec=0\n", p, fd, fd < 0 ? errno : 0);
        pid_t c = fork(); if (c == 0) child_exec(&argv[1]); out("FDOPEN_EXEC child=%d\n", c); report("FDOPEN_EXEC", c); close(50);
    }
    else if (!strcmp(argv[0], "scm_exec") && argc > 1) {
        int sv[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sv); dup2(sv[0], 60); dup2(sv[1], 61); close(sv[0]); close(sv[1]);
        char p[300]; uverbs_path(p, sizeof p); int fd = open(p, O_RDWR | O_CLOEXEC);
        if (fd >= 0 && fd != 50) { dup3(fd, 50, O_CLOEXEC); close(fd); fd = 50; }
        char ch = 'x'; struct iovec io = {&ch, 1}; char cb[CMSG_SPACE(sizeof(int))]; struct msghdr m = {0};
        m.msg_iov = &io; m.msg_iovlen = 1; m.msg_control = cb; m.msg_controllen = sizeof cb;
        struct cmsghdr *h = CMSG_FIRSTHDR(&m); h->cmsg_level = SOL_SOCKET; h->cmsg_type = SCM_RIGHTS; h->cmsg_len = CMSG_LEN(sizeof(int)); memcpy(CMSG_DATA(h), &fd, sizeof(int));
        out("SCM sent fd=%d over 60 r=%zd (uverbs fd O_CLOEXEC)\n", fd, sendmsg(60, &m, 0));
        pid_t c = fork(); if (c == 0) child_exec(&argv[1]); out("SCM_EXEC child=%d\n", c); report("SCM_EXEC", c); close(50); close(60); close(61);
    }
    else if (!strcmp(argv[0], "madv") && argc > 3) {
        unsigned long a = strtoul(argv[1], 0, 16), l = strtoul(argv[2], 0, 0); int adv = atoi(argv[3]);
        out("MADV begin addr=0x%lx len=%lu advice=%d\n", a, l, adv);
        int r = madvise((void *)a, l, adv);
        out("MADV ret=%d errno=%d (tenant still alive)\n", r, r ? errno : 0);
    }
    /* ---- Request Q ---- */
    else if (!strcmp(argv[0], "vfork_exec") && argc > 1) { pid_t c = vfork(); if (c == 0) child_exec(&argv[1]); out("VFORK_EXEC child=%d\n", c); report("VFORK_EXEC", c); }
    else if (!strcmp(argv[0], "vfork_exit")) { pid_t c = vfork(); if (c == 0) _exit(0); out("VFORK_EXIT child=%d\n", c); report("VFORK_EXIT", c); }
    else if (!strcmp(argv[0], "clonevm_open") && argc > 1) {
        uverbs_path(g_uvp, sizeof g_uvp); g_cv_hold = atoi(argv[1]);
        pid_t c = clone(cv_child, g_cv_stack + sizeof g_cv_stack, CLONE_VM | SIGCHLD, NULL);
        out("CLONEVM parent child=%d\n", c); report("CLONEVM", c);
    }
    else if (!strcmp(argv[0], "thread_exec_child") && argc > 1) {   /* child: fd 50 (no CLOEXEC), then a non-leader thread execs */
        pid_t c = fork();
        if (c == 0) { char p[300]; uverbs_path(p, sizeof p); int fd = open(p, O_RDWR); if (fd >= 0 && fd != 50) { dup2(fd, 50); close(fd); }
                      out("TEXEC child=%d fd50=%d\n", getpid(), fd); g_texec_argv = &argv[1]; pthread_t t; pthread_create(&t, NULL, texec, NULL); pthread_join(t, NULL); _exit(126); }
        report("TEXEC", c);
    }
    else if (!strcmp(argv[0], "leader_exit_child") && argc > 1) {
        g_lt_hold = atoi(argv[1]); pid_t c = fork();
        if (c == 0) { pthread_t t; pthread_create(&t, NULL, lthr, NULL); out("LEADER pid=%d pthread_exit first\n", getpid()); pthread_exit(NULL); }
        report("LEADER_EXIT", c);
    }
    else if (!strcmp(argv[0], "execfail_eacces")) {
        pid_t c = fork();
        if (c == 0) { char *a[] = {"/etc/hostname", NULL}; execv(a[0], a); out("EXECFAIL2_CHILD pid=%d errno=%d continues\n", getpid(), errno); _exit(open_seq("EXECFAIL2_CHILD")); }
        report("EXECFAIL2", c);
    }
    else if (!strcmp(argv[0], "ioctl32_self")) {
        char p[300]; uverbs_path(p, sizeof p); int fd = open(p, O_RDWR | O_CLOEXEC); long r = fd >= 0 ? ia32_ioctl(fd, 0xc0181b01UL) : -999;
        out("IOCTL32_SELF pid=%d fd=%d ret=%ld (sealed: allowed by the gate; the uverbs handler decides the result)\n", getpid(), fd, r); if (fd >= 0) close(fd);
    }
    else if (!strcmp(argv[0], "fork_opendev") && argc > 1) {   /* a sealed child opens ANOTHER VF's RDMA device */
        pid_t c = fork();
        if (c == 0) { snprintf(g_dev, sizeof g_dev, "%s", argv[1]); out("OPENDEV_CHILD pid=%d dev=%s\n", getpid(), g_dev); _exit(open_seq("OPENDEV_CHILD")); }
        report("FORK_OPENDEV", c);
    }
    else if (!strcmp(argv[0], "opendev") && argc > 1) { char sv[64]; snprintf(sv, sizeof sv, "%s", g_dev); snprintf(g_dev, sizeof g_dev, "%s", argv[1]); open_seq("OPENDEV"); snprintf(g_dev, sizeof g_dev, "%s", sv); }
    else if (!strcmp(argv[0], "passfd_out") && argc > 1) {   /* send the uverbs cmd fd of a context to a process OUTSIDE the cgroup */
        struct ibv_context *c = open_ctx(g_dev); int s = socket(AF_UNIX, SOCK_STREAM, 0); struct sockaddr_un a = { .sun_family = AF_UNIX };
        snprintf(a.sun_path, sizeof a.sun_path, "%s", argv[1]); int cr = connect(s, (struct sockaddr *)&a, sizeof a), fd = c ? c->cmd_fd : -1;
        char ch = 'x'; struct iovec io = {&ch, 1}; char cb[CMSG_SPACE(sizeof(int))]; struct msghdr m = {0};
        m.msg_iov = &io; m.msg_iovlen = 1; m.msg_control = cb; m.msg_controllen = sizeof cb;
        struct cmsghdr *h = CMSG_FIRSTHDR(&m); h->cmsg_level = SOL_SOCKET; h->cmsg_type = SCM_RIGHTS; h->cmsg_len = CMSG_LEN(sizeof(int)); memcpy(CMSG_DATA(h), &fd, sizeof(int));
        ssize_t r = cr == 0 && fd >= 0 ? sendmsg(s, &m, 0) : -1; out("PASSFD_OUT ctx=%s cmd_fd=%d connect=%d sent=%zd\n", c ? "ok" : "FAIL", fd, cr, r); close(s);
    }
    else if (!strcmp(argv[0], "evfd_exec") && argc > 1) {   /* async-event and completion-channel fds inherited by an exec'd image */
        struct ibv_context *c = open_ctx(g_dev); struct ibv_comp_channel *ch = c ? ibv_create_comp_channel(c) : NULL;
        if (c) dup2(c->async_fd, 52); if (ch) dup2(ch->fd, 53); out("EVFD async_fd=%d channel_fd=%d -> 52,53\n", c ? c->async_fd : -1, ch ? ch->fd : -1);
        pid_t k = fork(); if (k == 0) child_exec(&argv[1]); out("EVFD_EXEC child=%d\n", k); report("EVFD_EXEC", k); close(52); close(53);
    }
    else if (!strcmp(argv[0], "rawqp_tx") && argc > 2) rawqp_tx(argv[1], atoi(argv[2]));
    else if (!strcmp(argv[0], "netpaths") && argc > 1) netpaths(argv[1]);
    else if (!strcmp(argv[0], "nnp_child") && argc > 1) {   /* forked child (no exec): NO_NEW_PRIVS/seccomp/caps inherited? */
        int hold = atoi(argv[1]); pid_t c = fork(); if (c == 0) { out("NNPCHILD pid=%d\n", getpid()); sleep(hold); _exit(0); } report("NNPCHILD", c);
    }
    else if (!strcmp(argv[0], "fork_storm") && argc > 1) {   /* concurrent sealed children (open + exit) */
        int n = atoi(argv[1]); if (n > 256) n = 256; pid_t k[256]; uverbs_path(g_uvp, sizeof g_uvp);
        for (int i = 0; i < n; i++) { k[i] = fork(); if (k[i] == 0) { int fd = open(g_uvp, O_RDWR | O_CLOEXEC); out("STORM child=%d open=%d\n", getpid(), fd); if (fd >= 0) close(fd); usleep(300000); _exit(fd >= 0 ? 0 : 1); } }
        int ok = 0, kill9 = 0, oth = 0; for (int i = 0; i < n; i++) { int st = 0; waitpid(k[i], &st, 0); if (WIFEXITED(st) && !WEXITSTATUS(st)) ok++; else if (WIFSIGNALED(st) && WTERMSIG(st) == 9) kill9++; else oth++; }
        out("STORM done n=%d ok=%d killed=%d other=%d\n", n, ok, kill9, oth);
    }
    out("DONE %s\n", argv[0]);
}

static void *driver(void *a)
{
    (void)a;   /* the command file is root-owned (append-only for the Manager): consume complete lines by offset */
    off_t done = 0; char b[4096];
    for (;;) {
        int fd = open(g_cmd, O_RDONLY);
        if (fd >= 0) {
            off_t sz = lseek(fd, 0, SEEK_END);
            if (sz > done) {
                lseek(fd, done, SEEK_SET); ssize_t n = read(fd, b, sizeof b - 1);
                if (n > 0) { b[n] = 0; char *e = strrchr(b, '\n');
                    if (e) { *e = 0; done += (e - b) + 1; char *sl;
                             for (char *l = strtok_r(b, "\n", &sl); l; l = strtok_r(NULL, "\n", &sl)) run(l); } }
            }
            close(fd);
        }
        usleep(100000);
    }
    return NULL;
}

__attribute__((constructor)) static void chap_nicj_init(void)
{
    const char *on = getenv("CHAP_NICJ_TEST"); if (!on || strcmp(on, "1")) return;
    const char *dir = getenv("CHAP_NICJ_DIR"); if (!dir) dir = "/tmp"; snprintf(g_dir, sizeof g_dir, "%s", dir);
    const char *dev = getenv("CHAP_NICJ_IBDEV"); snprintf(g_dev, sizeof g_dev, "%s", dev ? dev : "");
    snprintf(g_out, sizeof g_out, "%s/nicj_out.txt", dir); snprintf(g_cmd, sizeof g_cmd, "/tmp/chap_nicj_cmd_%d", (int)getpid());
    pthread_t t; pthread_attr_t at; pthread_attr_init(&at); pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_create(&t, &at, driver, 0); pthread_setname_np(t, "chap-nicj");
}
