// Chaperon Request P -- TEST-ONLY NIC access probe (never part of a launch). Runs a list of steps in order and prints
// one unbuffered line per step, so a SIGKILL shows exactly which step was reached.
//   nicprobe <ibdev> step...
//   wait                 read one line from stdin (the harness registers/inspects the process meanwhile)
//   open                 ibv_open_device + ibv_alloc_pd + ibv_create_cq + ibv_query_port (real resource acquisition)
//   hold <s>             sleep s seconds (resources stay allocated for inspection)
//   close                release what "open" acquired
//   forkopen <s>         fork; the child runs "open", holds s seconds, exits; the parent waits and reports the status
//   fdopen               open the uverbs device node WITHOUT O_CLOEXEC; prints the fd
//   fdioctl <fd>|fdmmap <fd>|fdwrite <fd>   one raw ioctl / mmap / write on an existing uverbs fd
//   exec <path> [args...] (consumes the rest of the line) execv; on failure prints EXECFAIL and continues
//   forkexec <path> [args...]  fork; the child execs (rest of line); the parent waits and reports exit/signal
//   sockpair              create a socketpair (fds printed); sendfd <sock> <fd>; recvfd <sock> -> prints received fd
//   forge <pindir>        try to obtain and write the pinned sealed_procs map (must fail for the tenant)
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <infiniband/verbs.h>
#include <linux/bpf.h>
#include <rdma/rdma_user_ioctl_cmds.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *g_dev;
static struct ibv_context *g_ctx; static struct ibv_pd *g_pd; static struct ibv_cq *g_cq;
#define P(...) do { printf(__VA_ARGS__); fflush(stdout); } while (0)

static void uverbs_path(char *out, size_t n)
{   /* /sys/class/infiniband/<ibdev>/device/infiniband_verbs/uverbsN -> /dev/infiniband/uverbsN */
    char p[256]; snprintf(p, sizeof p, "/sys/class/infiniband/%s/device/infiniband_verbs", g_dev);
    DIR *d = opendir(p); struct dirent *e; char nm[64] = "";
    while (d && (e = readdir(d))) if (!strncmp(e->d_name, "uverbs", 6)) { snprintf(nm, sizeof nm, "%s", e->d_name); break; }
    if (d) closedir(d);
    snprintf(out, n, "/dev/infiniband/%s", nm);
}

static int do_open(void)
{
    int num = 0; struct ibv_device **l = ibv_get_device_list(&num), *d = NULL;
    for (int i = 0; l && i < num; i++) if (!strcmp(ibv_get_device_name(l[i]), g_dev)) d = l[i];
    if (!d) { P("OPEN step=list FAIL dev %s not found errno=%d\n", g_dev, errno); return 1; }
    P("OPEN step=open_device begin pid=%d\n", getpid());
    g_ctx = ibv_open_device(d);
    if (!g_ctx) { P("OPEN step=open_device FAIL errno=%d (%s)\n", errno, strerror(errno)); return 1; }
    P("OPEN step=open_device ok cmd_fd=%d\n", g_ctx->cmd_fd);
    g_pd = ibv_alloc_pd(g_ctx);
    if (!g_pd) { P("OPEN step=alloc_pd FAIL errno=%d\n", errno); return 1; }
    P("OPEN step=alloc_pd ok handle=%u\n", g_pd->handle);
    g_cq = ibv_create_cq(g_ctx, 16, NULL, NULL, 0);
    if (!g_cq) { P("OPEN step=create_cq FAIL errno=%d\n", errno); return 1; }
    P("OPEN step=create_cq ok handle=%u\n", g_cq->handle);
    struct ibv_port_attr pa; int r = ibv_query_port(g_ctx, 1, &pa);
    P("OPEN step=query_port %s state=%d\n", r ? "FAIL" : "ok", r ? -1 : (int)pa.state);
    P("OPEN RESULT ok pid=%d\n", getpid()); return 0;
}
static void do_close(void)
{ if (g_cq) ibv_destroy_cq(g_cq); if (g_pd) ibv_dealloc_pd(g_pd); if (g_ctx) ibv_close_device(g_ctx); g_cq = 0; g_pd = 0; g_ctx = 0; P("CLOSE ok\n"); }

static void report_child(pid_t c, const char *what)
{
    int st = 0; waitpid(c, &st, 0);
    if (WIFEXITED(st)) P("%s child=%d EXIT %d\n", what, c, WEXITSTATUS(st));
    else if (WIFSIGNALED(st)) P("%s child=%d SIGNAL %d\n", what, c, WTERMSIG(st));
}

int main(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr, "usage: %s <ibdev> step...\n", argv[0]); return 2; }
    g_dev = argv[1];
    for (int i = 2; i < argc; i++) {
        const char *s = argv[i];
        if (!strcmp(s, "wait")) { char b[64]; P("WAIT pid=%d\n", getpid()); if (!fgets(b, sizeof b, stdin)) {} P("WAIT done\n"); }
        else if (!strcmp(s, "open")) { do_open(); }
        else if (!strcmp(s, "close")) { do_close(); }
        else if (!strcmp(s, "hold") && i + 1 < argc) { int t = atoi(argv[++i]); P("HOLD %d\n", t); sleep(t); }
        else if (!strcmp(s, "forkopen") && i + 1 < argc) {
            int t = atoi(argv[++i]); pid_t c = fork();
            if (c == 0) { P("CHILD pid=%d ppid=%d\n", getpid(), getppid()); int r = do_open(); sleep(t); do_close(); _exit(r); }
            report_child(c, "FORKOPEN");
        }
        else if (!strcmp(s, "fdopen")) {
            char p[300]; uverbs_path(p, sizeof p); int fd = open(p, O_RDWR);   /* no O_CLOEXEC: survives exec */
            if (fd >= 0 && fd != 50) { dup2(fd, 50); close(fd); fd = 50; }
            P("FDOPEN path=%s fd=%d errno=%d cloexec=0\n", p, fd, fd < 0 ? errno : 0);
        }
        else if (!strcmp(s, "fdopenclo")) {   /* O_CLOEXEC: not inherited by exec (only passable via SCM_RIGHTS) */
            char p[300]; uverbs_path(p, sizeof p); int fd = open(p, O_RDWR | O_CLOEXEC);
            if (fd >= 0 && fd != 50) { dup3(fd, 50, O_CLOEXEC); close(fd); fd = 50; }
            P("FDOPEN path=%s fd=%d errno=%d cloexec=1\n", p, fd, fd < 0 ? errno : 0);
        }
        else if (!strcmp(s, "fdioctl") && i + 1 < argc) {
            int fd = atoi(argv[++i]);
            struct ib_uverbs_ioctl_hdr h; memset(&h, 0, sizeof h); h.length = sizeof h; h.object_id = 0xffff; h.method_id = 0xffff;
            P("FDIOCTL begin fd=%d pid=%d\n", fd, getpid());
            int r = ioctl(fd, RDMA_VERBS_IOCTL, &h);
            P("FDIOCTL ret=%d errno=%d (%s)\n", r, r < 0 ? errno : 0, r < 0 ? strerror(errno) : "-");
        }
        else if (!strcmp(s, "fdmmap") && i + 1 < argc) {
            int fd = atoi(argv[++i]); P("FDMMAP begin fd=%d pid=%d\n", fd, getpid());
            void *m = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
            P("FDMMAP ret=%s errno=%d (%s)\n", m == MAP_FAILED ? "MAP_FAILED" : "mapped", m == MAP_FAILED ? errno : 0, m == MAP_FAILED ? strerror(errno) : "-");
        }
        else if (!strcmp(s, "fdwrite") && i + 1 < argc) {
            int fd = atoi(argv[++i]); unsigned char b[16] = {0}; P("FDWRITE begin fd=%d pid=%d\n", fd, getpid());
            ssize_t r = write(fd, b, sizeof b);
            P("FDWRITE ret=%zd errno=%d (%s)\n", r, r < 0 ? errno : 0, r < 0 ? strerror(errno) : "-");
        }
        else if (!strcmp(s, "exec") && i + 1 < argc) {
            P("EXEC %s pid=%d\n", argv[i + 1], getpid()); execv(argv[i + 1], &argv[i + 1]);
            P("EXECFAIL %s errno=%d (%s)\n", argv[i + 1], errno, strerror(errno)); i = argc; /* rest consumed */
        }
        else if (!strcmp(s, "execfail")) {   /* failed exec: the process (and its status) continue */
            char *a[] = {"/nonexistent/chap_reqP", NULL}; execv(a[0], a);
            P("EXECFAIL /nonexistent errno=%d (%s) pid=%d continues\n", errno, strerror(errno), getpid());
        }
        else if (!strcmp(s, "forkexec") && i + 1 < argc) {
            pid_t c = fork();
            if (c == 0) { execv(argv[i + 1], &argv[i + 1]); P("EXECFAIL %s errno=%d\n", argv[i + 1], errno); _exit(127); }
            P("FORKEXEC child=%d path=%s\n", c, argv[i + 1]); report_child(c, "FORKEXEC"); i = argc;
        }
        else if (!strcmp(s, "sockpair")) { int sv[2]; int r = socketpair(AF_UNIX, SOCK_STREAM, 0, sv); dup2(sv[0], 60); dup2(sv[1], 61); close(sv[0]); close(sv[1]); P("SOCKPAIR r=%d fds=60,61\n", r); }
        else if (!strcmp(s, "sendfd") && i + 2 < argc) {
            int sk = atoi(argv[++i]), fd = atoi(argv[++i]); char c = 'x'; struct iovec io = {&c, 1};
            char cb[CMSG_SPACE(sizeof(int))]; struct msghdr m = {0}; m.msg_iov = &io; m.msg_iovlen = 1; m.msg_control = cb; m.msg_controllen = sizeof cb;
            struct cmsghdr *h = CMSG_FIRSTHDR(&m); h->cmsg_level = SOL_SOCKET; h->cmsg_type = SCM_RIGHTS; h->cmsg_len = CMSG_LEN(sizeof(int)); memcpy(CMSG_DATA(h), &fd, sizeof(int));
            P("SENDFD sock=%d fd=%d r=%zd\n", sk, fd, sendmsg(sk, &m, 0));
        }
        else if (!strcmp(s, "recvfd") && i + 1 < argc) {
            int sk = atoi(argv[++i]); char c; struct iovec io = {&c, 1}; char cb[CMSG_SPACE(sizeof(int))];
            struct msghdr m = {0}; m.msg_iov = &io; m.msg_iovlen = 1; m.msg_control = cb; m.msg_controllen = sizeof cb;
            ssize_t r = recvmsg(sk, &m, 0); int fd = -1; struct cmsghdr *h = CMSG_FIRSTHDR(&m);
            if (r > 0 && h && h->cmsg_type == SCM_RIGHTS) memcpy(&fd, CMSG_DATA(h), sizeof(int));
            if (fd >= 0 && fd != 51) { dup2(fd, 51); close(fd); fd = 51; }
            P("RECVFD sock=%d fd=%d\n", sk, fd);
        }
        else if (!strcmp(s, "forge") && i + 1 < argc) {
            char p[300]; snprintf(p, sizeof p, "%s/sealed_procs", argv[++i]);
            union bpf_attr a; memset(&a, 0, sizeof a); a.pathname = (unsigned long)p;
            long fd = syscall(SYS_bpf, BPF_OBJ_GET, &a, sizeof a);
            P("FORGE obj_get(%s) ret=%ld errno=%d (%s)\n", p, fd, fd < 0 ? errno : 0, fd < 0 ? strerror(errno) : "-");
            memset(&a, 0, sizeof a); a.map_id = 1; long f2 = syscall(SYS_bpf, BPF_MAP_GET_FD_BY_ID, &a, sizeof a);
            P("FORGE map_get_fd_by_id ret=%ld errno=%d (%s)\n", f2, f2 < 0 ? errno : 0, f2 < 0 ? strerror(errno) : "-");
            int pf = open(p, O_RDWR); P("FORGE open(pin) ret=%d errno=%d (%s)\n", pf, pf < 0 ? errno : 0, pf < 0 ? strerror(errno) : "-");
        }
        else { P("UNKNOWN step %s\n", s); }
    }
    P("END pid=%d\n", getpid());
    return 0;
}
