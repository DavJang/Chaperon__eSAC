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
#include <sys/stat.h>
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
    char *env[] = {"PATH=/usr/local/bin:/usr/bin:/bin", "XDG_RUNTIME_DIR=/var/tmp/chap_dpdkrun", NULL};
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
