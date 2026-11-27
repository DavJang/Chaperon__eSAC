// Chaperon multi-id FD broker (trusted root init) -- review fix #2-1: AUTHENTICATED, SINGLE-SERVE.
// The tenant's bpftime agent connects, writes a u32 kernel-map id, and we reply (SCM_RIGHTS) with
// that kernel map's fd -- but ONLY when:
//   (a) the connecting peer belongs to the APPROVED tenant process (SO_PEERCRED -> /proc Tgid ==
//       tenant_pid). Same UID alone is NOT enough.
//   (b) the requested id is in the allowlist for THIS run.
//   (c) that id has NOT been served before (per-map single-serve => reissue blocked after init).
// => a tenant that closed its fd cannot re-acquire a writable fd for the same map from this broker.
//   usage: fd_broker_multi <sock> <id1,id2,...> <tenant_pid> [max_total_serves]
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <bpf/bpf.h>

static int allowed[32], served[32] = {0}, n_allowed = 0;
static int idx_of(uint32_t id){ for (int i=0;i<n_allowed;i++) if ((uint32_t)allowed[i]==id) return i; return -1; }

static int peer_tgid(int s){
    struct ucred cr; socklen_t len = sizeof cr;
    if (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cr, &len) < 0) return -1;
    char p[64]; snprintf(p,sizeof p,"/proc/%d/status", cr.pid);
    FILE *f = fopen(p,"r"); if (!f) return cr.pid; /* fallback: the connecting pid itself */
    char line[128]; int tgid = cr.pid;
    while (fgets(line,sizeof line,f)) if (!strncmp(line,"Tgid:",5)) { tgid = atoi(line+5); break; }
    fclose(f); return tgid;
}

static int send_fd(int s, int fd){
    char dummy='K'; char cbuf[CMSG_SPACE(sizeof(int))]; memset(cbuf,0,sizeof cbuf);
    struct iovec iov = { &dummy, 1 };
    struct msghdr msg; memset(&msg,0,sizeof msg);
    msg.msg_iov=&iov; msg.msg_iovlen=1; msg.msg_control=cbuf; msg.msg_controllen=sizeof cbuf;
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS; c->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof(int));
    return sendmsg(s, &msg, 0);
}

int main(int argc, char **argv){
    if (argc < 4) { fprintf(stderr,"usage: %s sock id1,id2,... tenant_pid [max_total_serves]\n", argv[0]); return 2; }
    const char *sockpath = argv[1];
    char *ids = strdup(argv[2]);
    for (char *t = strtok(ids, ","); t && n_allowed < 32; t = strtok(NULL, ",")) allowed[n_allowed++] = atoi(t);
    int tenant_pid = atoi(argv[3]);
    int max_serves = argc > 4 ? atoi(argv[4]) : n_allowed;   /* default: exactly one per allowed map */

    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sa; memset(&sa,0,sizeof sa); sa.sun_family=AF_UNIX;
    strncpy(sa.sun_path, sockpath, sizeof sa.sun_path - 1);
    unlink(sockpath);
    if (bind(srv,(struct sockaddr*)&sa,sizeof sa)<0){ perror("bind"); return 1; }
    if (listen(srv, 8)<0){ perror("listen"); return 1; }
    fprintf(stderr,"[broker] ready sock=%s allowed=%s tenant_pid=%d single-serve-per-map max_total=%d\n",
            sockpath, argv[2], tenant_pid, max_serves);

    int served_total = 0;
    while (served_total < max_serves) {
        int c = accept(srv, NULL, NULL);
        if (c < 0) continue;
        int ptg = peer_tgid(c);
        uint32_t id = 0;
        if (read(c, &id, sizeof id) != (ssize_t)sizeof id) { close(c); continue; }
        if (ptg != tenant_pid) { fprintf(stderr,"[broker] REJECT id=%u: peer tgid=%d != approved tenant %d\n", id, ptg, tenant_pid); close(c); continue; }
        int k = idx_of(id);
        if (k < 0) { fprintf(stderr,"[broker] REJECT id=%u: not in allowlist\n", id); close(c); continue; }
        if (served[k]) { fprintf(stderr,"[broker] REJECT id=%u: already served (reissue blocked)\n", id); close(c); continue; }
        int mfd = bpf_map_get_fd_by_id(id);
        if (mfd < 0) { fprintf(stderr,"[broker] get_fd_by_id(%u) FAIL errno=%d\n", id, errno); close(c); continue; }
        if (send_fd(c, mfd) > 0) { served[k] = 1; served_total++; fprintf(stderr,"[broker] served id=%u to tenant %d (%d/%d)\n", id, tenant_pid, served_total, max_serves); }
        close(mfd); close(c);
    }
    fprintf(stderr,"[broker] served %d request(s); exiting (no further FD issuance)\n", served_total);
    return 0;
}
