/* chap_policy_lock.h -- Request E item-3-1: host-wide exclusive lock for comm_policy WRITERS.
 * Every Chaperon writer of the kernel comm_policy ARRAY (chaperon_loader initial + Model-B inserts,
 * chap_policy_flip live updates) holds this flock for the whole claim-slot + seqlock write. Readers
 * (the Filters, RO mmap) never take it. Lock file: root-owned, mode 0600, in a root-owned 0755 dir. */
#ifndef CHAP_POLICY_LOCK_H
#define CHAP_POLICY_LOCK_H
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static inline int chap_policy_lock(void)
{
    const char *p = getenv("CHAP_POLICY_LOCK"); if (!p || p[0] != '/') p = "/var/lib/chaperon/comm_policy.lock";
    (void)mkdir("/var/lib/chaperon", 0755);
    int fd = open(p, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    struct stat st; if (fstat(fd, &st) != 0 || st.st_uid != 0 || !S_ISREG(st.st_mode)) { close(fd); return -1; }
    if (flock(fd, LOCK_EX) != 0) { close(fd); return -1; }
    return fd;                                   /* held until chap_policy_unlock() */
}
static inline void chap_policy_unlock(int fd) { if (fd >= 0) { flock(fd, LOCK_UN); close(fd); } }
/* seqlock-protocol-aware table reset (a plain memset can be read torn by the RO Filters) */
#define CHAP_POL_RESET(tab, n) do { for (unsigned _i = 0; _i < (n); _i++) {         volatile struct pol_slot *_s = &(tab)[_i]; uint32_t _q = _s->seq & ~1u; _s->seq = _q + 1; __sync_synchronize();         _s->occupied = 0; memset((void *)&_s->key, 0, sizeof(_s->key)); _s->action = 0; __sync_synchronize(); _s->seq = _q + 2; } } while (0)
#endif
