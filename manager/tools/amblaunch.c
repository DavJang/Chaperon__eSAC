// root launcher: set the tenant capabilities as ambient, drop to the dedicated tenant user (non-root, no sudo),
// set PR_SET_NO_NEW_PRIVS, deny I/O-port access, exec argv with the capabilities retained.
//   CHAP_TENANT_USER  tenant account (required; must not be uid/gid 0)
// Request Q:
// - capabilities = what the mlx5 PMD needs: CAP_NET_RAW (DevX TIS / raw packet queues: without it the probe fails) and
//   CAP_SYS_RAWIO (DevX internal device resources: without it TX drops ~60x). CAP_NET_ADMIN is not given (host network
//   administration: netlink, ioctl, ethtool, tc, RDMA netlink); the mlx5 PMD init, RX/TX, rte_flow and port restart
//   work without it.
// - NO_NEW_PRIVS: setuid/setgid bits and file capabilities of any later exec grant nothing (sudo, su, ...); inherited
//   by every fork/clone/exec, cannot be cleared.
// - seccomp: iopl/ioperm fail with EPERM (CAP_SYS_RAWIO would otherwise give port I/O, i.e. PCI configuration space
//   access to the NIC through 0xcf8/0xcfc). DPDK only probes iopl for the virtio PMD and continues on failure.
#include <errno.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pwd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <unistd.h>
#ifndef CHAP_TENANT_CAPS
#define CHAP_TENANT_CAPS CAP_NET_RAW,CAP_SYS_RAWIO
#endif
static int deny_ioport(void)
{   /* x86_64 (incl. x32 bit): iopl 172, ioperm 173; i386 (int $0x80 / compat): iopl 110, ioperm 101 */
  struct sock_filter f[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 5),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xbfffffffu),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 172, 7, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 173, 6, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_I386, 0, 3),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 110, 2, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 101, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
  };
  struct sock_fprog p = { .len = (unsigned short)(sizeof f / sizeof f[0]), .filter = f };
  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &p, 0, 0);
}
int main(int argc,char**argv){
  if(argc<2){fprintf(stderr,"usage: CHAP_TENANT_USER=<user> amblaunch CMD [args]\n");return 2;}
  const char *tu=getenv("CHAP_TENANT_USER"); struct passwd *pw=tu?getpwnam(tu):NULL;
  if(!pw||pw->pw_uid==0||pw->pw_gid==0){fprintf(stderr,"amblaunch: CHAP_TENANT_USER unset, unknown or root -> refuse\n");return 2;}
  cap_value_t caps[]={CHAP_TENANT_CAPS}; int nc=(int)(sizeof caps/sizeof caps[0]);
  prctl(PR_SET_KEEPCAPS,1,0,0,0);
  cap_t c=cap_get_proc();
  cap_set_flag(c,CAP_INHERITABLE,nc,caps,CAP_SET);
  cap_set_flag(c,CAP_PERMITTED,nc,caps,CAP_SET);
  cap_set_flag(c,CAP_EFFECTIVE,nc,caps,CAP_SET);
  if(cap_set_proc(c)!=0){perror("cap_set_proc");return 2;}
  // drop privileges to the tenant user (no supplementary groups)
  if(setgroups(0,NULL)!=0){perror("setgroups");return 2;}
  if(setgid(pw->pw_gid)!=0){perror("setgid");return 2;}
  if(setuid(pw->pw_uid)!=0){perror("setuid");return 2;}
  if(getuid()==0||geteuid()==0){fprintf(stderr,"amblaunch: still root -> refuse\n");return 2;}
  // raise ambient so caps survive exec of a non-file-cap binary (after exec: permitted = effective = ambient)
  for(int i=0;i<nc;i++) if(prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_RAISE,caps[i],0,0)!=0){perror("amb");return 2;}
  if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)!=0||prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1){perror("no_new_privs");return 2;}
  if(deny_ioport()!=0){perror("seccomp");return 2;}
  execvp(argv[1],&argv[1]);
  perror("exec"); return 127;
}
