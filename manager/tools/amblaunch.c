// root launcher: set 3 caps as ambient, drop to uid/gid 1003 (non-root), exec argv with caps retained
#include <stdio.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <grp.h>
int main(int argc,char**argv){
  if(argc<2){fprintf(stderr,"usage: amblaunch CMD [args]\n");return 2;}
  cap_value_t caps[3]={CAP_NET_RAW,CAP_NET_ADMIN,CAP_SYS_RAWIO};
  prctl(PR_SET_KEEPCAPS,1,0,0,0);
  cap_t c=cap_get_proc();
  cap_set_flag(c,CAP_INHERITABLE,3,caps,CAP_SET);
  cap_set_flag(c,CAP_PERMITTED,3,caps,CAP_SET);
  cap_set_flag(c,CAP_EFFECTIVE,3,caps,CAP_SET);
  if(cap_set_proc(c)!=0) perror("cap_set_proc");
  // drop privileges to the tenant user (uid/gid 1003)
  setgroups(0,NULL);
  if(setgid(1003)!=0) perror("setgid");
  if(setuid(1003)!=0) perror("setuid");
  // raise ambient so caps survive exec of a non-file-cap binary
  for(int i=0;i<3;i++) if(prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_RAISE,caps[i],0,0)!=0) perror("amb");
  execvp(argv[1],&argv[1]);
  perror("exec"); return 127;
}
