#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include "policy_table_opt.h"
#include "chap_policy_lock.h"
#include "chap_pmask.h"   /* Request I: active-combo header */
static int gfd(unsigned id){union bpf_attr a;memset(&a,0,sizeof a);a.map_id=id;return (int)syscall(__NR_bpf,BPF_MAP_GET_FD_BY_ID,&a,sizeof a);}
static uint32_t ip_of(const char*s){unsigned a,b,c,d;if(sscanf(s,"%u.%u.%u.%u",&a,&b,&c,&d)!=4)return 0;return (uint32_t)((a)|(b<<8)|(c<<16)|((unsigned)d<<24));}
int main(int argc,char**argv){
 if(argc<10){fprintf(stderr,"usage: %s <id> <N> <cgid> <sip> <cip> <sport> <dport> <proto> <action|99=reset>\n",argv[0]);return 2;}
 unsigned id=atoi(argv[1]),N=atoi(argv[2]); uint64_t cg=strtoull(argv[3],0,0);
 struct comm_policy_key k; memset(&k,0,sizeof k);
 k.cgroup_id=cg; k.src_ip=ip_of(argv[4]); k.dst_ip=ip_of(argv[5]);
 k.src_port=(uint16_t)atoi(argv[6]); k.dst_port=(uint16_t)atoi(argv[7]); k.protocol=(uint8_t)atoi(argv[8]); k.layer=2;
 uint32_t act=atoi(argv[9]);
 int fd=gfd(id); if(fd<0){fprintf(stderr,"get_fd_by_id(%u) fail: %s\n",id,strerror(errno));return 1;}
 int hdr=1; struct pol_slot*t=mmap(0,(size_t)(N+1)*sizeof(struct pol_slot),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);   /* Request I: + header slot */
 if(t==MAP_FAILED){ hdr=0; t=mmap(0,(size_t)N*sizeof(struct pol_slot),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0); }   /* 20-probe table (no header) */
 if(t==MAP_FAILED){perror("mmap RW");return 1;}
 int lk=chap_policy_lock(); if(lk<0){fprintf(stderr,"[flip] writer lock FAILED -> no write (fail-closed)\n");return 1;}
 if(act==99){ CHAP_POL_RESET(t,N); if(hdr) chap_pmask_store(t,N,0); chap_policy_unlock(lk); printf("[flip] RESET table id=%u N=%u all slots zeroed\n", id, N); return 0; }
 if(hdr) chap_pmask_add(t,N,1ull<<chap_combo_of(&k));   /* combo bit BEFORE the rule */
 int r=pol_insert(t,N,&k,act);
 chap_policy_unlock(lk);
 printf("[flip] id=%u key{cg=%llu sip=%s dip=%s sport=%s dport=%s proto=%s} action=%u combo=%u mask=0x%llx -> %s\n",id,(unsigned long long)cg,argv[4],argv[5],argv[6],argv[7],argv[8],act,chap_combo_of(&k),(unsigned long long)(hdr?chap_pmask_get(t,N):0),r==0?"OK":"SATURATED(kept old)");
 return r==0?0:1;}
