// Chaperon tamper probe: joins the tenant's cgroup and attempts to make the Agent's protected
// hook page writable (mprotect RWX). If the Integrity Sentinel protects that range for this cgroup,
// the mprotect sys_enter is SIGKILLed BEFORE it runs, so TAMPER_SURVIVED never prints.
//   usage: tamper_child <cgroup.procs path> <addr_hex>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
int main(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr,"usage: %s cgroup.procs addr_hex\n", argv[0]); return 2; }
    int cf = open(argv[1], O_WRONLY);
    if (cf >= 0) { char b[32]; snprintf(b,sizeof b,"%d", getpid()); if (write(cf,b,strlen(b))<0){} close(cf); }
    unsigned long addr = strtoul(argv[2], 0, 16);
    void *page = (void *)(addr & ~0xFFFUL);
    mprotect(page, 4096, PROT_READ|PROT_WRITE|PROT_EXEC);   /* tamper attempt on the Agent hook page */
    printf("TAMPER_SURVIVED\n");                             /* reached only if NOT killed */
    return 0;
}
