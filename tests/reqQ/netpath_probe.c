// Chaperon Request Q -- TEST-ONLY probe of NIC paths that do not go through the uverbs command interface. Every step
// prints one "NPP <step> ..." line with the system-call results; whether a frame really left / reached the NIC is
// judged by an independent observer (tcpdump / counters on the peer VF), never by this program's return codes alone.
//   netpath_probe <step> [args]
//   afp_tx IF DSTMAC N        AF_PACKET SOCK_RAW frames (ethertype 0x88b5, payload "CHAPQ-AFP")
//   afp_rx IF SECS            AF_PACKET receive; counts frames whose payload starts with "CHAPQ-PEER"
//   udp_bind IF N             UDP broadcast 255.255.255.255:47999 with SO_BINDTODEVICE (payload "CHAPQ-UDPB")
//   udp_pktinfo IF N          UDP broadcast with IP_PKTINFO ifindex (no SO_BINDTODEVICE; payload "CHAPQ-UDPP")
//   rawip IF N                AF_INET SOCK_RAW IPPROTO_RAW (IP_HDRINCL) + SO_BINDTODEVICE (payload "CHAPQ-RAWIP")
//   ifmtu IF MTU              SIOCSIFMTU, then reads the MTU back
//   ifflags IF                SIOCSIFFLAGS |= IFF_ALLMULTI, then reads the flags back
//   ethring IF                ETHTOOL_SRINGPARAM rx_pending-=64 (reads back)
//   pio                       ioperm(0xcf8,8) permission check (no port access; grant dropped at once)
//   iopl                      iopl(3) permission check (dropped at once)
//   procpci BUS DEV FN        open(/proc/bus/pci/BB/DD.F) access check (no mapping)
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/ethtool.h>
#include <linux/if_packet.h>
#include <linux/pci.h>
#include <linux/sockios.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/io.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define P(...) do { printf(__VA_ARGS__); fflush(stdout); } while (0)
static int ifidx(const char *n) { return (int)if_nametoindex(n); }
static int parse_mac(const char *s, unsigned char *m) { return sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", m, m+1, m+2, m+3, m+4, m+5) == 6 ? 0 : -1; }

static void udp_send(const char *ifn, int n, int mode, const char *tag)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0), on = 1, ok = 0, e = 0, r1 = 0;
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, &on, sizeof on);
    if (mode == 0) r1 = setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, ifn, strlen(ifn) + 1);
    struct sockaddr_in d = { .sin_family = AF_INET, .sin_port = htons(47999) }; d.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    char pl[64]; snprintf(pl, sizeof pl, "%s-%d", tag, getpid());
    for (int i = 0; i < n; i++) {
        ssize_t r;
        if (mode == 0) r = sendto(s, pl, strlen(pl), 0, (struct sockaddr *)&d, sizeof d);
        else {
            char cb[CMSG_SPACE(sizeof(struct in_pktinfo))] = {0}; struct iovec io = { pl, strlen(pl) };
            struct msghdr m = { .msg_name = &d, .msg_namelen = sizeof d, .msg_iov = &io, .msg_iovlen = 1, .msg_control = cb, .msg_controllen = sizeof cb };
            struct cmsghdr *c = CMSG_FIRSTHDR(&m); c->cmsg_level = IPPROTO_IP; c->cmsg_type = IP_PKTINFO; c->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
            struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(c); pi->ipi_ifindex = ifidx(ifn);
            r = sendmsg(s, &m, 0);
        }
        if (r > 0) ok++; else e = errno;
        usleep(1000);
    }
    P("NPP %s if=%s socket=%d bindtodevice=%d sent_ok=%d/%d last_errno=%d(%s)\n", mode ? "udp_pktinfo" : "udp_bind", ifn, s, r1, ok, n, e, e ? strerror(e) : "-");
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    const char *st = argv[1];
    if (!strcmp(st, "afp_tx") && argc > 4) {
        int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)), e0 = s < 0 ? errno : 0;
        struct sockaddr_ll a = { .sll_family = AF_PACKET, .sll_ifindex = ifidx(argv[2]), .sll_halen = 6 };
        unsigned char f[128] = {0}; parse_mac(argv[3], f); parse_mac(argv[3], a.sll_addr);
        struct ifreq q = {0}; snprintf(q.ifr_name, IFNAMSIZ, "%s", argv[2]);
        if (s >= 0 && !ioctl(s, SIOCGIFHWADDR, &q)) memcpy(f + 6, q.ifr_hwaddr.sa_data, 6);
        const char *tag = getenv("NPP_TAG"); if (!tag) tag = "CHAPQ-AFP";
        f[12] = 0x88; f[13] = 0xb5; int pl = snprintf((char *)f + 14, 64, "%s-%d", tag, getpid());
        int n = atoi(argv[4]), ok = 0, e = 0;
        for (int i = 0; s >= 0 && i < n; i++) { if (sendto(s, f, 14 + pl + 1 < 60 ? 60 : 14 + pl + 1, 0, (struct sockaddr *)&a, sizeof a) > 0) ok++; else e = errno; usleep(1000); }
        P("NPP afp_tx if=%s socket=%d socket_errno=%d sent_ok=%d/%d last_errno=%d(%s)\n", argv[2], s, e0, ok, n, e, e ? strerror(e) : "-");
    } else if (!strcmp(st, "afp_rx") && argc > 3) {
        int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)), e0 = s < 0 ? errno : 0;
        struct sockaddr_ll a = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL), .sll_ifindex = ifidx(argv[2]) };
        int br = s >= 0 ? bind(s, (struct sockaddr *)&a, sizeof a) : -1, got = 0, any = 0; time_t end = time(0) + atoi(argv[3]);
        while (s >= 0 && time(0) < end) {
            struct pollfd p = { s, POLLIN, 0 }; if (poll(&p, 1, 200) <= 0) continue;
            unsigned char b[2048]; ssize_t r = recv(s, b, sizeof b, 0); if (r <= 0) continue; any++;
            if (r > 24 && memmem(b, r, "CHAPQ-PEER", 10)) got++;
        }
        P("NPP afp_rx if=%s socket=%d socket_errno=%d bind=%d frames_any=%d frames_from_peer=%d\n", argv[2], s, e0, br, any, got);
    } else if (!strcmp(st, "udp_bind") && argc > 3) udp_send(argv[2], atoi(argv[3]), 0, "CHAPQ-UDPB");
    else if (!strcmp(st, "udp_pktinfo") && argc > 3) udp_send(argv[2], atoi(argv[3]), 1, "CHAPQ-UDPP");
    else if (!strcmp(st, "rawip") && argc > 3) {
        int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW), e0 = s < 0 ? errno : 0, on = 1, ok = 0, e = 0, n = atoi(argv[3]);
        int r1 = s >= 0 ? setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, argv[2], strlen(argv[2]) + 1) : -1; if (s >= 0) setsockopt(s, SOL_SOCKET, SO_BROADCAST, &on, sizeof on);
        unsigned char pk[128] = {0}; struct iphdr *ip = (struct iphdr *)pk; struct udphdr *u = (struct udphdr *)(ip + 1);
        int pl = snprintf((char *)(u + 1), 64, "CHAPQ-RAWIP-%d", getpid());
        ip->version = 4; ip->ihl = 5; ip->ttl = 64; ip->protocol = IPPROTO_UDP; ip->daddr = htonl(INADDR_BROADCAST); ip->tot_len = htons(28 + pl);
        u->source = htons(1); u->dest = htons(47999); u->len = htons(8 + pl);
        struct sockaddr_in d = { .sin_family = AF_INET }; d.sin_addr.s_addr = htonl(INADDR_BROADCAST);
        for (int i = 0; s >= 0 && i < n; i++) { if (sendto(s, pk, 28 + pl, 0, (struct sockaddr *)&d, sizeof d) > 0) ok++; else e = errno; usleep(1000); }
        P("NPP rawip if=%s socket=%d socket_errno=%d bindtodevice=%d sent_ok=%d/%d last_errno=%d(%s)\n", argv[2], s, e0, r1, ok, n, e, e ? strerror(e) : "-");
    } else if (!strcmp(st, "ifmtu") && argc > 3) {
        int s = socket(AF_INET, SOCK_DGRAM, 0); struct ifreq q = {0}; snprintf(q.ifr_name, IFNAMSIZ, "%s", argv[2]);
        ioctl(s, SIOCGIFMTU, &q); int before = q.ifr_mtu; q.ifr_mtu = atoi(argv[3]); int r = ioctl(s, SIOCSIFMTU, &q), e = r ? errno : 0;
        ioctl(s, SIOCGIFMTU, &q); P("NPP ifmtu if=%s before=%d set=%s ret=%d errno=%d(%s) after=%d\n", argv[2], before, argv[3], r, e, e ? strerror(e) : "-", q.ifr_mtu);
    } else if (!strcmp(st, "ifflags") && argc > 2) {
        int s = socket(AF_INET, SOCK_DGRAM, 0); struct ifreq q = {0}; snprintf(q.ifr_name, IFNAMSIZ, "%s", argv[2]);
        ioctl(s, SIOCGIFFLAGS, &q); int before = q.ifr_flags; q.ifr_flags |= IFF_ALLMULTI; int r = ioctl(s, SIOCSIFFLAGS, &q), e = r ? errno : 0;
        ioctl(s, SIOCGIFFLAGS, &q); P("NPP ifflags if=%s before=0x%x ret=%d errno=%d(%s) after=0x%x\n", argv[2], before, r, e, e ? strerror(e) : "-", q.ifr_flags);
    } else if (!strcmp(st, "ethring") && argc > 2) {
        int s = socket(AF_INET, SOCK_DGRAM, 0); struct ifreq q = {0}; snprintf(q.ifr_name, IFNAMSIZ, "%s", argv[2]);
        struct ethtool_ringparam rp = { .cmd = ETHTOOL_GRINGPARAM }; q.ifr_data = (void *)&rp; ioctl(s, SIOCETHTOOL, &q); unsigned before = rp.rx_pending;
        rp.cmd = ETHTOOL_SRINGPARAM; rp.rx_pending = before > 128 ? before - 64 : before + 64; int r = ioctl(s, SIOCETHTOOL, &q), e = r ? errno : 0;
        rp.cmd = ETHTOOL_GRINGPARAM; ioctl(s, SIOCETHTOOL, &q); P("NPP ethring if=%s rx_pending before=%u ret=%d errno=%d(%s) after=%u\n", argv[2], before, r, e, e ? strerror(e) : "-", rp.rx_pending);
    } else if (!strcmp(st, "pio")) {   /* permission check only: no port is accessed, the grant is dropped at once */
        int r = ioperm(0xcf8, 8, 1), e = r ? errno : 0; if (!r) ioperm(0xcf8, 8, 0);
        P("NPP pio ioperm(0xcf8,8)=%d errno=%d(%s)\n", r, e, e ? strerror(e) : "-");
    } else if (!strcmp(st, "iopl")) {   /* permission check only */
        int r = iopl(3), e = r ? errno : 0; if (!r) iopl(0); P("NPP iopl ret=%d errno=%d(%s)\n", r, e, e ? strerror(e) : "-");
    } else if (!strcmp(st, "procpci") && argc > 4) {
        char p[128]; snprintf(p, sizeof p, "/proc/bus/pci/%s/%s.%s", argv[2], argv[3], argv[4]);
        char rp_[160]; snprintf(rp_, sizeof rp_, "/sys/bus/pci/devices/0000:%s:%s.%s/resource", argv[2], argv[3], argv[4]);
        unsigned long long bar = 0, end = 0, fl = 0; FILE *rf = fopen(rp_, "r"); if (rf) { if (fscanf(rf, "%llx %llx %llx", &bar, &end, &fl) != 3) bar = 0; fclose(rf); }
        int fd = open(p, O_RDONLY), e0 = fd < 0 ? errno : 0;   /* access check only: no mapping, no register read */
        P("NPP procpci %s open=%d errno=%d(%s) bar0=0x%llx\n", p, fd, e0, e0 ? strerror(e0) : "-", bar); if (fd >= 0) close(fd);
    } else { fprintf(stderr, "bad step\n"); return 2; }
    return 0;
}
