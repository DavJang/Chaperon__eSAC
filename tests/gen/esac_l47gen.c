/* esac_l47gen: controllable DPDK tx generator for eSAC L4/L7 functional verification.
 * Sends an EXACT count of packets with fully specified L4 fields and payload, rate-limited
 * (low pps) so the eSAC rxonly tenant can count delivered packets precisely.
 *
 *   EAL args -- <count> <dmac> <src_ip> <dst_ip> <sport> <dport> <proto:udp|tcp> <payload>
 *   payload := none | pad:N | dns:QNAME | raw:HEX
 *     none     : 16-byte filler (NOT DNS-shaped: qdcount!=1 -> L7 gate skips inspection)
 *     dns:NAME : 12-byte DNS header (flags 0x0100, qdcount 0x0001) + encoded QNAME + A/IN
 *                -> matches the L7 content-gate (proto==udp && qdcount==1), HS scans QNAME
 *     pad:N    : N filler bytes
 *     raw:HEX  : literal hex payload
 * The eSAC-protected RECEIVER stays UNMODIFIED. Test tooling only (no eSAC change). */
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

static uint16_t find_port(void){ uint16_t p; RTE_ETH_FOREACH_DEV(p) return p; return 0xffff; }

/* encode "a.b.c" -> \x01a\x01b\x01c\x00 ; returns encoded length */
static int dns_qname(const char *name, unsigned char *out){
    int o=0; const char *s=name;
    while(*s){
        const char *dot=strchr(s,'.'); int len = dot ? (int)(dot-s) : (int)strlen(s);
        out[o++]=(unsigned char)len; memcpy(out+o,s,len); o+=len;
        if(!dot) break; s=dot+1;
    }
    out[o++]=0; return o;
}

/* build payload into buf, return length */
static int build_payload(const char *spec, unsigned char *buf){
    if(!strcmp(spec,"none")){ memset(buf,0xAB,16); return 16; }
    if(!strncmp(spec,"pad:",4)){ int n=atoi(spec+4); if(n<1)n=1; if(n>1400)n=1400; memset(buf,0xAB,n); return n; }
    if(!strncmp(spec,"dns:",4)){
        /* DNS header: id, flags=0x0100(std query,RD), qd=1, an=ns=ar=0 */
        int o=0; buf[o++]=0x12; buf[o++]=0x34; buf[o++]=0x01; buf[o++]=0x00;
        buf[o++]=0x00; buf[o++]=0x01; buf[o++]=0x00; buf[o++]=0x00;
        buf[o++]=0x00; buf[o++]=0x00; buf[o++]=0x00; buf[o++]=0x00;
        o += dns_qname(spec+4, buf+o);
        buf[o++]=0x00; buf[o++]=0x01; /* QTYPE A */
        buf[o++]=0x00; buf[o++]=0x01; /* QCLASS IN */
        return o;
    }
    if(!strncmp(spec,"raw:",4)){
        const char *h=spec+4; int o=0;
        while(h[0]&&h[1]){ unsigned v; sscanf(h,"%2x",&v); buf[o++]=(unsigned char)v; h+=2; }
        return o;
    }
    memset(buf,0xAB,16); return 16;
}

int main(int argc, char **argv){
    int ret = rte_eal_init(argc, argv);
    if (ret < 0){ fprintf(stderr,"EAL init fail\n"); return 1; }
    argc -= ret; argv += ret;
    int count       = (argc>1)? atoi(argv[1]) : 1000;
    const char *dmac_s = (argc>2)? argv[2] : "02:51:00:00:00:01";
    const char *sip_s  = (argc>3)? argv[3] : "198.18.0.1";
    const char *dip_s  = (argc>4)? argv[4] : "198.18.0.2";
    uint16_t sport  = (argc>5)? (uint16_t)atoi(argv[5]) : 5000;
    uint16_t dport  = (argc>6)? (uint16_t)atoi(argv[6]) : 9;
    const char *proto_s= (argc>7)? argv[7] : "udp";
    const char *pay_s  = (argc>8)? argv[8] : "none";
    int is_tcp = !strcmp(proto_s,"tcp");
    uint32_t sip = ntohl(inet_addr(sip_s)), dip = ntohl(inet_addr(dip_s));

    struct rte_ether_addr dmac;
    { unsigned b[6]; sscanf(dmac_s,"%x:%x:%x:%x:%x:%x",&b[0],&b[1],&b[2],&b[3],&b[4],&b[5]);
      for(int i=0;i<6;i++) dmac.addr_bytes[i]=(uint8_t)b[i]; }
    unsigned char pay[1600]; int paylen = build_payload(pay_s, pay);

    uint16_t port = find_port();
    if (port==0xffff){ fprintf(stderr,"no port\n"); return 2; }
    struct rte_mempool *mp = rte_pktmbuf_pool_create("MP", 8192, 256, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if(!mp){ fprintf(stderr,"mempool fail\n"); return 3; }
    struct rte_eth_conf conf; memset(&conf,0,sizeof(conf));
    if(rte_eth_dev_configure(port,1,1,&conf)<0){ fprintf(stderr,"configure fail\n"); return 4; }
    rte_eth_rx_queue_setup(port,0,512,rte_socket_id(),NULL,mp);
    rte_eth_tx_queue_setup(port,0,512,rte_socket_id(),NULL);
    if(rte_eth_dev_start(port)<0){ fprintf(stderr,"start fail\n"); return 5; }
    struct rte_ether_addr smac; rte_eth_macaddr_get(port,&smac);
    rte_eth_promiscuous_enable(port);

    int l4hdr = is_tcp ? (int)sizeof(struct rte_tcp_hdr) : (int)sizeof(struct rte_udp_hdr);
    int l3len = 20 + l4hdr + paylen;
    int frame = 14 + l3len;
    int sent=0, txfail=0;
    for(int i=0;i<count;i++){
        struct rte_mbuf *m = rte_pktmbuf_alloc(mp);
        if(!m){ txfail++; continue; }
        char *p = rte_pktmbuf_append(m, frame);
        struct rte_ether_hdr *eth=(struct rte_ether_hdr*)p;
        rte_ether_addr_copy(&dmac,&eth->dst_addr); rte_ether_addr_copy(&smac,&eth->src_addr);
        eth->ether_type=rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
        struct rte_ipv4_hdr *ip=(struct rte_ipv4_hdr*)(eth+1);
        ip->version_ihl=0x45; ip->type_of_service=0; ip->total_length=rte_cpu_to_be_16(l3len);
        ip->packet_id=rte_cpu_to_be_16(i); ip->fragment_offset=0; ip->time_to_live=64;
        ip->next_proto_id = is_tcp ? IPPROTO_TCP : IPPROTO_UDP;
        ip->src_addr=rte_cpu_to_be_32(sip); ip->dst_addr=rte_cpu_to_be_32(dip);
        ip->hdr_checksum=0; ip->hdr_checksum=rte_ipv4_cksum(ip);
        unsigned char *l4 = (unsigned char*)(ip+1);
        if(is_tcp){
            struct rte_tcp_hdr *t=(struct rte_tcp_hdr*)l4;
            memset(t,0,sizeof(*t));
            t->src_port=rte_cpu_to_be_16(sport); t->dst_port=rte_cpu_to_be_16(dport);
            t->sent_seq=rte_cpu_to_be_32(1); t->data_off=0x50; t->tcp_flags=0x18; /* PSH|ACK */
            t->rx_win=rte_cpu_to_be_16(1024);
            memcpy(l4+l4hdr, pay, paylen);
        } else {
            struct rte_udp_hdr *u=(struct rte_udp_hdr*)l4;
            u->src_port=rte_cpu_to_be_16(sport); u->dst_port=rte_cpu_to_be_16(dport);
            u->dgram_len=rte_cpu_to_be_16(l4hdr+paylen); u->dgram_cksum=0;
            memcpy(l4+l4hdr, pay, paylen);
        }
        uint16_t n = rte_eth_tx_burst(port,0,&m,1);
        if(n==1) sent++; else { txfail++; rte_pktmbuf_free(m); }
        if((i%20)==0) usleep(1000);
    }
    struct rte_eth_stats st; rte_eth_stats_get(port,&st);
    printf("L47GEN proto=%s sip=%s dip=%s sport=%u dport=%u pay=%s(%dB) count=%d sent=%d fail=%d opackets=%lu obytes=%lu\n",
           proto_s, sip_s, dip_s, sport, dport, pay_s, paylen, count, sent, txfail,
           (unsigned long)st.opackets, (unsigned long)st.obytes);
    rte_eth_dev_stop(port);
    return 0;
}
