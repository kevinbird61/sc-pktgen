#include "pktgen.h"

void encap_ipv4(char *pkt_ip,
    int total_len, int protocol,
    char *srcIP, char *dstIP)
{
    struct ip *iph;
    iph=(struct ip *)pkt_ip;
    // init 
    memset(iph, 0x00, sizeof(struct ip));
    // header len & version
    iph->ip_hl=5;
    iph->ip_v=4;
    // fragment offset
    iph->ip_off&=IP_DF;
    // TTL
    iph->ip_ttl=0xff; 
    // total length
    iph->ip_len=htons(total_len);
    // protocol
    iph->ip_p=protocol;
    // src & dst addr
    struct in_addr srcip, dstip;
    srcip.s_addr=ipv4str2hex(srcIP);
    dstip.s_addr=ipv4str2hex(dstIP);
    iph->ip_src=srcip;
    iph->ip_dst=dstip;

    // checksum 
    compute_ipv4_csum(pkt_ip);
}