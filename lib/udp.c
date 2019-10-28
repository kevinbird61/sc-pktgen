#include "pktgen.h"

void encap_udp(char *pkt_udp, unsigned short sport, unsigned short dport)
{
    struct udphdr *udp;
    udp=(struct udphdr *)pkt_udp;
    memset(udp, 0x00, sizeof(struct udphdr));

    udp->source=htons(sport);
    udp->dest=htons(dport);
    udp->len=htons(8);
    // udp->check
}

