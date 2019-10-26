#include "pktgen.h"

void encap_tcp(char *pkt_tcp, unsigned short sport, unsigned short dport,
    unsigned int seq, unsigned ack_seq, unsigned short window,
    unsigned char flags)
{
    struct tcphdr *tcp;
    tcp=(struct tcphdr *)pkt_tcp;
    memset(tcp, 0x00, sizeof(struct tcphdr));

    tcp->source=htons(sport);
    tcp->dest=htons(dport);
    tcp->seq=htons(seq);
    tcp->ack_seq=htons(ack_seq);

    tcp->doff=(sizeof(struct tcphdr))/4;

    tcp->fin=(flags&0x001>0)?1:0;
    tcp->syn=(flags&0x002>0)?1:0;
    tcp->rst=(flags&0x004>0)?1:0;
    tcp->psh=(flags&0x008>0)?1:0;
    tcp->ack=(flags&0x010>0)?1:0;
    tcp->urg=(flags&0x020>0)?1:0;
}