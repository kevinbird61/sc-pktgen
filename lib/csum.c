#include "pktgen.h"

void compute_tcp_csum(char *pkt_ip)
{
    struct ip *iph;
    iph=(struct ip*)pkt_ip;
    struct tcphdr *tcph;
    char *payload;
    payload=pkt_ip+sizeof(struct ip);
    tcph=(struct tcphdr*)(pkt_ip+sizeof(struct ip));

    register unsigned long sum=0;
    unsigned short tcplen = (ntohs(iph->ip_len) - (iph->ip_hl<<2));

    // src ip
    sum += (iph->ip_src.s_addr>>16)&0xFFFF;
    sum += (iph->ip_src.s_addr)&0xFFFF;

    // dst ip
    sum += (iph->ip_dst.s_addr>>16)&0xFFFF;
    sum += (iph->ip_dst.s_addr)&0xFFFF;

    // protocol
    sum += htons(6);

    // length
    sum += htons(tcplen);

    // payload (tcp)
    tcph->check=0;
    while(tcplen>1){
        sum += *((payload)++);
        tcplen -= 2;
    }

    if(tcplen>0){
        sum += (*(payload) & htons(0xFF00));
    }

    while(sum>>16){
        sum=(sum&0xFFFF)+(sum>>16);
    }

    sum = ~sum;

    // assign csum
    tcph->check=(unsigned short)sum;
}

void compute_udp_csum(char *pkt_ip)
{
    struct ip *iph;
    iph=(struct ip*)pkt_ip;
    struct udphdr *udph;
    char *payload;
    payload=pkt_ip+sizeof(struct ip);
    udph=(struct udphdr*)(pkt_ip+sizeof(struct ip));

    register unsigned long sum=0;
    unsigned short udplen = htons(udph->len);

    // src ip
    sum += (iph->ip_src.s_addr>>16)&0xFFFF;
    sum += (iph->ip_src.s_addr)&0xFFFF;

    // dst ip
    sum += (iph->ip_dst.s_addr>>16)&0xFFFF;
    sum += (iph->ip_dst.s_addr)&0xFFFF;

    // protocol
    sum += htons(17);

    // lenght 
    sum += udph->len;

    udph->check=0;
    while(udplen > 1){
        sum += *(payload++);
        udplen -= 2;
    }
    
    if(udplen > 0){
        sum += ((*payload)&htons(0xFF00));
    }

    while(sum >> 16){
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum = ~sum;

    udph->check=((unsigned short) sum == 0x0000) ? 0xFFFF : (unsigned short) sum;
}