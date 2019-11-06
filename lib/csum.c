#include "pktgen.h"

void compute_ipv4_csum(char *pkt_ip)
{
    struct ip *iph;
    iph=(struct ip*)pkt_ip;
    
    // check if ip len is 5 (20 bytes)
    if(iph->ip_hl<5){
        perror("Invalid IP length");
        exit(1);
    }

    // each 2 bytes add together (except checksum)
    iph->ip_sum=0; // set checksum field to 0
    unsigned int checksum=0;
    for(int i=0;i<(iph->ip_hl<<2);i+=2){
        checksum+=(unsigned short)(pkt_ip+sizeof(char)*i);
    }

    // check the carry, if exceed, add it back
    unsigned int carry=checksum>>16;
    checksum+=carry;
    
    // complement 
    iph->ip_sum=htons(~checksum);
}

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