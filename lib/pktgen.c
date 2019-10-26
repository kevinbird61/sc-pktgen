#include "pktgen.h"

void encap_eth_default(char *pkt)
{
    struct ether_header *ethhdr;
    ethhdr=(struct ether_header*)pkt;
    // dst mac addr (ether_dhost), 0xffffffffffff (FIXME: let user defined? or from ARP table)
    filled_eth(ethhdr->ether_dhost, 0xde, 0xb4, 0x0f, 0x81, 0x62, 0xcb);
    // src mac addr (ether_shost), 0x010101010101 (FIXME: how to config local machine's MAC?)
    filled_eth(ethhdr->ether_shost, 0xb2, 0x42, 0x34, 0x3e, 0xfa, 0x58);
    // ether_type (default is IP)
    ethhdr->ether_type=htons(ETHERTYPE_IP);
}

void encap_ipv4_default(char *pkt)
{
    struct ip *iph;
    iph=(struct ip *)pkt;
    // init -> all 0x00
    memset(iph, 0x00, sizeof(struct ip));
    // header len
    iph->ip_hl=5;
    // version
    iph->ip_v=4;
    /* TODO: other field */
    
    // fragment offset
    iph->ip_off&=IP_DF;
        
    iph->ip_ttl=0xff;

    // total len
    iph->ip_len=htons(40);
    // protocol (default: TCP)
    iph->ip_p=6;

    // src addr
    struct in_addr ip_src, ip_dst;
    ip_src.s_addr=ipv4str2hex("20.20.20.225");
    // printf("%x\n", ipv4str2hex("20.20.20.225"));
    iph->ip_src=ip_src;
    // dst addr
    ip_dst.s_addr=ipv4str2hex("20.20.101.226");
    // printf("%x\n", ipv4str2hex("20.20.101.226"));
    iph->ip_dst=ip_dst;
}

void encap_tcp_default(char *pkt)
{
    struct tcphdr *tcp;
    tcp=(struct tcphdr *)pkt;
    memset(tcp, 0x00, sizeof(struct tcphdr));

    tcp->source=htons(2000);
    tcp->dest=htons(80);
    tcp->seq=htons(100);
    //tcp->ack_seq=htons(200); // don't need to set ack_seq if tcp->ack is not set

    tcp->doff=(sizeof(struct tcphdr))/4;
    tcp->window=htons(8192);

    tcp->syn=1; // SYN
}

void gen_dummy_pkt(char *pkt)
{
    /* create ETH/IP/TCP */
    // encap ethernet 
    encap_eth_default(pkt);
    // encap ip
    encap_ipv4_default(pkt+sizeof(struct ethhdr));
    // encap tcp
    encap_tcp_default(pkt+sizeof(struct ethhdr)+sizeof(struct ip));
}