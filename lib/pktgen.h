#ifndef __PKTGEN__
#define __PKTGEN__

#include <netinet/if_ether.h>
#include <netinet/udp.h>            // https://android.googlesource.com/platform/bionic/+/f8a2243/libc/include/netinet/udp.h
#include <netinet/tcp.h>            // https://android.googlesource.com/platform/bionic/+/master/libc/include/netinet/tcp.h
#include <netinet/in.h>             // https://android.googlesource.com/platform/bionic/+/master/libc/include/netinet/in.h
#include <netinet/ip.h>             // https://android.googlesource.com/platform/bionic/+/master/libc/include/netinet/ip.h
#include <arpa/inet.h>
#include <pcap/pcap.h>

#include "utils.h"

#define SIZE_ETH    sizeof(struct ethhdr)
#define SIZE_IP     sizeof(struct ip)
#define SIZE_TCP    sizeof(struct tcphdr)
#define SIZE_UDP    sizeof(struct udphdr)

/* basic encap. func for ethernet header (with "fixed" default setting) */
void encap_eth_default(char *pkt);
void encap_ipv4_default(char *pkt);
void encap_tcp_default(char *pkt);
/* generate dummy pkt */ 
void gen_dummy_pkt(char *pkt);

/* ethernet */
void encap_eth(char *pkt_eth,
    const char *dmac, const char *smac, unsigned short ethertype);
/* ipv4 */
void encap_ipv4(char *pkt_ip,
    int total_len, int protocol,
    char *srcIP, char *dstIP);

/* tcp */
void encap_tcp(char *pkt_tcp, unsigned short sport, unsigned short dport,
    unsigned int seq, unsigned ack_seq, unsigned short window,
    unsigned char flags);
void compute_tcp_csum(char *pkt_ip);

/* udp */
void encap_udp(char *pkt_udp, unsigned short sport, unsigned short dport);
void compute_udp_csum(char *pkt_ip);

#endif 