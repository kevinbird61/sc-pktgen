#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef unsigned char u8;

unsigned int ipv4str2hex(char *str)
{
    char ipstr[32]={0};
    int i=0;
    unsigned char ip[4];
    unsigned int ipv4=0;

    strcpy(ipstr, str);

    char *token=strtok(ipstr, ".");
    while(token!=NULL){
        ip[i++]=atoi(token);
        token=strtok(NULL, ".");
    }

    memcpy(&ipv4, ip, sizeof(unsigned int));
    return ipv4;
}

void filled_eth(u8 *eth,
    u8 b0, u8 b1, u8 b2,
    u8 b3, u8 b4, u8 b5)
{
    *(eth)=b0;
    *(eth+1)=b1;
    *(eth+2)=b2;
    *(eth+3)=b3;
    *(eth+4)=b4;
    *(eth+5)=b5;
}

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

int main(int argc, char *argv[])
{
    char *dev;
    pcap_t *handle;
    char err_buf[PCAP_ERRBUF_SIZE];
    // char u_char *pkt;

    if(argc<2){
        // find a dev
        dev=pcap_lookupdev(err_buf);
        if(dev==NULL){
            printf("Error finding device: %s\n", err_buf);
            return 1;
        }
    } else {
        // using argv[1]
        dev=argv[1];
    }

    // open device 
    handle=pcap_open_live(dev, BUFSIZ, 1, 10000, err_buf);
    if(handle==NULL){
        printf("Network device: %s not available, using default device.\n", dev);
        dev=pcap_lookupdev(err_buf);
        if(dev==NULL){
            printf("Error finding device: %s\n", err_buf);
            return 1;
        }
        handle=pcap_open_live(dev, BUFSIZ, 1, 10000, err_buf);
        if(handle==NULL){
            printf("No any network device is available now,\n");
            return 1;
        }
    }
 
    printf("Using network device: %s\n", dev);

    // generate packet 
    // FIXME: 54 -> change to dynamic allocation
    char *pkt;
    pkt=malloc(54*sizeof(char));
    gen_dummy_pkt(pkt);
    
    // send
    int byte_written=pcap_inject(handle, pkt, 54);
    printf("sent bytes: %d\n", byte_written);

    return 0;
}
