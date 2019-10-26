#include "pktgen.h"

void encap_eth(char *pkt_eth,
    const char *dmac, const char *smac, unsigned short ethertype)
{
    struct ether_header *ethhdr;
    ethhdr=(struct ether_header*)pkt_eth;
    // assign dmac & smac
    sscanf(dmac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &ethhdr->ether_dhost[0], &ethhdr->ether_dhost[1], 
        &ethhdr->ether_dhost[2], &ethhdr->ether_dhost[3], 
        &ethhdr->ether_dhost[4], &ethhdr->ether_dhost[5]);
    sscanf(smac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &ethhdr->ether_shost[0], &ethhdr->ether_shost[1], 
        &ethhdr->ether_shost[2], &ethhdr->ether_shost[3], 
        &ethhdr->ether_shost[4], &ethhdr->ether_shost[5]);
    // ethertype
    ethhdr->ether_type=htons(ethertype);
}