#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <string.h>
#include <stdio.h>

void encap_eth_default(char *pkt)
{
    struct ether_header *ethhdr;
    ethhdr=(struct ether_header*)pkt;
    // dst mac addr (ether_dhost), 0xffffffffffff
    memset(ethhdr->ether_dhost, 0xff, ETH_ALEN*sizeof(char));
    // src mac addr (ether_shost), 0x010101010101 (FIXME)
    memset(ethhdr->ether_shost, 0x01, ETH_ALEN*sizeof(char));
    // ether_type
    ethhdr->ether_type=ETHERTYPE_IP;
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

    // sending packet
    char fakebuf[200];
    memset(fakebuf, 0x00, 200);
    encap_eth_default(fakebuf);
    int byte_written=pcap_inject(handle, fakebuf, 200);

    return 0;
}
