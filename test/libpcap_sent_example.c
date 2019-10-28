#include "utils.h"
#include "pktgen.h"

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
