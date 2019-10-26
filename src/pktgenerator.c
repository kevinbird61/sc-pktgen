/*
 * Self-crafted packet generator:
 * - support interval `-i`
 * 
*/
#include <unistd.h>
#include <getopt.h>

#include "pktgen.h"
#include "utils.h"

int pkt_rate=100;   // 100 pps
// int interval=100;   // output 100 ms

int main(int argc, char *argv[])
{
    /* using getopt library to catpure user's options 
     * - flags: (denote which feature is enable)
     *      - 0x01: pkt_rate 
     *      - 0x02: interface
     *      - 0x04: destination IP address
     *      - 0x08: l4 protocol (tcp/udp/...)
    */
    char err_buf[PCAP_ERRBUF_SIZE];
    int ch, flags=0;
    char *intf;

    while((ch=getopt(argc,argv,"r:i:"))!=-1) {
        switch(ch)
        {
            case 'r':
                // pkt_rate
                flags|=0x01;
                pkt_rate=atoi(optarg);
                printf("User-defined packet rate (pps): %d\n", pkt_rate);
                break;
            case 'i':
                // interface
                flags|=0x02;
                intf=optarg;
                printf("User-defined interface: %s\n", intf);
                break;
        }
    }

    if(!(flags&0x01)){
        printf("You didn't assign packet rate parameter!\n");
        printf("Using default value %d pps.\n", pkt_rate);
    } 
    if(!(flags&0x02)){
        printf("You didn't assign interface!\n");
        // configure default interface
        intf=pcap_lookupdev(err_buf);
        if(intf==NULL){
            printf("No available devices/interfaces on this machine.\n");
            return 1;
        }
        printf("Using default value %s.\n", intf);
    }

    // open device
    pcap_t *handle;
    handle=pcap_open_live(intf, BUFSIZ, 1, 10000, err_buf);
    if(handle==NULL){
        printf("Network device: %s is not available. Please check your interface again.\n");
        return 1;
    }

    // TODO: using parameters/arguments to generate packet!


    return 0;
}