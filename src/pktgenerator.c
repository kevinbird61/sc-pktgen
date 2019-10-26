/*
 * Self-crafted packet generator:
 * - support interval `-i`
 * 
*/
#include <unistd.h>
#include <getopt.h>

#include "pktgen.h"
#include "utils.h"
#include "intf.h"

int pkt_rate=100;   // 100 pps
// int interval=100;   // output 100 ms

void print_options();

int main(int argc, char *argv[])
{
    /* using getopt library to catpure user's options 
     * - options:
     *      - r: packet rate
     *      - i: network interface 
     *      - sip: source ip (spoof)
     *      - dip: destination ip
     *      - sport: source port
     *      - dport: destintation port
     * - flags: (denote which feature is enable)
     *      - 0x01: pkt_rate 
     *      - 0x02: interface
     *      - 0x04: source IPv4
     *      - 0x08: destination IPv4
     *      - 0x010: l4 protocol (tcp/udp/...)
     *      - 0x020: source port
     *      - 0x040: destintation port
    */
    char err_buf[PCAP_ERRBUF_SIZE];
    int ch, flags=0;
    char *intf;

    const char *short_opt="r:i:s:";
    struct option long_opt[]=
    {
        {"packet_rate", required_argument, NULL, 'r'},
        {"interface", required_argument, NULL, 'i'},
        {"sip", required_argument, NULL, 0},
        {"dip", required_argument, NULL, 0},
        {"sport", required_argument, NULL, 0},
        {"dport", required_argument, NULL, 0}
    };

    int option_index=0;
    while((ch=getopt_long_only(argc, argv, short_opt, long_opt, &option_index))!=-1) {
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
            case 0:
                // support different options with same prefix alphabet
                // printf("option %s\n", long_opt[option_index].name);
                if(!strcmp(long_opt[option_index].name, "sip")){
                    // specify source IP
                    printf("[Options: %s] %s\n", long_opt[option_index].name, optarg);
                } else if(!strcmp(long_opt[option_index].name, "dip")){
                    // specify destination IP
                    printf("[Options: %s] %s\n", long_opt[option_index].name, optarg);
                } else if(!strcmp(long_opt[option_index].name, "sport")){
                    // specify source port
                    printf("[Options: %s] %d\n", long_opt[option_index].name, atoi(optarg));
                } else if(!strcmp(long_opt[option_index].name, "dport")){
                    // specify destination port
                    printf("[Options: %s] %d\n", long_opt[option_index].name, atoi(optarg));
                }
                break;
            default:
                // print helper function 
                print_options();
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
    unsigned char mac_intf[8];
    unsigned char ip_addr[16];
    handle=pcap_open_live(intf, BUFSIZ, 1, 10000, err_buf);
    if(handle==NULL){
        printf("Network device: %s is not available. Please check your interface again.\n", intf);
        return 1;
    } else {
        get_mac(intf, mac_intf);
        printf("Interface's MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac_intf[0], mac_intf[1], mac_intf[2], mac_intf[3], mac_intf[4], mac_intf[5]);
        get_ip(intf, ip_addr);
        printf("Interface's IP: %s\n", ip_addr);
    }

    /* generate a MAC/IP/TCP packet */
    char pkt[200];
    encap_eth(pkt, "ff:ff:ff:ff:ff:ff", mac_intf, ETHERTYPE_IP);
    encap_ipv4(pkt+sizeof(struct ip), 40, 6, ip_addr, "8.8.8.8");
    encap_tcp(pkt+sizeof(struct ip), 2000, 80, 1, 0, 8192, 0x02);
    
    printf("sent bytes: %d\n", pcap_inject(handle, pkt, sizeof(struct ether_header)+sizeof(struct ip)+sizeof(struct tcphdr)));
    
    // TODO: using parameters/arguments to generate packet!


    return 0;
}

void print_options()
{

}