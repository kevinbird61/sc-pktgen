/* Self-crafted packet generator */
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <pthread.h>

#include "pktgen.h"
#include "utils.h"
#include "intf.h"

#define EXEC "sc-pktgen.exe"
#define AUTHOR "Kevin Cyu"
#define DATE "2019"
#define MSEC 1000

int pkt_rate=100;   // 100 pps
double per_pkt_time=10; // per pkt time (ms)
int interval=1000;
double pkt_sent_slot=0.0;
double total_sent_pkts=0;
unsigned int CPU_HZ=0;
unsigned char mac_intf[8];

void print_options();

struct user_params {
    int                 flags;
    char                sip[32];
    char                dip[32];
    unsigned short      sport;
    unsigned short      dport;
};

/* thread arguments */
struct thread_info {
    pthread_t           thread_id;
    int                 thread_num;
    pcap_t              *handle;
    struct user_params  *params;
};

// timer function 
static void *timer(void *arg)
{
    struct thread_info *tinfo = (struct thread_info*) arg;
    //pthread_cond_wait(&tinfo->cond, &tinfo->mutex);
    unsigned long long t_start=read_tsc(), t_measure=0, t_prev_sec=t_start;
    double prev_sent=0;

    while(1)
    {
        t_measure=read_tsc();
        // execute 1 time per sec
        if(((t_measure-t_prev_sec)/CPU_HZ)>MSEC){
            // print 
            // printf("[%lld s] Packet rate: %u pps. Pkt sent in each slot(~ %dms): %f. Total packet sent: %f\n", (t_measure-t_start)/(CPU_HZ*MSEC), pkt_rate, interval, pkt_sent_slot, total_sent_pkts);
            pkt_sent_slot=total_sent_pkts-prev_sent;
            prev_sent=total_sent_pkts;
            printf("[%lld s] Packet rate: %u pps. Pkt sent in each slot(~ %dms): %f. Total packet sent: %f\n", 
                (t_measure-t_start)/(CPU_HZ*MSEC), pkt_rate, interval, pkt_sent_slot, total_sent_pkts);
            // update 
            t_prev_sec=t_measure;
        }
    }
}

static void *pkt_sender(void *arg)
{
    struct thread_info *tinfo = (struct thread_info*) arg;

    /* FIXME: using *arg instead dummy pkts */
    char pkt[200];
    int size_existed=0, totalen=0, protocol=0;
    totalen=(tinfo->params->flags&0x040)>0? 28: 40;
    protocol=(tinfo->params->flags&0x040)>0? 17: 6;

    memset(pkt, 0x00, 200);
    // encap_eth(pkt, "ff:ff:ff:ff:ff:ff", mac_intf, ETHERTYPE_IP);
    // FIXME: how to fill in the dmac?
    encap_eth(pkt, "de:b4:0f:81:62:cb", mac_intf, ETHERTYPE_IP);
    encap_ipv4(pkt+SIZE_ETH, totalen, protocol, tinfo->params->sip, tinfo->params->dip);
    if(tinfo->params->flags&0x040){
        // udp
        encap_udp(pkt+SIZE_ETH+SIZE_IP, tinfo->params->sport, tinfo->params->dport);
        compute_udp_csum(pkt+SIZE_ETH);
        size_existed+=SIZE_ETH+SIZE_IP+SIZE_UDP;
    } else {
        // tcp (TODO: assigned control flags, default is SYN)
        encap_tcp(pkt+SIZE_ETH+SIZE_IP, tinfo->params->sport, tinfo->params->dport,
            1, 0, 8192, 0x002);
        compute_tcp_csum(pkt+SIZE_ETH);
        size_existed+=SIZE_ETH+SIZE_IP+SIZE_TCP;
    }

    unsigned long long t_start=read_tsc(), t_measure=0, t_prev=t_start;
    while(1)
    {
        t_measure=read_tsc();

        /*if(interval <= 0){
            // update per while loop
            pkt_sent_slot=((double)(t_measure-t_prev)/(CPU_HZ*MSEC))*pkt_rate;
            total_sent_pkts+=pkt_sent_slot;
            t_prev=t_measure;
        } else {
            // update per interval
            if(((t_measure-t_prev)/CPU_HZ) >= interval){
                printf("Per pkt time (ms): %f\n", per_pkt_time);
                pkt_sent_slot=((double)(t_measure-t_prev)/(CPU_HZ*MSEC))*pkt_rate;
                total_sent_pkts+=pkt_sent_slot;
                t_prev=t_measure;
            }
        }*/

        /* FIXME - Problem: 
         * sometimes (t_measure-t_prev)/CPU_HZ is much bigger than 
         * per_pkt_time (due to pcap_inject). (For example, each loop iteration
         * cost 3.439250 ms and per_pkt_time is 0.909091) This problem 
         * will appear only when you using very high transmission rate.
        */
        if(((double)(t_measure-t_prev)) >= per_pkt_time*CPU_HZ){
            // printf("%f, %f\n", (double)(t_measure-t_prev)/CPU_HZ, per_pkt_time);
            total_sent_pkts++;
            // send dummy pkt 
            pcap_inject(tinfo->handle, pkt, size_existed);
            // printf("sent byte: %d\n", pcap_inject(tinfo->handle, pkt, sizeof(struct ether_header)+sizeof(struct ip)+sizeof(struct tcphdr)));
            t_prev=t_measure;
        }
    }
}

// keypress event
void inc_pktrate(int sig)
{
    switch(sig)
    {
        case SIGTSTP:
            // inc pkt rate by 1000 
            pkt_rate+=1000;
            // change per_pkt_time
            per_pkt_time=((double)MSEC/pkt_rate);
            break;
        case SIGINT:
            exit(1);
        default:
            break;
    }
    return;
}

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
     *      - 0x010: source port
     *      - 0x020: destintation port
     *      - 0x040: tcp (0) or udp (=0x040)
    */
    char err_buf[PCAP_ERRBUF_SIZE];
    int ch, flags=0;
    char *intf;
    char sip[32]={0}, dip[32]={0};
    unsigned char ip_addr[16];
    unsigned short sport, dport;

    CPU_HZ=get_cpufreq();
    printf("*********************************************\n");
    printf("CPU_MHz of your machine: %u\n", CPU_HZ);

    const char *short_opt="hr:i:2";
    struct option long_opt[]=
    {
        {"packet_rate", required_argument, NULL, 'r'},
        {"interface", required_argument, NULL, 'i'},
        {"sip", required_argument, NULL, 0},
        {"dip", required_argument, NULL, 0},
        {"sport", required_argument, NULL, 0},
        {"dport", required_argument, NULL, 0},
        {"udp", no_argument, NULL, '2'},
        {"help", no_argument, NULL, 0}
    };

    int option_index=0;
    while((ch=getopt_long_only(argc, argv, short_opt, long_opt, &option_index))!=-1) {
        switch(ch)
        {
            case 'r':
                // pkt_rate
                flags|=0x01;
                pkt_rate=atoi(optarg);
                // printf("-> Specified packet rate (pps): %d\n", pkt_rate);
                break;
            case 'i':
                // interface
                flags|=0x02;
                intf=optarg;
                // printf("-> Specified interface: %s\n", intf);
                break;
            case 0:
                // support different options with same prefix alphabet
                // printf("option %s\n", long_opt[option_index].name);
                if(!strcmp(long_opt[option_index].name, "sip")){
                    // specify source IP
                    flags|=0x04;
                    strncpy(sip, optarg, strlen(optarg));
                    printf("[Options: %s] %s\n", long_opt[option_index].name, sip);
                } else if(!strcmp(long_opt[option_index].name, "dip")){
                    // specify destination IP
                    flags|=0x08;
                    strncpy(dip, optarg, strlen(optarg));
                    printf("[Options: %s] %s\n", long_opt[option_index].name, dip);
                } else if(!strcmp(long_opt[option_index].name, "sport")){
                    // specify source port
                    flags|=0x010;
                    sport=(unsigned short)atoi(optarg);
                    printf("[Options: %s] %d\n", long_opt[option_index].name, sport);
                } else if(!strcmp(long_opt[option_index].name, "dport")){
                    // specify destination port
                    flags|=0x020;
                    dport=(unsigned short)atoi(optarg);
                    printf("[Options: %s] %d\n", long_opt[option_index].name, dport);
                }
                break;
            case '2':
                // using udp instead of tcp
                flags|=0x040;
                break;
            case 'h':
            default:
                // print helper function 
                print_options();
                exit(1);
        }
    }

    /* list all user specified parameters here */
    if(!(flags&0x01)){
        printf("[!] You didn't assign packet rate parameter!\n");
        printf("└──> Using default value %d (pps).\n", pkt_rate);
    } else {
        printf("-> Packet rate: %d (pps).\n", pkt_rate);
    }
    if(!(flags&0x02)){
        printf("[!] You didn't assign interface!\n");
        // configure default interface
        intf=pcap_lookupdev(err_buf);
        if(intf==NULL){
            printf("└──X No available devices/interfaces on this machine.\n");
            return 1;
        }
        printf("└──> Using default value %s.\n", intf);
        get_mac(intf, mac_intf);
        printf("-> Interface's MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac_intf[0], mac_intf[1], mac_intf[2], mac_intf[3], mac_intf[4], mac_intf[5]);
    } else {
        printf("-> Interface: %s\n", intf);
        get_mac(intf, mac_intf);
        printf("-> Interface's MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac_intf[0], mac_intf[1], mac_intf[2], mac_intf[3], mac_intf[4], mac_intf[5]);
    }
    if(!(flags&0x04)){
        printf("[!] You didn't assign source IP!\n");
        get_ip(intf, sip);
        // strncpy(sip, ip_addr, strlen(ip_addr));
        printf("└──> Using default address %s.\n", sip);
    } else {
        printf("-> Source IP address: %s\n", sip);
    }
    if(!(flags&0x08)){
        printf("[!] You didn't assign destination IP!\n");
        strncpy(dip, "8.8.8.8", 8);
        printf("└──> Using default address %s\n", dip);
    } else {
        printf("-> Destination IP address: %s\n", dip);
    }
    if(!(flags&0x010)){
        printf("[!] You didn't assign src port!\n");
        sport=2000;
        printf("└──> Using default src port %d.\n", sport);
    } else {
        printf("-> Source Port: %d\n", sport);
    }
    if(!(flags&0x020)){
        printf("[!] You didn't assign dst port!\n");
        dport=80;
        printf("└──> Using default dst port %d.\n", dport);
    } else {
        printf("-> Destination Port: %d\n", dport);
    }
    if(!(flags&0x040)){
        printf("-> Using TCP as L4 protocol.\n");
    } else {
        printf("-> Using UDP as L4 protocol.\n");
    }

    per_pkt_time=((double)MSEC/pkt_rate);

    // open device
    pcap_t *handle;
    handle=pcap_open_live(intf, BUFSIZ, 1, 10000, err_buf);
    if(handle==NULL){
        printf("└──X Network device: %s is not available. Please check your interface again.\n", intf);
        return 1;
    }

    /* generate a MAC/IP/TCP packet */
    // char pkt[200];
    // encap_eth(pkt, "ff:ff:ff:ff:ff:ff", mac_intf, ETHERTYPE_IP);
    // encap_ipv4(pkt+SIZE_ETH, 40, 6, ip_addr, "8.8.8.8");
    // encap_tcp(pkt+SIZE_ETH+SIZE_IP, 2000, 80, 1, 0, 8192, 0x02);
    
    // send the packet
    // printf("sent bytes: %d\n", pcap_inject(handle, pkt, sizeof(struct ether_header)+sizeof(struct ip)+sizeof(struct tcphdr)));

    // register key press C-z
    if(signal(SIGTSTP, &inc_pktrate)==SIG_ERR){
        perror("└──X Could not establish handler for SIGTSTP!");
        return EXIT_FAILURE;
    }

    /* TODO list: 
     * - [x] create 2 threads, one send packets and the other print status periodically
     * - [ ] add user-defined parameters into pkt_sender thread, and let it send those dummy packets
    */
    struct thread_info *tinfo;
    pthread_attr_t attr;    

    // init thread creation attributes
    pthread_attr_init(&attr);

    tinfo = calloc(2, sizeof(tinfo));
    if(tinfo==NULL){
        printf("Error when calloc.\n");
        exit(1);
    }
    
    // first thread -> timer
    tinfo[0].thread_num=1;
    tinfo[0].handle=NULL;
    if(pthread_create(&tinfo[0].thread_id, &attr, &timer, &tinfo[0])){
        // handle error
        perror("pthread_create - timer");
    }

    // second thread -> packet sender
    tinfo[1].thread_num=2;
    tinfo[1].handle=handle;
    tinfo[1].params=malloc(sizeof(struct user_params));
    tinfo[1].params->flags=flags;
    strncpy(tinfo[1].params->sip, sip, strlen(sip));
    strncpy(tinfo[1].params->dip, dip, strlen(dip));
    tinfo[1].params->sport=sport;
    tinfo[1].params->dport=dport;
    if(pthread_create(&tinfo[1].thread_id, &attr, &pkt_sender, &tinfo[1])){
        perror("pthread_create - pkt_sender");
    }

    printf("*********************************************\n");

    // join with each thread
    void *res;
    pthread_join(tinfo[1].thread_id, &res);
    pthread_join(tinfo[0].thread_id, &res);

    return 0;
}

void print_options()
{
    printf("A packet generator built by C language, which is one of my self-training side project.\n");
    printf("Author: %s, %s\n", AUTHOR, DATE);
    printf("\n");
    printf("Usage: [sudo] ./%s\n", EXEC);
    printf("\t-h, --help: Print this helper function.\n");
    printf("\t-r, --pkt_rate [val]: Sending rate of packet generator.\n");
    printf("\t-i, --interface [name]: Network device used to send packet.\n");
    printf("\t--sip [A.B.C.D]: Assign source IP address (v4).\n");
    printf("\t--dip [A.B.C.D]: Assign destination IP address (v4).\n");
    printf("\t--sport [port num]: Assign source port.\n");
    printf("\t--dport [port num]: Assign destination port.\n");
    printf("\t-2, --udp: sending udp packet instead of tcp.\n");
    printf("\n");
}