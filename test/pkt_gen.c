#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h> 

#define CPU_MZ 1699999

static inline unsigned long long read_tsc(void)
{
    unsigned low, high;
    asm volatile("rdtsc":"=a"(low),"=d"(high));
    return ((low)|((unsigned long long)(high)<<32));
}

// pkt rate
unsigned int pktrate=0;

void inc_pktrate(int sig)
{
    switch(sig)
    {
        case SIGTSTP:
            // inc pkt rate by 1000
            pktrate+=1000;
            break;
        case SIGINT:
            exit(-1);
        default:
            // nothing
            break;
    }

    return;
}

int main(int argc, char *argv[])
{
    if(argc<2){
        printf("Need to specify packet rate.\n");
        exit(1);
    }

    pktrate=atoi(argv[1]);

    printf("Specified packet rate: %u\n", pktrate);

    // capture Ctrl+Z
    if(signal(SIGTSTP, &inc_pktrate)==SIG_ERR){
        perror("Could not establish handler for SIGTSTP!");
        return EXIT_FAILURE;
    }

    unsigned long long t_start=read_tsc(), t_measure=0;
    while(1)
    {
        t_measure=read_tsc();
        if(pktrate>1000){
            printf("[%lld s] Packet rate: %u K pps.\n", (t_measure-t_start)/(CPU_MZ*1000), pktrate/1000);
        }
        else{
            printf("[%lld s] Packet rate: %u pps.\n", (t_measure-t_start)/(CPU_MZ*1000), pktrate);
        }
        sleep(1);
    }

    return 0;
}
