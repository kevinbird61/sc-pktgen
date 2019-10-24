#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>

#define CPU_MZ 1699999

struct thread_info {
    pthread_t   thread_id;
    int         thread_num;
    char        *argv_string;
};

static inline unsigned long long read_tsc(void)
{
    unsigned low, high;
    asm volatile("rdtsc":"=a"(low),"=d"(high));
    return ((low)|((unsigned long long)(high)<<32));
}

// global variables
unsigned int pkt_rate=0;
double pkt_sent_slot=0.0;
double total_sent_pkts=0;

// timer function 
static void *timer(void *arg)
{
    unsigned long long t_start=read_tsc(), t_measure=0, t_prev_sec=t_start;
    while(1)
    {
        t_measure=read_tsc();
        // execute 1 time per sec
        if(((t_measure-t_prev_sec)/CPU_MZ)>=1000){
            // print 
            printf("[%lld s] Packet rate: %u pps. Pkt sent in each slot(~ 250ms): %f. Total packet sent: %f\n", (t_measure-t_start)/(CPU_MZ*1000), pkt_rate,  pkt_sent_slot, total_sent_pkts);
            // update 
            t_prev_sec=t_measure;
        }
        // printf("[%d] Pkt rate: %u, total sent pkts: %llu\n", i, pkt_rate, total_sent_pkts);
        
    }
}

static void *pkt_sender(void *arg)
{
    unsigned long long t_start=read_tsc(), t_measure=0, t_prev=t_start;
    while(1)
    {
        t_measure=read_tsc();
        // update in each 250 ms
        if(((t_measure-t_prev)/CPU_MZ) >= 250){
            pkt_sent_slot=((double)(t_measure-t_prev)/(CPU_MZ*1000))*pkt_rate;
            total_sent_pkts+=pkt_sent_slot;
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
    if(argc<2){
        printf("You didn't assign packet rate parameter!\n");
        printf("So the packet rate would be 100 pps. (default value)\n");
        pkt_rate=100;
        // exit(1);
    } else {
        pkt_rate=atoi(argv[1]);
        printf("User-defined packet rate: %d\n", pkt_rate);
    }

    // register key press C-z
    if(signal(SIGTSTP, &inc_pktrate)==SIG_ERR){
        perror("Could not establish handler for SIGTSTP!");
        return EXIT_FAILURE;
    }

    // create 2 threads
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
    if(pthread_create(&tinfo[0].thread_id, &attr, &timer, &tinfo[0])){
        // handle error
        perror("pthread_create - timer");
    }

    // second thread -> packet sender
    tinfo[1].thread_num=2;
    if(pthread_create(&tinfo[1].thread_id, &attr, &pkt_sender, &tinfo[0])){
        perror("pthread_create - pkt_sender");
    }

    // join with each thread
    void *res;
    pthread_join(tinfo[0].thread_id, &res);
    pthread_join(tinfo[1].thread_id, &res);
    
    return 0;
}
