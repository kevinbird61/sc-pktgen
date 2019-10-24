#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <getopt.h>

#define CPU_MZ 1699999
#define MSEC 1000

/* thread arguments */
struct thread_info {
    pthread_t   thread_id;
    int         thread_num;
};

static inline unsigned long long read_tsc(void)
{
    unsigned low, high;
    asm volatile("rdtsc":"=a"(low),"=d"(high));
    return ((low)|((unsigned long long)(high)<<32));
}

// global variables
unsigned int pkt_rate=100, interval=250;
double pkt_sent_slot=0.0;
double total_sent_pkts=0;

// timer function 
static void *timer(void *arg)
{
    struct thread_info *tinfo = (struct thread_info*) arg;
    //pthread_cond_wait(&tinfo->cond, &tinfo->mutex);
    unsigned long long t_start=read_tsc(), t_measure=0, t_prev_sec=t_start;
    while(1)
    {
        t_measure=read_tsc();
        // execute 1 time per sec
        if(((t_measure-t_prev_sec)/CPU_MZ)>MSEC){
            // print 
            printf("[%lld s] Packet rate: %u pps. Pkt sent in each slot(~ %dms): %f. Total packet sent: %f\n", (t_measure-t_start)/(CPU_MZ*MSEC), pkt_rate, interval, pkt_sent_slot, total_sent_pkts);
            // update 
            t_prev_sec=t_measure;
        }
    }
}

static void *pkt_sender(void *arg)
{
    struct thread_info *tinfo = (struct thread_info*) arg;
    //pthread_cond_wait(&tinfo->cond, &tinfo->mutex);
    unsigned long long t_start=read_tsc(), t_measure=0, t_prev=t_start;
    while(1)
    {
        t_measure=read_tsc();

        if(interval <= 0){
            // update per while loop
            pkt_sent_slot=((double)(t_measure-t_prev)/(CPU_MZ*MSEC))*pkt_rate;
            total_sent_pkts+=pkt_sent_slot;
            t_prev=t_measure;
        } else {
            // update per interval
            if(((t_measure-t_prev)/CPU_MZ) >= interval){
                pkt_sent_slot=((double)(t_measure-t_prev)/(CPU_MZ*MSEC))*pkt_rate;
                total_sent_pkts+=pkt_sent_slot;
                t_prev=t_measure;
            }
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
    int ch, rflag=0, iflag=0;

    while((ch=getopt(argc,argv,"r:i:"))!=-1) {
        switch(ch)
        {
            case 'r':
                // pkt_rate
                rflag=1;
                pkt_rate=atoi(optarg);
                printf("User-defined packet rate (pps): %d\n", pkt_rate);
                break;
            case 'i':
                // interval
                iflag=1;
                interval=atoi(optarg);
                printf("User-defined interval(ms): %d\n", interval);
                break;
        }
    }

    if(!rflag){
        printf("You didn't assign packet rate parameter!\n");
        printf("Using default value %d pps.\n", interval);
    } 
    if(!iflag){
        printf("You didn't assign interval parameter!\n");
        printf("Using default value %d.\n", interval);
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
    pthread_join(tinfo[1].thread_id, &res);
    pthread_join(tinfo[0].thread_id, &res);
    

    return 0;
}
