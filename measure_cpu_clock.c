#include <stdio.h>
#include <unistd.h>

#define CPU_MZ 1699999

static inline unsigned long long read_tsc(void)
{
    unsigned low, high;
    asm volatile("rdtsc":"=a"(low),"=d"(high));
    return ((low)|((unsigned long long)(high)<<32));
}

int main(void)
{
    unsigned long long tsc=0, prev_tsc=0;
    while(1){
        tsc=read_tsc();
        printf("current time: %llu, (prev diff: %llu)\n", tsc, tsc-prev_tsc);
        printf("current time(ms): %lld, (prev diff(ms): %lld)\n", tsc/CPU_MZ, (tsc-prev_tsc)/CPU_MZ);
        prev_tsc=tsc;
        sleep(1);
    }

    return 0;
}
