#ifndef __UTILS__
#define __UTILS__

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

typedef unsigned char u8;

unsigned int ipv4str2hex(char *str);

void filled_eth(u8 *eth,
    u8 b0, u8 b1, u8 b2,
    u8 b3, u8 b4, u8 b5);

static inline unsigned long long read_tsc(void)
{
    unsigned low, high;
    asm volatile("rdtsc":"=a"(low),"=d"(high));
    return ((low)|((unsigned long long)(high)<<32));
}

unsigned int get_cpufreq();

#endif 